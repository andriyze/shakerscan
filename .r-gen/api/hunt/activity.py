"""What changed for a Hunt since it last looked, so a planner can wait instead of polling.

A capability call already holds until its action settles (or hands back ``running``), and a
permission request can be waited on by id. What a planner with several things in flight lacked is one
read that returns as soon as *anything* it is waiting for changes: one of its actions settling, a
person deciding one of its permission requests, or a lead on its target moving (another Hunt
claiming or settling it).

``activity_since`` is that read, as ids and states only: no text from the target, a planner or an
operator. The cursor is opaque. It restarts slightly before the time of the read, so a row committed
late is not missed, and carries what was already reported inside that overlap, so nothing is
reported twice. Reading it grants nothing and changes nothing.
"""
from __future__ import annotations

import base64
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

SETTLED_STATES = ("completed", "partial", "failed", "blocked", "cancelled")
IN_FLIGHT_STATES = ("reserved", "running")
#: A row whose timestamp is its transaction's start can commit this long after a read and still be seen.
OVERLAP = timedelta(seconds=5)
#: Below the MCP client's default request timeout, so a wait ends before the client gives up.
MAX_WAIT_SECONDS = 15
MAX_ITEMS = 50
MAX_CURSOR_CHARS = 8192


class ActivityQueryError(ValueError):
    """A filter this read does not take, or a cursor it did not issue."""


def encode_cursor(after: datetime, seen: list[str]) -> str:
    raw = json.dumps({"t": after.isoformat(), "s": seen[-3 * MAX_ITEMS:]}, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor: Any) -> tuple[datetime, frozenset[str]]:
    if not isinstance(cursor, str) or not cursor or len(cursor) > MAX_CURSOR_CHARS:
        raise ActivityQueryError("after must be the cursor a previous activity read returned")
    try:
        data = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
        after = datetime.fromisoformat(data["t"])
        seen = frozenset(str(item) for item in data["s"])
    except (ValueError, KeyError, TypeError):
        raise ActivityQueryError("after must be the cursor a previous activity read returned") from None
    if after.tzinfo is None:
        raise ActivityQueryError("after must be the cursor a previous activity read returned")
    return after, seen


def parse_filters(filters: Mapping[str, Any] | None) -> tuple[str | None, int]:
    supplied = dict(filters or {})
    unknown = set(supplied) - {"after", "wait_seconds"}
    if unknown:
        raise ActivityQueryError("Unsupported activity filters: " + ", ".join(sorted(unknown)))
    wait = supplied.get("wait_seconds", 0)
    if isinstance(wait, bool) or not isinstance(wait, int) or not 0 <= wait <= MAX_WAIT_SECONDS:
        raise ActivityQueryError(f"wait_seconds is an integer from 0 to {MAX_WAIT_SECONDS}")
    after = supplied.get("after")
    if after is not None:
        decode_cursor(after)
    # A wait without after waits from now (the server takes the baseline read itself): agents kept
    # asking to wait first and were refused until they read a cursor.
    return after, wait


async def activity_since(conn: Any, run: Mapping[str, Any], after: str | None) -> dict[str, Any]:
    """This Hunt's settled actions, decided permission requests and its target's moved leads since ``after``."""
    hunt = uuid.UUID(str(run["id"]))
    owner = f"hunt:{run['id']}"
    target = run.get("device_target_id") or run.get("target_id")
    now = await conn.fetchval("SELECT clock_timestamp()")
    in_flight = int(await conn.fetchval(
        "SELECT count(*) FROM hunt_actions WHERE hunt_run_id=$1 AND status = ANY($2::text[])",
        hunt, list(IN_FLIGHT_STATES)) or 0)
    actions: list[dict[str, Any]] = []
    permissions: list[dict[str, Any]] = []
    leads: list[dict[str, Any]] = []
    reported: list[str] = []
    #: When a page is full, the next read restarts at its last row instead of skipping the rest.
    held_back: list[datetime] = []
    horizon = now - OVERLAP
    # The first read is a baseline: it reports nothing, and remembers what already lies inside the
    # overlap so the next read does not present it as new.
    baseline = after is None
    since, seen = (horizon, frozenset()) if baseline else decode_cursor(after)
    rows = await conn.fetch(
            """SELECT id, capability_name, status, COALESCE(completed_at, started_at) AS at
               FROM hunt_actions
               WHERE hunt_run_id=$1 AND status = ANY($2::text[]) AND COALESCE(completed_at, started_at) > $3
               ORDER BY at, id LIMIT $4""", hunt, list(SETTLED_STATES), since, MAX_ITEMS)
    if len(rows) == MAX_ITEMS:
        held_back.append(rows[-1]["at"])
    for row in rows:
        token = f"a:{row['id']}"
        if token not in seen and not baseline:
            actions.append({"action_id": str(row["id"]), "capability": row["capability_name"],
                            "status": row["status"], "at": row["at"].isoformat()})
        if token not in seen or row["at"] > horizon:
            reported.append(token)
    rows = await conn.fetch(
        """SELECT id, kind, status, decided_at FROM hunt_permission_requests
           WHERE hunt_run_id=$1 AND decided_at > $2 ORDER BY decided_at, id LIMIT $3""",
        hunt, since, MAX_ITEMS)
    if len(rows) == MAX_ITEMS:
        held_back.append(rows[-1]["decided_at"])
    for row in rows:
        token = f"p:{row['id']}:{row['status']}"
        if token not in seen and not baseline:
            permissions.append({"request_id": str(row["id"]), "kind": row["kind"], "status": row["status"],
                                "at": row["decided_at"].isoformat()})
        if token not in seen or row["decided_at"] > horizon:
            reported.append(token)
    if target is not None:
        rows = await conn.fetch(
            """SELECT id, status, version, claim_owner, claim_lease_expires_at, updated_at
               FROM hypotheses
               WHERE target_id=$1 AND updated_at > $2 AND NOT (metadata_json ? 'hunt_withheld')
               ORDER BY updated_at, id LIMIT $3""", uuid.UUID(str(target)), since, MAX_ITEMS)
        if len(rows) == MAX_ITEMS:
            held_back.append(rows[-1]["updated_at"])
        for row in rows:
            token = f"l:{row['id']}:{row['version']}"
            held = bool(row["claim_owner"] == owner and row["claim_lease_expires_at"]
                        and row["claim_lease_expires_at"] > now)
            if token not in seen and not baseline:
                leads.append({"hypothesis_id": str(row["id"]), "status": row["status"],
                              "version": row["version"], "held_by_this_hunt": held,
                              "at": row["updated_at"].isoformat()})
            if token not in seen or row["updated_at"] > horizon:
                reported.append(token)
    # Keep only what lies inside the next read's overlap; older rows cannot be returned again.
    cursor_time = min([max(since, horizon), *held_back])
    changed = bool(actions or permissions or leads)
    return {"kind": "activity", "supported": True, "changed": changed, "more": bool(held_back), "actions": actions,
            "permission_requests": permissions, "leads": leads, "in_flight_actions": in_flight,
            "cursor": encode_cursor(cursor_time, reported), "as_of": now.astimezone(timezone.utc).isoformat(),
            "rows": [], "count": 0, "has_more": False, "next_cursor": None,
            "next": ("Pass cursor as filter.after (with wait_seconds up to "
                     f"{MAX_WAIT_SECONDS}) to wait for the next change.")}
