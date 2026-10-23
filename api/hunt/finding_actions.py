"""Target-bound, evidence-linked finding mutations for the Hunt runtime.

These operations deliberately do not accept proof or verification fields.  A Hunt
may curate findings that it created, while deterministic proof contracts remain the
only path that can promote a finding to verified.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from typing import Any, Mapping, Sequence
import urllib.parse
import uuid

try:
    from redaction import redact_text
except ModuleNotFoundError:  # package import in host-side tests
    from scanner.redaction import redact_text


_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
# A Hunt may withdraw or restore its own unverified claim; dismissing a finding as a false positive
# or an accepted risk is an operator's triage decision (targets/interpretation_routes.py).
_STATUSES = frozenset({"active", "resolved"})
_EDITABLE_FIELDS = frozenset({"title", "description", "severity", "notes", "status"})
# The bytes a Hunt's finding records may hold, counted as stored (title, description, notes, URL
# and evidence document, in UTF-8). Each field is bounded in characters only, so the largest
# finding is about 40 KB of ASCII text and about 155 KB of four-byte characters; at a generous
# record allowance that is gigabytes per Hunt. A write that would pass the bound is refused like
# any input error: nothing is charged and the Hunt keeps running. About 1,650 findings of the
# largest ASCII size fit, about 430 of the largest four-byte size, and tens of thousands of
# typical findings of a few kilobytes (tests/test_hunt_finding_actions.py checks the counts).
MAX_FINDING_BYTES_PER_HUNT = 64 * 1024 * 1024
_STORED_FINDING_BYTES_SQL = """SELECT COALESCE(SUM(
        COALESCE(octet_length(title),0) + COALESCE(octet_length(description),0)
        + COALESCE(octet_length(notes),0) + COALESCE(octet_length(url),0)
        + COALESCE(octet_length(evidence::text),0)),0)
    FROM findings WHERE hunt_run_id=$1 AND ($2::uuid IS NULL OR id<>$2)"""


class HuntFindingActionError(ValueError):
    """A safe public rejection of a Hunt finding action."""


def _uuid(value: Any, label: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value or ""))
    except (TypeError, ValueError, AttributeError) as exc:
        raise HuntFindingActionError(f"Invalid {label}") from exc


def _bounded_text(value: Any, label: str, *, maximum: int, required: bool = False) -> str | None:
    text = str(value or "").strip()
    if required and not text:
        raise HuntFindingActionError(f"{label} is required")
    if len(text) > maximum:
        raise HuntFindingActionError(f"{label} exceeds {maximum} characters")
    return str(redact_text(text)) if text else None


_HTTP_PORTS = {"http": 80, "https": 443}
_RELATIVE_NEEDS_ORIGIN = "Use an absolute URL for an evidenced HTTP service"
_FROZEN_MALFORMED = "The Hunt's frozen target origins are malformed; cite an evidenced service instead"
_UNNAMED_NEEDS_SERVICE = (
    "This Hunt's target is a host and no cited evidence came from one of its HTTP services: cite "
    "evidence from the service the finding is on, or give its absolute URL as path"
)


def _host_key(host: Any) -> str | None:
    """One spelling per host: lower case, unbracketed, an IPv6 address compressed."""
    text = str(host or "").strip().lower()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text.rstrip(".") or None


def _origin(url: Any) -> tuple[str, str | None, int | None]:
    """(scheme, host, port) of an HTTP(S) URL. Raises ValueError for anything else."""
    if not isinstance(url, str):
        raise ValueError("an origin is a URL string")
    parsed = urllib.parse.urlsplit(url)
    if parsed.username or parsed.password:
        raise ValueError("userinfo is not allowed")
    scheme = parsed.scheme.lower()
    host = _host_key(parsed.hostname)
    if scheme not in _HTTP_PORTS or not host:
        raise ValueError("an origin is an http(s) URL with a host")
    port = parsed.port  # ValueError above 65535
    if port is None:
        return scheme, host, _HTTP_PORTS[scheme]
    if port <= 0:
        raise ValueError("an origin's port is between 1 and 65535")
    return scheme, host, port


def _origin_root(origin: tuple[str, str | None, int | None]) -> str:
    scheme, host, port = origin
    shown = f"[{host}]" if host and ":" in host else host
    return f"{scheme}://{shown}{'' if port == _HTTP_PORTS[scheme] else f':{port}'}/"


def _target_host(target_url: str) -> tuple[str | None, tuple[str, str | None, int | None] | None]:
    """The Hunt target's host, and its HTTP origin when the locator is a URL.

    A ``host://`` asset and a device locator (a bare host name or IP literal, IPv6 with or
    without brackets) are hosts: they name no HTTP service of their own.
    """
    text = str(target_url or "").strip()
    if text.lower().startswith("host://"):
        return _host_key(urllib.parse.urlsplit("http://" + text[len("host://"):]).hostname), None
    if "://" in text:
        origin = _origin(text)
        return origin[1], origin
    if not text or any(character in text for character in "/?#@ "):
        raise ValueError("the Hunt target is neither a URL nor a host")
    return _host_key(text), None


def _frozen_origins(values: Any) -> list[tuple[str, str | None, int | None]]:
    """The origins frozen in the Hunt context; malformed ones refuse the write (never a 500)."""
    if values is None:
        return []
    if isinstance(values, (str, bytes)) or not isinstance(values, (list, tuple)):
        raise HuntFindingActionError(_FROZEN_MALFORMED)
    try:
        return [_origin(value) for value in values]
    except ValueError as exc:
        raise HuntFindingActionError(_FROZEN_MALFORMED) from exc


def _evidenced(urls: Sequence[Any], host: str | None, path: str | None = None) -> set[tuple[str, str | None, int | None]]:
    """Services on the target host that answered a cited action; an unparseable record proves none."""
    services = set()
    for url in urls:
        try:
            origin = _origin(url)
            if origin[1] == host and (path is None or urllib.parse.urlsplit(url).path == path):
                services.add(origin)
        except ValueError:
            continue
    return services


def _canonical(url: str) -> str:
    """One spelling per location: the canonical origin (lower-case scheme and host, a default port
    left out) and the path and query as written."""
    parts = urllib.parse.urlsplit(url)
    return _origin_root(_origin(url))[:-1] + (parts.path or "/") + (f"?{parts.query}" if parts.query else "")


def _unnamed_location(target_url: str, host: str | None, base: tuple[str, str | None, int | None] | None,
                      observed_urls: Sequence[Any], admitted: Sequence[tuple[str, str | None, int | None]]) -> str:
    """Where a finding created without a path is located, by the rules a relative path follows.

    The evidenced service takes it, with the path its evidence names (its root when the evidence
    names several): the single evidenced service on the Hunt's host, else the inventory's own when
    it is among them, else the one whose evidence names the most distinct paths (a tie goes to
    the first by scheme, then port). Nothing evidenced: the inventory's own location, or for a host target
    (``host://`` asset or device) its first frozen origin. A host with neither is refused.
    """
    paths: dict[tuple[str, str | None, int | None], set[str]] = {}
    for url in observed_urls:
        try:
            origin = _origin(url)
        except ValueError:
            continue
        if origin[1] == host:
            paths.setdefault(origin, set()).add(urllib.parse.urlsplit(url).path or "/")
    if paths:
        service = (next(iter(paths)) if len(paths) == 1 else base if base in paths
                   else min(paths, key=lambda origin: (-len(paths[origin]), origin[0], origin[2] or 0)))
        evidenced = paths[service]
        return _origin_root(service)[:-1] + (next(iter(evidenced)) if len(evidenced) == 1 else "/")
    if base is not None:
        return _canonical(target_url)
    frozen = [origin for origin in admitted if origin[1] == host]
    if frozen:
        return _origin_root(frozen[0])
    raise HuntFindingActionError(_UNNAMED_NEEDS_SERVICE)


def _finding_url(target_url: str, path: Any, observed_urls: Sequence[str] = (),
                 admitted_origins: Any = ()) -> str:
    """The finding's location, bound to a service the Hunt may name.

    A relative path takes the inventory's own service when it is among the evidenced ones (or
    nothing is evidenced), else the single evidenced service on the target host; a host target
    (``host://`` asset or device) with no evidence takes its single frozen origin. Several
    candidates need an absolute URL. An absolute URL must be the inventory service, an evidenced
    one or a frozen one, on the target host. No path at all is located by ``_unnamed_location``.
    """
    value = str(path or "").strip()
    if len(value) > 2_000:
        raise HuntFindingActionError("path exceeds 2000 characters")
    admitted_values = _frozen_origins(admitted_origins)
    try:
        host, base = _target_host(target_url)
        if not value:
            return _unnamed_location(target_url, host, base, observed_urls, admitted_values)
        observed = _evidenced(observed_urls, host)
        admitted = {origin for origin in admitted_values if origin[1] == host}
        supplied = urllib.parse.urlsplit(value)
        if not supplied.scheme and not supplied.netloc:
            # A relative location belongs to the cited service, which may differ from the
            # inventory's default port: never silently attach :8443 evidence to :443.
            services = _evidenced(observed_urls, host, supplied.path) or observed
            if base is not None and (base in services or not services):
                resolved_url = urllib.parse.urljoin(target_url, value)
            elif len(services) == 1:
                resolved_url = urllib.parse.urljoin(_origin_root(next(iter(services))), value)
            elif not services and len(admitted) == 1:
                resolved_url = urllib.parse.urljoin(_origin_root(next(iter(admitted))), value)
            else:
                raise HuntFindingActionError(_RELATIVE_NEEDS_ORIGIN)
        else:
            resolved_url = value
        permitted = _origin(resolved_url) in {base, *observed, *admitted} - {None}
    except HuntFindingActionError:
        raise
    except ValueError as exc:
        raise HuntFindingActionError("Finding path must remain on the Hunt target origin") from exc
    if not permitted:
        raise HuntFindingActionError("Finding path must remain on the Hunt target origin")
    # One spelling per location, so a repeated finding has the same fingerprint.
    return _canonical(resolved_url)


async def _require_evidence_actions(
    conn: Any,
    *,
    hunt_id: uuid.UUID,
    current_action_id: uuid.UUID,
    values: Sequence[Any],
) -> list[str]:
    if not isinstance(values, (list, tuple)) or not values:
        raise HuntFindingActionError("At least one evidence_action_id is required")
    if len(values) > 50:
        raise HuntFindingActionError("At most 50 evidence actions may be linked")
    action_ids = sorted({_uuid(value, "evidence action id") for value in values}, key=str)
    if current_action_id in action_ids:
        raise HuntFindingActionError("The current finding action cannot cite itself as evidence")
    rows = await conn.fetch(
        """SELECT id FROM hunt_actions
           WHERE hunt_run_id=$1
             AND id=ANY($2::uuid[])
             AND status IN ('completed','partial')""",
        hunt_id,
        action_ids,
    )
    found = {row["id"] for row in rows}
    if found != set(action_ids):
        raise HuntFindingActionError(
            "Evidence actions must be completed or partial actions from this Hunt"
        )
    return [str(value) for value in action_ids]


async def _refuse_operator_decided(conn: Any, finding_id: uuid.UUID) -> None:
    """An operator dismissed (or reopened) this finding: a Hunt no longer changes or deletes it."""
    decided = await conn.fetchval(
        """SELECT 1 FROM target_interpretations
           WHERE finding_id=$1 AND negative_state='finding_dismissed' LIMIT 1""",
        finding_id,
    )
    if decided:
        raise HuntFindingActionError(
            "An operator made a triage decision on this finding; a Hunt cannot change or delete it"
        )


async def _locked_run(conn: Any, hunt_id: uuid.UUID) -> Any:
    # Lock order: the Hunt's target row, then the Hunt row, as operator retractions and decisions
    # take them. The target lock is FOR NO KEY UPDATE, the lock the finding-count refresh needs.
    await conn.execute(
        """SELECT 1 FROM targets WHERE id=(SELECT target_id FROM hunt_runs WHERE id=$1)
           FOR NO KEY UPDATE OF targets""",
        hunt_id,
    )
    await conn.execute(
        """SELECT 1 FROM device_targets WHERE id=(SELECT device_target_id FROM hunt_runs WHERE id=$1)
           FOR NO KEY UPDATE OF device_targets""",
        hunt_id,
    )
    run = await conn.fetchrow(
        """SELECT id, status, completed_at, target_kind, target_id, device_target_id, context_pack, notes
           FROM hunt_runs WHERE id=$1 FOR UPDATE""",
        hunt_id,
    )
    if run is None:
        raise HuntFindingActionError("Hunt not found")
    if dict(run).get("completed_at") is not None or str(run["status"]) not in {"active", "awaiting_planner", "budget_exhausted"}:
        raise HuntFindingActionError(f"Hunt is {run['status']}")
    return run


def _refuse_quarantined(run: Any) -> None:
    """A Hunt whose entries an operator retracted writes no more finding text."""
    from .interpretations import QUARANTINE_MESSAGE, notes_quarantined
    if notes_quarantined(dict(run).get("notes")):
        raise HuntFindingActionError(QUARANTINE_MESSAGE)


def _context_target(run: Any) -> Mapping[str, Any]:
    raw = dict(run).get("context_pack")
    try:
        context = json.loads(raw) if isinstance(raw, str) else raw
    except ValueError:
        context = None
    context = context if isinstance(context, Mapping) else {}
    return context.get("target") if isinstance(context.get("target"), Mapping) else {}


def _target_url(run: Any) -> str:
    target = _context_target(run)
    return str(target.get("url") or target.get("locator") or "").strip()


def _probe_origin(summary: Any) -> str | None:
    """The service a cited device HTTP probe reached, from its recorded result."""
    if isinstance(summary, str):
        try:
            summary = json.loads(summary)
        except ValueError:
            return None
    if not isinstance(summary, Mapping):
        return None
    data = summary.get("data") if isinstance(summary.get("data"), Mapping) else summary
    origin = data.get("origin")
    return origin if isinstance(origin, str) else None


async def _evidenced_urls(conn: Any, run: Any, hunt_uuid: uuid.UUID, evidence_action_ids: Sequence[str]) -> list[str]:
    """URLs that answered the cited actions: their HTTP archive, and a device probe's origin."""
    action_ids = [uuid.UUID(value) for value in evidence_action_ids]
    rows = await conn.fetch(
        """SELECT DISTINCT url FROM http_transactions
           WHERE hunt_run_id=$1 AND hunt_action_id=ANY($2::uuid[])
             AND status_code IS NOT NULL AND error IS NULL""",
        hunt_uuid, action_ids,
    )
    urls = [row["url"] for row in rows]
    if run["device_target_id"] is not None:
        # A device HTTP probe is recorded on the action, not in the HTTP archive.
        probes = await conn.fetch(
            """SELECT result_summary FROM hunt_actions
               WHERE hunt_run_id=$1 AND id=ANY($2::uuid[])
                 AND capability_name='device.http.probe' AND status IN ('completed','partial')""",
            hunt_uuid, action_ids,
        )
        urls.extend(origin for origin in (_probe_origin(row["result_summary"]) for row in probes) if origin)
    return urls


def _record_bytes(*values: Any) -> int:
    return sum(len(str(value).encode("utf-8")) for value in values if value is not None)


async def _require_finding_room(conn: Any, hunt_uuid: uuid.UUID, size: int, *,
                                replacing: uuid.UUID | None = None) -> None:
    """Refuse a write that would take this Hunt's findings past ``MAX_FINDING_BYTES_PER_HUNT``."""
    stored = int(await conn.fetchval(_STORED_FINDING_BYTES_SQL, hunt_uuid, replacing) or 0)
    if stored + size > MAX_FINDING_BYTES_PER_HUNT:
        raise HuntFindingActionError(
            f"This Hunt's findings hold {stored:,} bytes; this {size:,}-byte record would pass the "
            f"{MAX_FINDING_BYTES_PER_HUNT:,}-byte limit per Hunt. Record a shorter finding or add to an "
            "existing one with findings.update; nothing was written and the Hunt keeps running."
        )


async def _existing_by_fingerprint(conn: Any, run: Any, hunt_uuid: uuid.UUID, fingerprint: str) -> Any:
    return await conn.fetchrow(
        """SELECT id, status, created_at, last_verified_at, verification_count, evidence
           FROM findings
           WHERE fingerprint=$1 AND hunt_run_id=$2
             AND target_id IS NOT DISTINCT FROM $3
             AND device_target_id IS NOT DISTINCT FROM $4""",
        fingerprint, hunt_uuid, run["target_id"], run["device_target_id"],
    )


async def _refresh_counts(conn: Any, run: Any) -> None:
    if run["target_id"] is not None:
        await conn.execute(
            """UPDATE targets t SET active_findings_count=(
                   SELECT COUNT(*) FROM findings f
                   WHERE f.target_id=t.id AND f.status='active'
               ), updated_at=NOW() WHERE t.id=$1""",
            run["target_id"],
        )
    if run["device_target_id"] is not None:
        await conn.execute(
            """UPDATE device_targets d SET active_findings_count=(
                   SELECT COUNT(*) FROM findings f
                   WHERE f.device_target_id=d.id AND f.status='active'
               ), updated_at=NOW() WHERE d.id=$1""",
            run["device_target_id"],
        )


async def create_hunt_finding(
    pool: Any,
    *,
    hunt_id: Any,
    action_id: Any,
    values: Mapping[str, Any],
) -> dict[str, Any]:
    hunt_uuid = _uuid(hunt_id, "hunt id")
    action_uuid = _uuid(action_id, "action id")
    title = _bounded_text(values.get("title"), "title", maximum=300, required=True)
    description = _bounded_text(
        values.get("description"), "description", maximum=20_000, required=True
    )
    severity = str(values.get("severity") or "").strip().lower()
    if severity not in _SEVERITIES:
        raise HuntFindingActionError("Invalid finding severity")
    evidence_summary = _bounded_text(
        values.get("evidence_summary"), "evidence_summary", maximum=8_000, required=True
    )
    notes = _bounded_text(values.get("notes"), "notes", maximum=8_000)

    async with pool.acquire() as conn:
        async with conn.transaction():
            run = await _locked_run(conn, hunt_uuid)
            _refuse_quarantined(run)
            evidence_action_ids = await _require_evidence_actions(
                conn,
                hunt_id=hunt_uuid,
                current_action_id=action_uuid,
                values=values.get("evidence_action_ids") or (),
            )
            target_url = _target_url(run)
            target = _context_target(run)
            finding_url = _finding_url(
                target_url, values.get("path"),
                await _evidenced_urls(conn, run, hunt_uuid, evidence_action_ids),
                target.get("origins"),
            )
            fingerprint = hashlib.sha256(
                json.dumps(
                    {
                        "hunt_id": str(hunt_uuid),
                        "target_id": str(run["target_id"] or run["device_target_id"]),
                        "title": title,
                        "url": finding_url,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            evidence = {
                "schema_version": "hunt-finding-evidence/v1",
                "proof_state": "unverified",
                "authoritative": False,
                "summary": evidence_summary,
                "source_action_ids": evidence_action_ids,
                "hunt_id": str(hunt_uuid),
            }
            existing = await _existing_by_fingerprint(conn, run, hunt_uuid, fingerprint)
            if existing is not None:
                return _existing_finding(existing, evidence_action_ids)
            await _require_finding_room(conn, hunt_uuid, _record_bytes(
                title, description, notes, finding_url, json.dumps(evidence, ensure_ascii=False)))
            row = await conn.fetchrow(
                """INSERT INTO findings (
                       target_id, device_target_id, hunt_run_id, fingerprint,
                       title, description, severity, tool, url, evidence, notes,
                       source, status
                   ) VALUES ($1,$2,$3,$4,$5,$6,$7,'hunt',$8,$9::jsonb,$10,'deep_hunt','active')
                   ON CONFLICT DO NOTHING
                   RETURNING id, status, created_at""",
                run["target_id"],
                run["device_target_id"],
                hunt_uuid,
                fingerprint,
                title,
                description,
                severity,
                finding_url,
                json.dumps(evidence),
                notes,
            )
            if row is None:  # created concurrently since the lookup above
                existing = await _existing_by_fingerprint(conn, run, hunt_uuid, fingerprint)
                if existing is None:
                    raise HuntFindingActionError("Finding identity conflicts with an existing record")
                return _existing_finding(existing, evidence_action_ids)
            await _refresh_counts(conn, run)
    return {
        "ok": True,
        "status": "success",
        "finding_id": str(row["id"]),
        "finding_status": str(row["status"]),
        "proof_state": "unverified",
        "authoritative": False,
        "created": True,
        "observation": {
            "kind": "finding_mutation",
            "operation": "created",
            "finding_id": str(row["id"]),
            "status": str(row["status"]),
            "proof_state": "unverified",
        },
    }


def _existing_finding(row: Any, evidence_action_ids: Sequence[str]) -> dict[str, Any]:
    """This Hunt already recorded a finding with this title and location: return it unchanged.

    Nothing is written (no record unit is spent). When the call cited evidence the record does not
    hold, the answer says so and names the write that attaches it.
    """
    raw = row["evidence"]
    try:
        stored = json.loads(raw) if isinstance(raw, str) else raw
    except ValueError:
        stored = None
    stored = stored if isinstance(stored, Mapping) else {}
    attached = set(evidence_action_ids) <= {str(value) for value in stored.get("source_action_ids") or ()}
    verified = row["last_verified_at"] is not None or int(row["verification_count"] or 0) > 0
    result: dict[str, Any] = {
        "ok": True,
        "status": "success",
        "finding_id": str(row["id"]),
        "finding_status": str(row["status"]),
        # A record with deterministic verification history is not described as unverified here;
        # read it for its current proof state.
        "proof_state": None if verified else "unverified",
        "verification_history": verified,
        "authoritative": False,
        "created": False,
        "evidence_attached": attached,
        "observation": {
            "kind": "finding_mutation",
            "operation": "existing",
            "finding_id": str(row["id"]),
            "status": str(row["status"]),
        },
    }
    if not attached:
        result["message"] = (
            f"This Hunt already recorded finding {row['id']} with this title and location; it is "
            "returned unchanged and the newly cited evidence was not attached. "
            + ("It has verification history, so a Hunt cannot change it; cite it instead."
               if verified else
               "Call findings.update with this finding_id and evidence_action_ids to attach it.")
        )
    return result


async def update_hunt_finding(
    pool: Any,
    *,
    hunt_id: Any,
    action_id: Any,
    values: Mapping[str, Any],
) -> dict[str, Any]:
    hunt_uuid = _uuid(hunt_id, "hunt id")
    action_uuid = _uuid(action_id, "action id")
    finding_uuid = _uuid(values.get("finding_id"), "finding id")
    supplied = {key for key in _EDITABLE_FIELDS if key in values}
    if not supplied:
        raise HuntFindingActionError("At least one editable finding field is required")
    updates: dict[str, Any] = {}
    if "title" in supplied:
        updates["title"] = _bounded_text(values.get("title"), "title", maximum=300, required=True)
    if "description" in supplied:
        updates["description"] = _bounded_text(
            values.get("description"), "description", maximum=20_000, required=True
        )
    if "notes" in supplied:
        updates["notes"] = _bounded_text(values.get("notes"), "notes", maximum=8_000)
    if "severity" in supplied:
        severity = str(values.get("severity") or "").strip().lower()
        if severity not in _SEVERITIES:
            raise HuntFindingActionError("Invalid finding severity")
        updates["severity"] = severity
    if "status" in supplied:
        status = str(values.get("status") or "").strip().lower()
        if status not in _STATUSES:
            raise HuntFindingActionError("Invalid finding status")
        updates["status"] = status

    async with pool.acquire() as conn:
        async with conn.transaction():
            run = await _locked_run(conn, hunt_uuid)
            _refuse_quarantined(run)
            evidence_action_ids = await _require_evidence_actions(
                conn,
                hunt_id=hunt_uuid,
                current_action_id=action_uuid,
                values=values.get("evidence_action_ids") or (),
            )
            finding = await conn.fetchrow(
                """SELECT id, evidence, last_verified_at, verification_count, title, description, notes, url
                   FROM findings
                   WHERE id=$1 AND hunt_run_id=$2 FOR UPDATE""",
                finding_uuid,
                hunt_uuid,
            )
            if finding is None:
                raise HuntFindingActionError("Finding was not created by this Hunt")
            await _refuse_operator_decided(conn, finding_uuid)
            if finding["last_verified_at"] is not None or int(finding["verification_count"] or 0) > 0:
                raise HuntFindingActionError(
                    "A finding with deterministic verification history cannot be edited by Hunt"
                )
            raw_evidence = finding["evidence"]
            evidence = json.loads(raw_evidence) if isinstance(raw_evidence, str) else dict(raw_evidence or {})
            audit = list(evidence.get("hunt_mutations") or [])
            audit.append({
                "action_id": str(action_uuid),
                "evidence_action_ids": evidence_action_ids,
                "fields": sorted(updates),
            })
            evidence["hunt_mutations"] = audit[-100:]
            await _require_finding_room(conn, hunt_uuid, _record_bytes(
                *(updates.get(column, finding[column]) for column in ("title", "description", "notes", "url")),
                json.dumps(evidence, ensure_ascii=False)), replacing=finding_uuid)
            assignments = []
            params: list[Any] = [finding_uuid, hunt_uuid]
            status_parameter: int | None = None
            for column, value in updates.items():
                params.append(value)
                assignments.append(f"{column}=${len(params)}")
                if column == "status":
                    status_parameter = len(params)
            params.append(json.dumps(evidence))
            assignments.append(f"evidence=${len(params)}::jsonb")
            if status_parameter is not None:
                assignments.append(
                    "resolved_at=CASE "
                    f"WHEN ${status_parameter}='active' THEN NULL "
                    "ELSE COALESCE(resolved_at,NOW()) END"
                )
            assignments.append("updated_at=NOW()")
            row = await conn.fetchrow(
                f"""UPDATE findings SET {', '.join(assignments)}
                    WHERE id=$1 AND hunt_run_id=$2
                    RETURNING id, status""",
                *params,
            )
            await _refresh_counts(conn, run)
    return {
        "ok": True,
        "status": "success",
        "finding_id": str(row["id"]),
        "finding_status": str(row["status"]),
        "proof_state": "unverified",
        "observation": {
            "kind": "finding_mutation",
            "operation": "updated",
            "finding_id": str(row["id"]),
            "status": str(row["status"]),
            "proof_state": "unverified",
        },
    }


async def delete_hunt_finding(
    pool: Any,
    *,
    hunt_id: Any,
    action_id: Any,
    values: Mapping[str, Any],
) -> dict[str, Any]:
    if values.get("confirm_delete") is not True:
        raise HuntFindingActionError("confirm_delete must be true")
    hunt_uuid = _uuid(hunt_id, "hunt id")
    action_uuid = _uuid(action_id, "action id")
    finding_uuid = _uuid(values.get("finding_id"), "finding id")
    async with pool.acquire() as conn:
        async with conn.transaction():
            run = await _locked_run(conn, hunt_uuid)
            await _require_evidence_actions(
                conn,
                hunt_id=hunt_uuid,
                current_action_id=action_uuid,
                values=values.get("evidence_action_ids") or (),
            )
            await _refuse_operator_decided(conn, finding_uuid)
            deleted = await conn.fetchrow(
                """DELETE FROM findings
                   WHERE id=$1 AND hunt_run_id=$2
                     AND last_verified_at IS NULL
                     AND COALESCE(verification_count,0)=0
                   RETURNING id""",
                finding_uuid,
                hunt_uuid,
            )
            if deleted is None:
                raise HuntFindingActionError(
                    "Finding was not created by this Hunt or has verification history"
                )
            await _refresh_counts(conn, run)
    return {
        "ok": True,
        "status": "success",
        "finding_id": str(deleted["id"]),
        "observation": {
            "kind": "finding_mutation",
            "operation": "deleted",
            "finding_id": str(deleted["id"]),
        },
    }


# Shared with finish retention, which keeps a proposed step on the same host as a finding.
http_origin = _origin
hunt_target_host = _target_host
hunt_target_locator = _target_url
