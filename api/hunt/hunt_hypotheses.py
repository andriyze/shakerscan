"""A Hunt works the target's hypothesis frontier: propose, claim and move leads through their lifecycle.

The frontier is the existing ``hypotheses`` lead board (shared target knowledge, invariant 11), not a
Hunt-private list: a lead a Hunt proposes is seen by later Hunts and by Arsenal, and a lead someone
else recorded can be claimed and tested by a Hunt. Every write goes through the one implementation
Arsenal uses (``_upsert_hypothesis``, ``claim_hypothesis_row``, ``transition_hypothesis_row``), so
the dedupe key, compare-and-set claim, lifecycle edges, falsifier gate and deterministic refutation
check are shared, never re-implemented here (invariant 10).

What a Hunt adds, and what it may not:

* Leads are advisory. Nothing here sends traffic, creates or changes a finding, or grants authority.
  ``promoted`` is unreachable from a Hunt; only proof reconciliation promotes (invariant 7).
* Writes are fenced to the Hunt's own target: another target's lead is reported as not found.
* Text a Hunt writes is bounded and screened (``clean_text``), and is stored only where it is
  attributable to that Hunt: the title and description of a lead it *created*, and its own test
  record under ``metadata_json.tests["hunt:<id>"]``. Endorsing an existing lead adds a text-free
  endorsement, and transitions carry a closed reason code, not prose. An operator retracting the
  Hunt's entries therefore withholds everything it wrote (``retract_hunt_hypotheses``).
* ``supported`` must cite completed testing actions of this Hunt on the target; ``refuted`` still
  needs the deterministic verification the shared gate checks.
* ``derived_from`` records the lineage of a lead (the action, candidate, finding, hypothesis or
  interpretation it follows from), each checked to be a record of this target's asset.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Mapping

from fastapi import HTTPException

from .interpretations import _ran_actions, clean_text, unknown_records

#: Leads one Hunt may propose (created or endorsed). Bounds what one run adds to shared knowledge.
MAX_HYPOTHESES_PER_HUNT = 200
#: A Hunt claim is a working lease, renewed by claiming again; it lapses if the planner goes away.
DEFAULT_CLAIM_LEASE_SECONDS = 900
MAX_CLAIM_LEASE_SECONDS = 3600
MIN_CLAIM_LEASE_SECONDS = 60
#: Checkpoint and frontier page bound.
MAX_FRONTIER = 25

#: Lifecycle targets a Hunt may request. ``claimed`` is reached through hypothesis.claim; ``dead``
#: is an operator's administrative close and ``promoted`` belongs to proof reconciliation.
HUNT_TARGET_STATES = ("testing", "supported", "refuted", "blocked", "exhausted", "open")

#: Why a Hunt moved a lead: a closed vocabulary, so a transition stores no free text.
REASON_CODES = (
    "testing_started",
    "expected_signal_observed",
    "expected_signal_absent",
    "deterministic_refutation",
    "missing_prerequisite",
    "policy_refused",
    "budget_exhausted",
    "released",
)

#: The dedupe dimensions a Hunt may name (the canonical set ``_upsert_hypothesis`` keys on).
DIMENSIONS = ("method", "route", "object_key", "principal_actor", "principal_other", "tenant",
              "parameter_path", "body_path", "proof_surface")
SEVERITIES = ("critical", "high", "medium", "low", "info")
#: Refutation bases a Hunt may cite. ``human_approved_review`` is a person's decision a Hunt never asserts.
HUNT_REFUTATION_BASES = ("deterministic_replay", "parser_protocol", "cryptographic")


def _owner(run: Mapping[str, Any]) -> str:
    return f"hunt:{run['id']}"


def _target(run: Mapping[str, Any]) -> uuid.UUID:
    return uuid.UUID(str(run.get("device_target_id") or run["target_id"]))


def _refused(status: int, error: str, message: str, **extra: Any) -> HTTPException:
    return HTTPException(status, {"error": error, "reason_code": error, "message": message, **extra})


def _loads(value: Any, default: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return default
    return default if value is None else value


def _hypothesis_id(values: Mapping[str, Any]) -> uuid.UUID:
    try:
        return uuid.UUID(str(values.get("hypothesis_id")))
    except (TypeError, ValueError):
        raise _refused(422, "invalid_hypothesis_id", "hypothesis_id must be a UUID") from None


def _version(values: Mapping[str, Any]) -> int:
    value = values.get("expected_version")
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise _refused(422, "invalid_expected_version",
                       "expected_version must be the lead's current version (an integer of at least 1)")
    return value


def _refs(values: Mapping[str, Any], field: str, *, maximum: int = 20) -> list[str]:
    raw = values.get(field) or []
    if not isinstance(raw, list) or len(raw) > maximum:
        raise _refused(422, f"invalid_{field}", f"{field} must be a list of at most {maximum} ids")
    refs: list[str] = []
    for item in raw:
        try:
            ref = str(uuid.UUID(str(item)))
        except (TypeError, ValueError):
            raise _refused(422, f"invalid_{field}", f"{field} must contain UUIDs") from None
        if ref not in refs:
            refs.append(ref)
    return refs


def _text(values: Mapping[str, Any], field: str, maximum: int, *, required: bool = False) -> str | None:
    try:
        text = clean_text(values.get(field), field=field, maximum=maximum, required=required)
    except ValueError as exc:
        raise _refused(422, "invalid_hypothesis_text", str(exc)) from None
    return text or None


def _test_record(values: Mapping[str, Any]) -> dict[str, str]:
    falsifier = _text(values, "falsifier", 1000)
    expected = _text(values, "expected_signal", 1000)
    if bool(falsifier) != bool(expected):
        raise _refused(422, "incomplete_falsifier",
                       "falsifier and expected_signal are given together: what you will run to try to "
                       "disprove the lead, and the observable result that would support it")
    return {"falsifier": falsifier, "expected_signal": expected} if falsifier else {}


def hunt_view(row: Mapping[str, Any], *, owner: str | None = None) -> dict[str, Any]:
    """What a Hunt sees of a lead: no description, no other caller's test text, withheld text hidden."""
    metadata = _loads(row.get("metadata_json"), {}) or {}
    endorsements = _loads(row.get("endorsements"), []) or []
    next_action = _loads(row.get("next_test_action"), {}) or {}
    tests = metadata.get("tests") if isinstance(metadata.get("tests"), dict) else {}
    withheld = "hunt_withheld" in metadata
    now = datetime.now(timezone.utc)
    expires = row.get("claim_lease_expires_at")
    if isinstance(expires, str):
        try:
            expires = datetime.fromisoformat(expires)
        except ValueError:
            expires = None
    claim_active = bool(row.get("claim_owner") and isinstance(expires, datetime) and expires > now)
    status = str(row.get("status") or "")
    effective = "open" if status in {"claimed", "testing"} and row.get("claim_owner") and not claim_active else status
    mine = tests.get(owner) if owner and isinstance(tests.get(owner), dict) else None
    derived = metadata.get("derived_from") if isinstance(metadata.get("derived_from"), list) else []
    return {
        "id": str(row["id"]),
        "family": row.get("family"),
        "title": None if withheld else row.get("title"),
        "text_withheld": withheld,
        "status": status,
        "effective_status": effective,
        "version": row.get("version"),
        "confidence": row.get("confidence"),
        "severity_guess": row.get("severity_guess"),
        "source": row.get("source"),
        "dedupe_dimensions": metadata.get("dedupe_dimensions") if isinstance(metadata.get("dedupe_dimensions"), dict) else {},
        "derived_from": [str(item) for item in derived][:20],
        "endorsement_count": len(endorsements) if isinstance(endorsements, list) else 0,
        "has_falsifier": bool((next_action.get("falsifier") and (next_action.get("expected_signal") or next_action.get("expected")))
                              or (metadata.get("falsifier") and metadata.get("expected_signal")) or mine),
        "claim": {"owner": row.get("claim_owner"), "active": claim_active,
                  "lease_expires_at": expires.isoformat() if isinstance(expires, datetime) else None,
                  "held_by_this_hunt": bool(owner and claim_active and row.get("claim_owner") == owner)},
        "claimable": effective in {"open", "claimed", "testing", "supported"} and not claim_active,
        "this_hunt_test": mine,
        "updated_at": row["updated_at"].isoformat() if isinstance(row.get("updated_at"), datetime) else row.get("updated_at"),
        "is_proof": False,
    }


def page_row(row: Mapping[str, Any]) -> dict[str, Any]:
    """A ``kind=hypotheses`` query row for a Hunt: retracted text withheld, metadata projected away."""
    item = dict(row)
    metadata = _loads(item.pop("metadata_json", None), {}) or {}
    withheld = isinstance(metadata, dict) and "hunt_withheld" in metadata
    if withheld:
        item["title"] = None
    item["text_withheld"] = withheld
    dimensions = metadata.get("dedupe_dimensions") if isinstance(metadata, dict) else None
    item["dedupe_dimensions"] = dimensions if isinstance(dimensions, dict) else {}
    return item


#: The lead-board operations this module shares with Arsenal (``_upsert_hypothesis``,
#: ``claim_hypothesis_row``, ``transition_hypothesis_row``) and the request model they take. The
#: composition root supplies them (``configure_hunt_hypotheses``); importing them here would make
#: Hunt and Arsenal import each other.
_board: dict[str, Any] = {}


def configure_hunt_hypotheses(*, upsert: Any, claim: Any, transition: Any, request_model: Any) -> None:
    _board.update(upsert=upsert, claim=claim, transition=transition, request_model=request_model)


def _shared(name: str) -> Any:
    call = _board.get(name)
    if call is None:
        raise HTTPException(503, {"error": "hypothesis_board_not_ready", "reason_code": "hypothesis_board_not_ready",
                                  "message": "The lead board is not configured in this process"})
    return call


async def proposed_count(conn: Any, hunt_run_id: Any) -> int:
    return int(await conn.fetchval(
        """SELECT count(*) FROM hypotheses
           WHERE endorsements @> jsonb_build_array(jsonb_build_object('hunt_run_id', $1::text))""",
        str(hunt_run_id)) or 0)


async def propose(conn: Any, run: Mapping[str, Any], values: Mapping[str, Any]) -> dict[str, Any]:
    """Record a lead on this Hunt's target, or endorse the identical lead already there."""
    target = _target(run)
    owner = _owner(run)
    family = str(values.get("family") or "").strip().lower().replace(" ", "_")
    if not family or len(family) > 80:
        raise _refused(422, "invalid_family", "family is a vulnerability family of 1-80 characters (e.g. bola, sqli)")
    title = _text(values, "title", 200, required=True)
    description = _text(values, "description", 2000)
    raw_dimensions = values.get("dedupe_dimensions") or {}
    if not isinstance(raw_dimensions, dict) or set(raw_dimensions) - set(DIMENSIONS):
        raise _refused(422, "invalid_dedupe_dimensions",
                       "dedupe_dimensions names only " + ", ".join(DIMENSIONS))
    dimensions = {key: _text(raw_dimensions, key, 512) for key in DIMENSIONS if raw_dimensions.get(key) is not None}
    dimensions = {key: value for key, value in dimensions.items() if value}
    if not dimensions:
        raise _refused(422, "missing_dedupe_dimensions",
                       "name where the lead applies in dedupe_dimensions (at least one of "
                       + ", ".join(DIMENSIONS) + "), so the same lead from another source merges with it")
    severity = values.get("severity_guess")
    if severity is not None and severity not in SEVERITIES:
        raise _refused(422, "invalid_severity_guess", "severity_guess is one of " + ", ".join(SEVERITIES))
    confidence = values.get("confidence", 0.0)
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
        raise _refused(422, "invalid_confidence", "confidence is a number from 0 to 1")
    cwe = _text(values, "cwe", 20)
    test = _test_record(values)
    derived_from = _refs(values, "derived_from")
    unknown = await unknown_records(conn, target, derived_from)
    if unknown:
        raise _refused(422, "unknown_derived_from",
                       "derived_from must name records of this target's asset", unknown=unknown)
    async with conn.transaction():
        # Serialize one Hunt's proposals so the per-Hunt bound cannot be raced past.
        await conn.execute("SELECT pg_advisory_xact_lock(hashtext($1))", f"hunt-hypotheses:{run['id']}")
        if await proposed_count(conn, run["id"]) >= MAX_HYPOTHESES_PER_HUNT:
            raise _refused(409, "hypothesis_limit_reached",
                           f"This Hunt already proposed {MAX_HYPOTHESES_PER_HUNT} leads; claim and settle existing ones")
        endorsement = {"source": "ai_planner", "created_by": owner, "hunt_run_id": str(run["id"]),
                       "confidence": float(confidence), "derived_from": derived_from}
        request = _shared("request_model")(
            source="ai_planner", family=family, dedupe_key=f"hunt:{family}",
            dedupe_dimensions=dimensions, target_id=str(target), cwe=cwe, title=title,
            description=description, severity_guess=severity, confidence=float(confidence),
            endorsement=endorsement, created_by=owner)
        result = await _shared("upsert")(conn, request)
        hypothesis = result["hypothesis"]
        created = bool(result.get("created"))
        if created and (derived_from or test):
            # Only on a lead this Hunt created: the lineage and its planned test become part of it.
            # An existing lead keeps its own text; this Hunt states its test when it claims and tests.
            row = await conn.fetchrow(
                """UPDATE hypotheses
                   SET metadata_json = metadata_json || $2::jsonb,
                       next_test_action = CASE WHEN $3::jsonb IS NULL THEN next_test_action ELSE $3::jsonb END,
                       version = version + 1, updated_at = NOW()
                   WHERE id = $1 RETURNING *""",
                uuid.UUID(str(hypothesis["id"])),
                json.dumps({"derived_from": derived_from} if derived_from else {}),
                json.dumps({**test, "proposed_by": owner}) if test else None)
        else:
            row = await conn.fetchrow("SELECT * FROM hypotheses WHERE id=$1", uuid.UUID(str(hypothesis["id"])))
    return {"ok": True, "created": created, "endorsed_existing": not created,
            "hypothesis": hunt_view(row, owner=owner),
            "next": ("hypothesis.claim with this version before testing it" if hunt_view(row)["claimable"]
                     else "this lead is not claimable now; read its status"),
            "is_proof": False, "authority_granted": False}


async def claim(conn: Any, run: Mapping[str, Any], values: Mapping[str, Any]) -> dict[str, Any]:
    """Take (or renew) this Hunt's working lease on one lead of its target."""
    lease = values.get("lease_seconds", DEFAULT_CLAIM_LEASE_SECONDS)
    if (isinstance(lease, bool) or not isinstance(lease, int)
            or not MIN_CLAIM_LEASE_SECONDS <= lease <= MAX_CLAIM_LEASE_SECONDS):
        raise _refused(422, "invalid_lease_seconds",
                       f"lease_seconds is {MIN_CLAIM_LEASE_SECONDS}-{MAX_CLAIM_LEASE_SECONDS}")
    owner = _owner(run)
    result = await _shared("claim")(
        conn, _hypothesis_id(values), expected_version=_version(values), owner=owner,
        lease_seconds=lease, target_uuid=_target(run))
    row = await conn.fetchrow("SELECT * FROM hypotheses WHERE id=$1", uuid.UUID(str(result["hypothesis"]["id"])))
    return {"ok": True, "claimed": True, "hypothesis": hunt_view(row, owner=owner),
            "is_proof": False, "authority_granted": False}


async def transition(conn: Any, run: Mapping[str, Any], values: Mapping[str, Any]) -> dict[str, Any]:
    """Move a lead this Hunt holds through its lifecycle, citing what this Hunt ran."""
    owner = _owner(run)
    target = _target(run)
    to_state = str(values.get("to") or "").strip().lower()
    if to_state not in HUNT_TARGET_STATES:
        raise _refused(422, "transition_not_available_to_hunt",
                       "A Hunt moves a lead to " + ", ".join(HUNT_TARGET_STATES)
                       + "; claiming is hypothesis.claim, dead is an operator's close and promotion needs proof reconciliation")
    reason_code = values.get("reason_code")
    if reason_code not in REASON_CODES:
        raise _refused(422, "invalid_reason_code", "reason_code is one of " + ", ".join(REASON_CODES))
    hypothesis_id = _hypothesis_id(values)
    refuted_by = values.get("refuted_by") if to_state == "refuted" else None
    if refuted_by is not None:
        if not isinstance(refuted_by, dict) or set(refuted_by) - {"verification_id", "basis", "ref"}:
            raise _refused(422, "invalid_refuted_by", "refuted_by names verification_id, basis and optionally ref")
        if refuted_by.get("basis") not in HUNT_REFUTATION_BASES:
            raise _refused(422, "refutation_basis_not_available_to_hunt",
                           "A Hunt refutes on a machine basis: " + ", ".join(HUNT_REFUTATION_BASES))
    evidence = _refs(values, "evidence_refs")
    unknown = await unknown_records(conn, target, evidence)
    if unknown:
        raise _refused(422, "unknown_evidence_refs", "evidence_refs must name records of this target's asset",
                       unknown=unknown)
    ran = await _ran_actions(conn, target, evidence, frozenset({"completed"}), hunt_run_id=run["id"])
    if to_state == "supported" and not ran:
        raise _refused(422, "support_requires_this_hunt_actions",
                       "supported cites at least one completed testing action of this Hunt in evidence_refs; "
                       "a lead is not supported by reasoning alone (and supported is still not proof)")
    row = await conn.fetchrow("SELECT metadata_json FROM hypotheses WHERE id=$1 AND target_id=$2",
                              hypothesis_id, target)
    if not row:
        raise HTTPException(404, "Hypothesis not found")
    previous = (_loads(row["metadata_json"], {}) or {}).get("tests") or {}
    previous = previous.get(owner) if isinstance(previous, dict) and isinstance(previous.get(owner), dict) else {}
    stated = _test_record(values)
    record = {key: value for key, value in {**previous, **stated}.items() if key in {"falsifier", "expected_signal"}}
    record["hunt_run_id"] = str(run["id"])
    record["reason_code"] = reason_code
    record["action_ids"] = sorted(set(previous.get("action_ids") or []) | set(ran))[-50:]
    record["evidence_refs"] = sorted(set(previous.get("evidence_refs") or []) | set(evidence))[-50:]
    result = await _shared("transition")(
        conn, hypothesis_id, to_state=to_state, expected_version=_version(values),
        reason=reason_code, refuted_by=refuted_by,
        created_by=owner, target_uuid=target, required_owner=owner, test_record=record)
    current = await conn.fetchrow("SELECT * FROM hypotheses WHERE id=$1", hypothesis_id)
    return {"ok": True, "transitioned": True, "from": result["from"], "to": result["to"],
            "hypothesis": hunt_view(current, owner=owner), "is_proof": False, "authority_granted": False,
            "note": ("supported is a lead, not a finding: verify it with candidate.verify or a registered verifier"
                     if to_state == "supported" else None)}


async def frontier(conn: Any, run: Mapping[str, Any], *, limit: int = MAX_FRONTIER) -> dict[str, Any]:
    """The open work on this Hunt's target: leads this Hunt holds first, then claimable ones."""
    owner = _owner(run)
    if not (run.get("device_target_id") or run.get("target_id")):
        return {"hypotheses": [], "total": 0, "truncated": False, "limit": limit, "supported": False}
    rows = await conn.fetch(
        """SELECT h.*, COUNT(*) OVER() AS total_count FROM hypotheses h
           WHERE h.target_id=$1 AND h.status IN ('open','claimed','testing','supported')
             AND NOT (h.metadata_json ? 'hunt_withheld')
           ORDER BY (h.claim_owner=$2 AND h.claim_lease_expires_at > NOW()) DESC NULLS LAST,
                    CASE h.status WHEN 'testing' THEN 0 WHEN 'supported' THEN 1 WHEN 'claimed' THEN 2 ELSE 3 END,
                    h.confidence DESC, h.updated_at DESC, h.id DESC
           LIMIT $3""",
        _target(run), owner, limit)
    total = int(rows[0]["total_count"]) if rows else 0
    return {"hypotheses": [hunt_view(row, owner=owner) for row in rows], "total": total,
            "truncated": total > len(rows), "limit": limit,
            "read_with": "POST /hunts/{hunt_id}/query kind=hypotheses",
            "work_with": ["hypothesis.propose", "hypothesis.claim", "hypothesis.transition"]}
