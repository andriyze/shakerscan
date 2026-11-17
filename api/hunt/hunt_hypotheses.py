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
  attributable to that Hunt: a lead it *created* (title, description, family, dimensions and the
  dedupe key built from them), and its own test record under ``metadata_json.tests["hunt:<id>"]``.
  Endorsing an existing lead adds a text-free endorsement and never moves that lead's confidence;
  proposing the same lead again is a no-op. Transitions carry a closed reason code that must fit
  the move, not prose. An operator retracting the Hunt's entries therefore withholds everything it
  wrote: its leads are closed and masked in every Hunt read, and give up their dedupe key so the
  same lead can be raised again by a trusted source (``hypothesis_retraction``).
* ``supported`` must cite completed testing actions of this Hunt on the target; ``refuted`` still
  needs the deterministic verification the shared gate checks.
* ``derived_from`` records the lineage of a lead (the action, candidate, finding, hypothesis or
  interpretation it follows from), each checked to be a record of this target's asset.
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Mapping

from fastapi import HTTPException

from .interpretations import _ran_actions, clean_text, unknown_records

try:
    import hypothesis_scheduler
except ModuleNotFoundError:  # package import layout
    from .. import hypothesis_scheduler

#: Leads one Hunt may propose (created or endorsed). Bounds what one run adds to shared knowledge.
MAX_HYPOTHESES_PER_HUNT = 200
#: A Hunt claim is a working lease, renewed by claiming again; it lapses if the planner goes away.
DEFAULT_CLAIM_LEASE_SECONDS = 900
MAX_CLAIM_LEASE_SECONDS = 3600
MIN_CLAIM_LEASE_SECONDS = 60
#: Checkpoint and frontier page bound.
MAX_FRONTIER = 25
#: Leads the frontier ranks per read (most recently updated first). Bounds one checkpoint's work.
MAX_RANKED = 200
#: Settled coverage the novelty term reads per read.
MAX_COVERAGE_PAIRS = 2000

#: Lifecycle targets a Hunt may request. ``claimed`` is reached through hypothesis.claim; ``dead``
#: is an operator's administrative close and ``promoted`` belongs to proof reconciliation.
HUNT_TARGET_STATES = ("testing", "supported", "refuted", "blocked", "exhausted", "open")

#: Why a Hunt moved a lead: a closed vocabulary, so a transition stores no free text. Each move
#: accepts only the reasons that describe it (``REASONS_BY_STATE``).
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
#: The reasons that fit each move. ``open`` hands the lead back (nothing found on this angle, out of
#: budget, or simply released); ``exhausted`` and ``blocked`` park it until an operator reopens it.
REASONS_BY_STATE: dict[str, tuple[str, ...]] = {
    "testing": ("testing_started",),
    "supported": ("expected_signal_observed",),
    "refuted": ("deterministic_refutation",),
    "blocked": ("missing_prerequisite", "policy_refused"),
    "exhausted": ("expected_signal_absent",),
    "open": ("released", "budget_exhausted", "expected_signal_absent"),
}
#: A family is an identifier, not prose: it is shown to every Hunt and kept in the action ledger.
FAMILY_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,39}")
CWE_PATTERN = re.compile(r"CWE-[0-9]{1,6}")
_HUNT_OWNER = re.compile(r"hunt:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
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


def _holder(owner: Any) -> str | None:
    """Who holds a lead, as a Hunt may see it: a Hunt's server-built id, or just that someone does.

    Arsenal callers name themselves in free text, which is not shown to a Hunt.
    """
    if not owner:
        return None
    return str(owner) if _HUNT_OWNER.fullmatch(str(owner)) else "other"


def hunt_view(row: Mapping[str, Any], *, owner: str | None = None) -> dict[str, Any]:
    """What a Hunt sees of a lead: no description, no other caller's test text, withheld text hidden.

    A withheld lead (its writer's entries were retracted) shows no word its writer chose: not the
    title, and not the family or dimensions either.
    """
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
    dimensions = metadata.get("dedupe_dimensions") if isinstance(metadata.get("dedupe_dimensions"), dict) else {}
    return {
        "id": str(row["id"]),
        "family": None if withheld else row.get("family"),
        "title": None if withheld else row.get("title"),
        "text_withheld": withheld,
        "status": status,
        "effective_status": effective,
        "version": row.get("version"),
        "confidence": row.get("confidence"),
        "severity_guess": row.get("severity_guess"),
        "source": row.get("source"),
        "dedupe_dimensions": {} if withheld else dimensions,
        "derived_from": [str(item) for item in derived][:20],
        "endorsement_count": len(endorsements) if isinstance(endorsements, list) else 0,
        "has_falsifier": bool((next_action.get("falsifier") and (next_action.get("expected_signal") or next_action.get("expected")))
                              or (metadata.get("falsifier") and metadata.get("expected_signal"))
                              or (mine and mine.get("falsifier") and mine.get("expected_signal"))),
        "claim": {"owner": _holder(row.get("claim_owner")) if claim_active else None, "active": claim_active,
                  "lease_expires_at": expires.isoformat() if claim_active else None,
                  "held_by_this_hunt": bool(owner and claim_active and row.get("claim_owner") == owner)},
        "claimable": effective in {"open", "claimed", "testing", "supported"} and not claim_active,
        "this_hunt_test": mine,
        "updated_at": row["updated_at"].isoformat() if isinstance(row.get("updated_at"), datetime) else row.get("updated_at"),
        "is_proof": False,
    }


def page_row(row: Mapping[str, Any]) -> dict[str, Any]:
    """A ``kind=hypotheses`` query row for a Hunt: retracted text withheld, metadata projected away.

    The row keeps its id, state and version. Every field a retracted writer chose is blanked: the
    title, and the family, dimensions and dedupe key that carry its words as well.
    """
    item = dict(row)
    metadata = _loads(item.pop("metadata_json", None), {}) or {}
    withheld = isinstance(metadata, dict) and "hunt_withheld" in metadata
    dimensions = metadata.get("dedupe_dimensions") if isinstance(metadata, dict) else None
    item["dedupe_dimensions"] = dimensions if isinstance(dimensions, dict) and not withheld else {}
    if withheld:
        for field in ("title", "family", "dedupe_key"):
            if field in item:
                item[field] = None
    item["text_withheld"] = withheld
    if "claim_owner" in item:
        item["claim_owner"] = _holder(item["claim_owner"])
    return item


#: The lead-board operations this module shares with Arsenal (``_upsert_hypothesis`` and the
#: canonical dedupe key it derives, ``claim_hypothesis_row``, ``transition_hypothesis_row``) and
#: the request model they take. The
#: composition root supplies them (``configure_hunt_hypotheses``); importing them here would make
#: Hunt and Arsenal import each other.
_board: dict[str, Any] = {}


def configure_hunt_hypotheses(*, upsert: Any, canonical: Any, claim: Any, transition: Any,
                              request_model: Any) -> None:
    _board.update(upsert=upsert, canonical=canonical, claim=claim, transition=transition,
                  request_model=request_model)


def _shared(name: str) -> Any:
    call = _board.get(name)
    if call is None:
        raise HTTPException(503, {"error": "hypothesis_board_not_ready", "reason_code": "hypothesis_board_not_ready",
                                  "message": "The lead board is not configured in this process"})
    return call


async def proposed_count(conn: Any, target: Any, hunt_run_id: Any) -> int:
    """Leads on its target this Hunt created or endorsed (a Hunt writes leads nowhere else)."""
    return int(await conn.fetchval(
        """SELECT count(*) FROM hypotheses
           WHERE target_id = $1
             AND endorsements @> jsonb_build_array(jsonb_build_object('hunt_run_id', $2::text))""",
        target, str(hunt_run_id)) or 0)


def _number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


async def propose(conn: Any, run: Mapping[str, Any], values: Mapping[str, Any]) -> dict[str, Any]:
    """Record a lead on this Hunt's target, or endorse the identical lead already there.

    Three outcomes, by the canonical dedupe key the shared upsert derives: this Hunt already
    endorsed the lead (nothing is written), another source holds it (this Hunt's text-free
    endorsement is added and the lead's own text and confidence are left alone), or it is new
    (created in this Hunt's words, with its lineage and planned test).
    """
    target = _target(run)
    owner = _owner(run)
    family = str(values.get("family") or "").strip().lower().replace(" ", "_").replace("-", "_")
    if not FAMILY_PATTERN.fullmatch(family):
        raise _refused(422, "invalid_family",
                       "family is a short vulnerability family identifier: a letter, then up to 39 letters, "
                       "digits or underscores (e.g. bola, sqli, mass_assignment)")
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
    cwe = values.get("cwe")
    if cwe is not None:
        cwe = str(cwe).strip().upper()
        if not CWE_PATTERN.fullmatch(cwe):
            raise _refused(422, "invalid_cwe", "cwe is a CWE identifier such as CWE-639")
    test = _test_record(values)
    derived_from = _refs(values, "derived_from")
    unknown = await unknown_records(conn, target, derived_from)
    if unknown:
        raise _refused(422, "unknown_derived_from",
                       "derived_from must name records of this target's asset", unknown=unknown)
    endorsement = {"source": "ai_planner", "created_by": owner, "hunt_run_id": str(run["id"]),
                   "confidence": float(confidence), "derived_from": derived_from}

    def request(**overrides: Any) -> Any:
        return _shared("request_model")(**{**dict(
            source="ai_planner", family=family, dedupe_key=f"hunt:{family}", dedupe_dimensions=dimensions,
            target_id=str(target), cwe=cwe, title=title, description=description, severity_guess=severity,
            confidence=float(confidence), endorsement=endorsement, created_by=owner), **overrides})

    canonical = _shared("canonical")(request())
    async with conn.transaction():
        # Serialize one Hunt's proposals so the per-Hunt bound cannot be raced past.
        await conn.execute("SELECT pg_advisory_xact_lock(hashtext($1))", f"hunt-hypotheses:{run['id']}")
        existing = await conn.fetchrow(
            "SELECT * FROM hypotheses WHERE target_id=$1 AND family=$2 AND dedupe_key=$3",
            target, canonical["family"], canonical["dedupe_key"])
        if existing is not None and any(
                isinstance(item, dict) and item.get("hunt_run_id") == str(run["id"])
                for item in (_loads(existing["endorsements"], []) or [])):
            return _proposal(existing, owner, created=False, already_endorsed=True)
        if await proposed_count(conn, target, run["id"]) >= MAX_HYPOTHESES_PER_HUNT:
            raise _refused(409, "hypothesis_limit_reached",
                           f"This Hunt already proposed {MAX_HYPOTHESES_PER_HUNT} leads; claim and settle existing ones")
        # On another source's lead this Hunt adds an endorsement only: the shared upsert raises a
        # lead's confidence to the highest stated, so the Hunt's stays in its endorsement entry.
        result = await _shared("upsert")(conn, request(confidence=0.0) if existing is not None else request())
        lead_id = uuid.UUID(str(result["hypothesis"]["id"]))
        row = None
        if existing is None and (derived_from or test):
            # Only on a lead this Hunt created (created_by guards the insert losing a race to
            # another source): the lineage and its planned test become part of the lead.
            row = await conn.fetchrow(
                """UPDATE hypotheses
                   SET metadata_json = metadata_json || $2::jsonb,
                       next_test_action = CASE WHEN $3::jsonb IS NULL THEN next_test_action ELSE $3::jsonb END,
                       version = version + 1, updated_at = NOW()
                   WHERE id = $1 AND created_by = $4 RETURNING *""",
                lead_id, json.dumps({"derived_from": derived_from} if derived_from else {}),
                json.dumps({**test, "proposed_by": owner}) if test else None, owner)
        if row is None:
            row = await conn.fetchrow("SELECT * FROM hypotheses WHERE id=$1", lead_id)
    return _proposal(row, owner, created=existing is None and row["created_by"] == owner, already_endorsed=False)


def _proposal(row: Mapping[str, Any], owner: str, *, created: bool, already_endorsed: bool) -> dict[str, Any]:
    view = hunt_view(row, owner=owner)
    return {"ok": True, "created": created, "endorsed_existing": not created,
            "already_endorsed": already_endorsed, "hypothesis": view,
            "next": ("hypothesis.claim with this version before testing it" if view["claimable"]
                     else "this lead is not claimable now; read its status"),
            "is_proof": False, "authority_granted": False}


async def claim(conn: Any, run: Mapping[str, Any], values: Mapping[str, Any]) -> dict[str, Any]:
    """Take (or renew) this Hunt's working lease on one lead of its target.

    Renewing a lease this Hunt already holds only extends it: a lead it moved to ``testing`` or
    ``supported`` stays there.
    """
    lease = values.get("lease_seconds", DEFAULT_CLAIM_LEASE_SECONDS)
    if (isinstance(lease, bool) or not isinstance(lease, int)
            or not MIN_CLAIM_LEASE_SECONDS <= lease <= MAX_CLAIM_LEASE_SECONDS):
        raise _refused(422, "invalid_lease_seconds",
                       f"lease_seconds is {MIN_CLAIM_LEASE_SECONDS}-{MAX_CLAIM_LEASE_SECONDS}")
    owner = _owner(run)
    result = await _shared("claim")(
        conn, _hypothesis_id(values), expected_version=_version(values), owner=owner,
        lease_seconds=lease, target_uuid=_target(run), renewal_keeps_state=True)
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
    if reason_code not in REASONS_BY_STATE[to_state]:
        raise _refused(422, "reason_does_not_fit_transition",
                       f"Moving a lead to {to_state} takes reason_code " + " or ".join(REASONS_BY_STATE[to_state]),
                       accepted=list(REASONS_BY_STATE[to_state]))
    hypothesis_id = _hypothesis_id(values)
    refuted_by = values.get("refuted_by") if to_state == "refuted" else None
    if refuted_by is not None:
        # No free-text reference: a refutation is the verification it names, nothing a Hunt writes.
        if not isinstance(refuted_by, dict) or set(refuted_by) - {"verification_id", "basis"}:
            raise _refused(422, "invalid_refuted_by", "refuted_by names verification_id and basis")
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
    # A test that found nothing stays counted after later moves: it ranks the lead for everyone.
    record["no_signal_count"] = min(99, int(_number(previous.get("no_signal_count")))
                                    + (1 if reason_code == "expected_signal_absent" else 0))
    record["action_ids"] = sorted(set(previous.get("action_ids") or []) | set(ran))[-50:]
    record["evidence_refs"] = sorted(set(previous.get("evidence_refs") or []) | set(evidence))[-50:]
    result = await _shared("transition")(
        conn, hypothesis_id, to_state=to_state, expected_version=_version(values),
        reason=reason_code, refuted_by=refuted_by, created_by=owner, target_uuid=target,
        required_owner=owner, test_record=record, release_claim=to_state == "open")
    current = await conn.fetchrow("SELECT * FROM hypotheses WHERE id=$1", hypothesis_id)
    return {"ok": True, "transitioned": True, "from": result["from"], "to": result["to"],
            "hypothesis": hunt_view(current, owner=owner), "is_proof": False, "authority_granted": False,
            "note": ("supported is a lead, not a finding: verify it with candidate.verify or a registered verifier"
                     if to_state == "supported" else None)}


def _route_key(value: Any) -> str:
    return str(value or "").strip().lower().rstrip("/") or "/"


def rank_frontier(
    rows: list[Mapping[str, Any]],
    *,
    owner: str,
    auth_available: bool,
    negative_pairs: frozenset[tuple[str, str]] = frozenset(),
    remaining_requests: int | None = None,
) -> dict[str, Any]:
    """Order the open leads with the deterministic hypothesis scheduler, from this Hunt's facts.

    A lead's own family, severity guess and confidence count as its source stated them. Everything
    else the scheduler weighs comes from server records: ``auth_available`` from this Hunt's own
    active authentication sessions, novelty from the latest coverage any Hunt on the target
    recorded for the same family at the same route (lost while that is ``negative``), prior
    failures from the tests on the lead that found no signal, and the remaining HTTP request budget
    for cost deferral. No per-read hint is passed. Order: leads this Hunt holds, then claimable
    leads by priority, then budget-deferred ones, then leads another holder is working.
    """
    leads: list[dict[str, Any]] = []
    views: dict[str, dict[str, Any]] = {}
    completed: set[str] = set()
    for row in rows:
        view = hunt_view(row, owner=owner)
        views[view["id"]] = view
        metadata = dict(_loads(row.get("metadata_json"), {}) or {})
        tests = metadata.get("tests") if isinstance(metadata.get("tests"), dict) else {}
        # Every holder's count of tests that found nothing (kept across its later moves).
        failures = sum(int(_number(record.get("no_signal_count"))) for record in tests.values()
                       if isinstance(record, dict))
        metadata["prior_failures"] = max(failures, int(_number(metadata.get("prior_failures"))))
        family = str(row.get("family") or "").strip().lower()
        route = (view["dedupe_dimensions"] or {}).get("route")
        if route and (family, _route_key(route)) in negative_pairs:
            completed.add(str(row.get("dedupe_key") or view["id"]))
        leads.append({"id": view["id"], "family": family, "severity_guess": row.get("severity_guess"),
                      "confidence": row.get("confidence"), "status": row.get("status"),
                      "effective_status": view["effective_status"], "source": row.get("source"),
                      "dedupe_key": str(row.get("dedupe_key") or view["id"]),
                      "next_test_action": _loads(row.get("next_test_action"), {}) or {},
                      "metadata_json": metadata})
    context: dict[str, Any] = {"auth_available": auth_available, "completed_dimensions": sorted(completed)}
    if remaining_requests is not None:
        context["remaining_requests"] = remaining_requests
    ranked = hypothesis_scheduler.rank_hypotheses(leads, context=context)
    ordered: list[tuple[tuple[int, float, str], dict[str, Any]]] = []
    for group, entries in (("scheduled", ranked["scheduled"]), ("deferred", ranked["deferred"])):
        for entry in entries:
            view = views[str(entry["hypothesis_id"])]
            claim = view["claim"]
            tier = (0 if claim["held_by_this_hunt"] else 3 if claim["active"]
                    else 1 if group == "scheduled" else 2)
            view["priority"] = entry["priority"]
            view["priority_breakdown"] = entry["breakdown"]
            view["deferred_reason"] = entry.get("deferred_reason")
            ordered.append(((tier, -float(entry["priority"]), view["id"]), view))
    ordered.sort(key=lambda item: item[0])
    return {"hypotheses": [view for _, view in ordered],
            "ranking": {"version": ranked["version"], "counts": ranked["counts"],
                        "auth_available": auth_available, "novelty_settled": len(completed),
                        "remaining_requests": remaining_requests}}


def _remaining_requests(run: Mapping[str, Any]) -> int | None:
    """HTTP requests this Hunt may still send: its ``max_http_requests`` ceiling less what it used."""
    budget = _loads(run.get("budget_json"), {}) or {}
    used = _loads(run.get("budget_used_json"), {}) or {}
    if not isinstance(budget, dict) or budget.get("max_http_requests") is None:
        return None
    spent = used.get("http_requests") if isinstance(used, dict) else 0
    return max(0, int(_number(budget.get("max_http_requests"))) - int(_number(spent)))


async def frontier(conn: Any, run: Mapping[str, Any], *, limit: int = MAX_FRONTIER) -> dict[str, Any]:
    """The open work on this Hunt's target, ranked: leads this Hunt holds first, then by priority."""
    owner = _owner(run)
    if not (run.get("device_target_id") or run.get("target_id")):
        return {"hypotheses": [], "total": 0, "truncated": False, "limit": limit, "supported": False}
    target = _target(run)
    rows = await conn.fetch(
        """SELECT h.*, COUNT(*) OVER() AS total_count FROM hypotheses h
           WHERE h.target_id=$1 AND h.status IN ('open','claimed','testing','supported')
             AND NOT (h.metadata_json ? 'hunt_withheld')
           ORDER BY (h.claim_owner=$2 AND h.claim_lease_expires_at > NOW()) DESC NULLS LAST,
                    h.updated_at DESC, h.id DESC
           LIMIT $3""",
        target, owner, MAX_RANKED)
    total = int(rows[0]["total_count"]) if rows else 0
    auth_available = bool(await conn.fetchval(
        """SELECT EXISTS(SELECT 1 FROM auth_sessions WHERE owner_kind='hunt' AND owner_id=$1
                         AND status='active' AND expires_at > NOW())""", uuid.UUID(str(run["id"]))))
    # The latest event of each coverage angle on this target, across its Hunts (an angle's
    # fingerprint is the same in every run): a family whose latest word at a route is negative makes
    # a lead for that family and route no longer novel, until a later Hunt reopens the angle.
    settled = await conn.fetch(
        """SELECT family, route FROM (
               SELECT DISTINCT ON (e.fingerprint) lower(e.family) AS family,
                      e.locus_json->>'route' AS route, e.status
               FROM hunt_coverage_angle_events e JOIN hunt_runs r ON r.id = e.hunt_run_id
               WHERE COALESCE(r.device_target_id, r.target_id) = $1
               ORDER BY e.fingerprint, e.event_seq DESC) latest
           WHERE status = 'negative' AND route IS NOT NULL
           LIMIT $2""",
        target, MAX_COVERAGE_PAIRS)
    ranked = rank_frontier(
        list(rows), owner=owner, auth_available=auth_available,
        negative_pairs=frozenset((row["family"], _route_key(row["route"])) for row in settled),
        remaining_requests=_remaining_requests(run))
    page = ranked["hypotheses"][:limit]
    return {"hypotheses": page, "total": total, "ranked": len(ranked["hypotheses"]),
            "truncated": total > len(page), "limit": limit, "ranking": ranked["ranking"],
            "read_with": "POST /hunts/{hunt_id}/query kind=hypotheses",
            "work_with": ["hypothesis.propose", "hypothesis.claim", "hypothesis.transition"]}
