"""Evidence-backed Hunt coverage angles and compact continuation checkpoints.

The external planner may describe what it intends to test, but ShakerScan owns the
ledger and only accepts settled coverage claims when they cite same-Hunt actions that
actually ran (rules in ``coverage_evidence``). Coverage is deliberately finer grained than a vulnerability family:
method, route/object/sink, mechanism, principal context, and application state can all
make one angle materially different from another.

The locus vocabulary is closed and published (``COVERAGE_LOCUS_KEYS``). An unknown key
is refused instead of dropped, because a dropped dimension silently merges two different
experiments into one fingerprint.

Events are append-only and ordered by ``event_seq``, which is assigned at insert while
the writer holds the Hunt row lock, so it follows commit order. An angle's current state
is its highest-sequence event; the record export carries every event, superseded ones
included. One supersession is refused: an event that cites no new
same-Hunt evidence cannot drop the candidate an angle is bound to.

Planner-supplied strings are passed through the shared redactor before they are stored
or fingerprinted, so a secret-shaped value never persists and never distinguishes angles.
A Hunt holds at most ``MAX_COVERAGE_EVENTS_PER_HUNT`` events.

This is investigation state, not proof.  A coverage event can point at a candidate,
but neither a planner-written angle nor a checkpoint may create or verify a finding.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
from typing import Any
from uuid import UUID

from .coverage_evidence import (
    TERMINAL_ACTION_STATUSES,
    CoverageLedgerError,
    owned_action_evidence,
    validate_evidence_claim,
)

COVERAGE_LEDGER_SCHEMA = "hunt-coverage-ledger/v1"
COVERAGE_HISTORY_SCHEMA = "hunt-coverage-history/v1"
HUNT_CHECKPOINT_SCHEMA = "hunt-checkpoint/v1"

COVERAGE_ANGLE_STATUSES = frozenset({
    "planned",
    "testing",
    "negative",
    "partial",
    "blocked",
    "candidate",
})
# Coverage may be appended while a Hunt is unfinished. budget_exhausted is resumable, so
# it accepts evidence-bound events; a set completed_at marks a finished run.
COVERAGE_WRITABLE_RUN_STATUSES = frozenset({"active", "awaiting_planner", "budget_exhausted"})
MAX_EVIDENCE_ACTIONS = 50
MAX_CHECKPOINT_ANGLES = 200
MAX_CHECKPOINT_CONTINUATION = 200
MAX_CHECKPOINT_CANDIDATES = 100
# Several events per examined angle fit comfortably; the record export bound is higher.
MAX_COVERAGE_EVENTS_PER_HUNT = 5_000
MAX_JSON_BYTES = 16_384
MAX_LOCUS_VALUE_CHARS = 1_000
_TEXT_LIMITS = {
    "family": 80, "mechanism": 1_000, "hypothesis": 8_000, "blocker": 2_000,
    "proof_gap": 4_000,
}

_SECRET_KEY_PARTS = (
    "authorization",
    "cookie",
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "session_key",
)

# The complete, published locus vocabulary: semantic dimensions only. Execution
# provenance (request/action/capability/collection IDs) belongs in evidence references;
# putting it in the fingerprint would make a retry of the same experiment look new.
# skills/hunt/SKILL.md lists the same keys on its "Locus keys:" line (a test enforces it).
COVERAGE_LOCUS_KEYS: tuple[str, ...] = (
    "method",
    "route",
    "path",
    "url",
    "origin",
    "scheme",
    "port",
    "transport",
    "protocol",
    "service",
    "service_name",
    "operation",
    "operation_id",
    "object",
    "object_id",
    "object_kind",
    "resource_kind",
    "parameter",
    "input",
    "input_path",
    "sink",
    "application_state",
    "variant",
)
_LOCUS_KEY_SET = frozenset(COVERAGE_LOCUS_KEYS)


def _redacted(value: Any) -> Any:
    """Mask secret-shaped values with the shared redactor before storage."""
    try:
        from redaction import redact_sensitive
    except ModuleNotFoundError:
        from scanner.redaction import redact_sensitive
    return redact_sensitive(value, redact_strings=True, scrub_text=True)


def _text(value: Any, *, field: str, required: bool = False) -> str:
    result = str(value or "").strip()
    if required and not result:
        raise CoverageLedgerError(
            "coverage_field_required", f"Required coverage field is empty: {field}",
        )
    if len(result) > _TEXT_LIMITS[field]:
        raise CoverageLedgerError(
            "coverage_field_too_long", f"{field} exceeds {_TEXT_LIMITS[field]} characters",
        )
    return str(_redacted(result))


def _json_value(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return value
    return value


def _reject_secret_keys(value: Any, path: str = "context") -> None:
    if isinstance(value, Mapping):
        for raw_key, child in value.items():
            key = str(raw_key).strip().lower()
            if any(part in key for part in _SECRET_KEY_PARTS):
                raise CoverageLedgerError(
                    "coverage_secret_context_forbidden",
                    f"{path} must contain labels and state only, not secret-bearing fields",
                )
            _reject_secret_keys(child, f"{path}.{key}" if key else path)
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _reject_secret_keys(child, f"{path}[{index}]")


def _bounded_json_object(value: Any, *, field: str) -> dict[str, Any]:
    if value in (None, ""):
        return {}
    if not isinstance(value, Mapping):
        raise CoverageLedgerError(
            "coverage_context_invalid", f"{field} must be a JSON object",
        )
    _reject_secret_keys(value, field)
    try:
        encoded = json.dumps(value, allow_nan=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError, RecursionError) as exc:
        raise CoverageLedgerError(
            "coverage_context_invalid", f"{field} must contain finite JSON values",
        ) from exc
    if len(encoded.encode("utf-8")) > MAX_JSON_BYTES:
        raise CoverageLedgerError(
            "coverage_context_too_large", f"{field} exceeds {MAX_JSON_BYTES} bytes",
        )
    return _redacted(json.loads(encoded))


def _locus_error(code: str, message: str, **details: Any) -> CoverageLedgerError:
    return CoverageLedgerError(
        code,
        f"{message}. Accepted locus keys: {', '.join(COVERAGE_LOCUS_KEYS)}",
        details={**details, "accepted_locus_keys": list(COVERAGE_LOCUS_KEYS)},
    )


def canonical_coverage_locus(value: Any) -> dict[str, Any]:
    """Return the dimensions that identify one concrete test angle, refusing unknown input."""
    if value in (None, ""):
        return {}
    if not isinstance(value, Mapping):
        raise _locus_error("coverage_locus_invalid", "locus must be a JSON object")
    unknown = sorted(str(key)[:80] for key in value if str(key) not in _LOCUS_KEY_SET)
    if unknown:
        raise _locus_error(
            "coverage_locus_key_unsupported",
            f"Unsupported locus key(s): {', '.join(unknown[:10])}",
            unsupported_locus_keys=unknown[:20],
        )
    result: dict[str, Any] = {}
    for key in COVERAGE_LOCUS_KEYS:
        item = value.get(key)
        if item is None or (isinstance(item, str) and not item.strip()):
            continue
        if isinstance(item, bool) or not isinstance(item, (str, int)):
            raise _locus_error(
                "coverage_locus_value_invalid", f"locus.{key} must be a string or integer",
            )
        text = str(item).strip()
        if key == "port":
            port = int(text) if text.isdigit() else 0
            if not 1 <= port <= 65535:
                raise _locus_error(
                    "coverage_locus_value_invalid",
                    "locus.port must be an integer from 1 to 65535",
                )
            result[key] = port
            continue
        if len(text) > MAX_LOCUS_VALUE_CHARS:
            raise _locus_error(
                "coverage_locus_value_too_long",
                f"locus.{key} exceeds {MAX_LOCUS_VALUE_CHARS} characters",
            )
        text = str(_redacted(text))
        result[key] = text.upper() if key == "method" else text
    return result


def _action_ids(value: Any, *, field: str) -> list[str]:
    items = value if isinstance(value, Sequence) and not isinstance(value, (str, bytes)) else []
    result: list[str] = []
    for item in items:
        text = str(item or "").strip()
        if not text:
            continue
        try:
            parsed = str(UUID(text))
        except ValueError as exc:
            raise CoverageLedgerError(
                "coverage_evidence_id_invalid", f"{field} contains a non-UUID action id",
            ) from exc
        if parsed not in result:
            result.append(parsed)
    if len(result) > MAX_EVIDENCE_ACTIONS:
        raise CoverageLedgerError(
            "coverage_evidence_too_many",
            f"{field} may cite at most {MAX_EVIDENCE_ACTIONS} actions",
        )
    return result


def coverage_fingerprint(
    *,
    family: Any,
    locus: Any,
    mechanism: Any,
    principal_context: Any,
) -> str:
    material = {
        "family": _text(family, field="family", required=True).lower(),
        "locus": canonical_coverage_locus(locus),
        "mechanism": _text(mechanism, field="mechanism").lower(),
        "principal_context": _bounded_json_object(
            principal_context, field="principal_context",
        ),
    }
    if not material["locus"]:
        raise _locus_error(
            "coverage_angle_too_broad",
            "Coverage must name a concrete locus; a family- or mechanism-only claim is too broad",
        )
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def normalize_coverage_angle(values: Mapping[str, Any]) -> dict[str, Any]:
    status = str(values.get("status") or "").strip().lower()
    if status not in COVERAGE_ANGLE_STATUSES:
        raise CoverageLedgerError(
            "coverage_status_invalid", f"Unsupported coverage status: {status[:40]}",
        )

    family = _text(values.get("family"), field="family", required=True).lower()
    locus = canonical_coverage_locus(values.get("locus"))
    mechanism = _text(values.get("mechanism"), field="mechanism")
    principal_context = _bounded_json_object(
        values.get("principal_context") or {}, field="principal_context",
    )
    fingerprint = coverage_fingerprint(
        family=family,
        locus=locus,
        mechanism=mechanism,
        principal_context=principal_context,
    )
    evidence = _action_ids(values.get("evidence_action_ids"), field="evidence_action_ids")
    contradictions = _action_ids(
        values.get("contradictory_evidence_action_ids"),
        field="contradictory_evidence_action_ids",
    )
    candidate_id = str(values.get("candidate_id") or "").strip()
    if candidate_id:
        try:
            candidate_id = str(UUID(candidate_id))
        except ValueError as exc:
            raise CoverageLedgerError(
                "coverage_candidate_id_invalid", "candidate_id must be a UUID",
            ) from exc

    blocker = _text(values.get("blocker"), field="blocker")
    proof_gap = _text(values.get("proof_gap"), field="proof_gap")
    if status in {"negative", "partial", "candidate"} and not evidence:
        raise CoverageLedgerError(
            "coverage_evidence_required",
            f"{status} coverage requires at least one same-Hunt evidence action",
        )
    if status == "blocked" and not (blocker or proof_gap):
        raise CoverageLedgerError(
            "coverage_blocker_required",
            "Blocked coverage must name the blocker or unresolved proof gap",
        )
    if status == "candidate" and not candidate_id:
        raise CoverageLedgerError(
            "coverage_candidate_required",
            "Candidate coverage must reference the Hunt candidate it produced",
        )

    return {
        "fingerprint": fingerprint,
        "family": family,
        "locus": locus,
        "mechanism": mechanism,
        "principal_context": principal_context,
        "hypothesis": _text(values.get("hypothesis"), field="hypothesis"),
        "status": status,
        "evidence_action_ids": evidence,
        "contradictory_evidence_action_ids": contradictions,
        "candidate_id": candidate_id or None,
        "blocker": blocker or None,
        "proof_gap": proof_gap or None,
    }


async def _require_owned_candidate(
    conn: Any, *, hunt_run_id: str, candidate_id: str | None,
) -> None:
    if not candidate_id:
        return
    found = await conn.fetchval(
        """SELECT 1
           FROM investigation_candidate_observations
           WHERE candidate_id=$1::uuid AND hunt_run_id=$2::uuid
           LIMIT 1""",
        candidate_id,
        hunt_run_id,
    )
    if not found:
        raise CoverageLedgerError(
            "coverage_candidate_not_owned",
            "Coverage candidate must have been produced or observed by this Hunt",
        )


async def _require_candidate_binding_preserved(
    conn: Any, *, hunt_run_id: str, angle: Mapping[str, Any],
) -> None:
    """An event without new evidence cannot replace the candidate an angle is bound to."""
    if angle["evidence_action_ids"]:
        return
    previous = await conn.fetchrow(
        """SELECT candidate_id
           FROM hunt_coverage_angle_events
           WHERE hunt_run_id=$1::uuid AND fingerprint=$2
           ORDER BY event_seq DESC
           LIMIT 1""",
        hunt_run_id,
        angle["fingerprint"],
    )
    bound = str(previous["candidate_id"]) if previous and previous["candidate_id"] else None
    if bound and bound != angle["candidate_id"]:
        raise CoverageLedgerError(
            "coverage_candidate_binding_superseded",
            "This angle is bound to a Hunt candidate. Keep candidate_id "
            f"{bound} or cite new same-Hunt evidence actions to change its state",
            status_code=409,
            details={"candidate_id": bound},
        )


def _public_row(row: Mapping[str, Any]) -> dict[str, Any]:
    item = dict(row)
    result = {
        "id": str(item.get("id") or ""),
        "sequence": int(item["event_seq"]) if item.get("event_seq") is not None else None,
        "fingerprint": str(item.get("fingerprint") or ""),
        "family": str(item.get("family") or ""),
        "locus": _json_value(item.get("locus_json")) or {},
        "mechanism": str(item.get("mechanism") or ""),
        "principal_context": _json_value(item.get("principal_context")) or {},
        "hypothesis": str(item.get("hypothesis") or ""),
        "status": str(item.get("status") or ""),
        "evidence_action_ids": [
            str(value) for value in (_json_value(item.get("evidence_action_ids")) or [])
        ],
        "contradictory_evidence_action_ids": [
            str(value) for value in (
                _json_value(item.get("contradictory_evidence_action_ids")) or []
            )
        ],
        "candidate_id": str(item["candidate_id"]) if item.get("candidate_id") else None,
        "candidate_status": (
            str(item["candidate_status"]) if item.get("candidate_status") else None
        ),
        "blocker": item.get("blocker"),
        "proof_gap": item.get("proof_gap"),
        "created_at": (
            item["created_at"].isoformat()
            if hasattr(item.get("created_at"), "isoformat")
            else item.get("created_at")
        ),
        "authoritative": False,
    }
    if "total_count" in item:
        result["total_count"] = int(item.get("total_count") or 0)
    return result


async def record_coverage_angle(
    conn: Any,
    *,
    hunt_run_id: str,
    values: Mapping[str, Any],
    run_status: str = "active",
) -> dict[str, Any]:
    """Append one immutable angle event after binding evidence to this Hunt.

    The caller holds the Hunt row lock, so every check below and the sequence assigned
    at insert are serialized with every other write to this Hunt.
    """
    angle = normalize_coverage_angle(values)
    if run_status == "budget_exhausted" and not angle["evidence_action_ids"]:
        raise CoverageLedgerError(
            "coverage_budget_exhausted_requires_evidence",
            "Hunt is budget_exhausted; until it resumes, coverage must cite the same-Hunt "
            "actions that settle the angle",
            status_code=409,
        )
    recorded = int(await conn.fetchval(
        "SELECT COUNT(*) FROM hunt_coverage_angle_events WHERE hunt_run_id=$1::uuid",
        hunt_run_id,
    ) or 0)
    if recorded >= MAX_COVERAGE_EVENTS_PER_HUNT:
        raise CoverageLedgerError(
            "coverage_event_limit_reached",
            f"This Hunt already has {MAX_COVERAGE_EVENTS_PER_HUNT} coverage events; record "
            "the remaining gaps in the final debrief",
            status_code=409,
            details={"max_events_per_hunt": MAX_COVERAGE_EVENTS_PER_HUNT},
        )
    all_refs = list(dict.fromkeys(
        list(angle["evidence_action_ids"])
        + list(angle["contradictory_evidence_action_ids"])
    ))
    evidence = await owned_action_evidence(
        conn, hunt_run_id=hunt_run_id, action_ids=all_refs,
    )
    validate_evidence_claim(angle, evidence)
    await _require_owned_candidate(
        conn, hunt_run_id=hunt_run_id, candidate_id=angle["candidate_id"],
    )
    await _require_candidate_binding_preserved(
        conn, hunt_run_id=hunt_run_id, angle=angle,
    )
    row = await conn.fetchrow(
        """INSERT INTO hunt_coverage_angle_events (
               hunt_run_id, fingerprint, family, locus_json, mechanism,
               principal_context, hypothesis, status, evidence_action_ids,
               contradictory_evidence_action_ids, candidate_id, blocker, proof_gap
           ) VALUES (
               $1::uuid,$2,$3,$4::jsonb,$5,$6::jsonb,$7,$8,$9::jsonb,
               $10::jsonb,$11::uuid,$12,$13
           )
           RETURNING *""",
        hunt_run_id,
        angle["fingerprint"],
        angle["family"],
        json.dumps(angle["locus"], separators=(",", ":")),
        angle["mechanism"],
        json.dumps(angle["principal_context"], separators=(",", ":")),
        angle["hypothesis"],
        angle["status"],
        json.dumps(angle["evidence_action_ids"]),
        json.dumps(angle["contradictory_evidence_action_ids"]),
        angle["candidate_id"],
        angle["blocker"],
        angle["proof_gap"],
    )
    return {
        "schema_version": COVERAGE_LEDGER_SCHEMA,
        "angle": _public_row(row),
    }


_LATEST_ANGLES_CTE = """WITH latest AS (
               SELECT DISTINCT ON (fingerprint) *
               FROM hunt_coverage_angle_events
               WHERE hunt_run_id=$1::uuid
               ORDER BY fingerprint, event_seq DESC
           )"""


async def list_coverage_angles(
    conn: Any,
    *,
    hunt_run_id: str,
    status: str | None = None,
    family: str | None = None,
    limit: int = MAX_CHECKPOINT_ANGLES,
) -> dict[str, Any]:
    """Return only the newest event for each exact coverage fingerprint."""
    normalized_status = str(status or "").strip().lower() or None
    if normalized_status and normalized_status not in COVERAGE_ANGLE_STATUSES:
        raise CoverageLedgerError("coverage_status_invalid", "Unsupported coverage status")
    normalized_family = str(family or "").strip().lower()[:80] or None
    bounded_limit = max(1, min(int(limit), 500))
    rows = await conn.fetch(
        _LATEST_ANGLES_CTE + """
           SELECT latest.*, c.status AS candidate_status,
                  COUNT(*) OVER() AS total_count
           FROM latest
           LEFT JOIN investigation_candidates c ON c.id=latest.candidate_id
           WHERE ($2::text IS NULL OR latest.status=$2)
             AND ($3::text IS NULL OR latest.family=$3)
           ORDER BY latest.event_seq DESC
           LIMIT $4""",
        hunt_run_id,
        normalized_status,
        normalized_family,
        bounded_limit,
    )
    angles = [_public_row(row) for row in rows]
    total = int(angles[0].pop("total_count", 0)) if angles else 0
    for angle in angles:
        angle.pop("total_count", None)
    return {
        "schema_version": COVERAGE_LEDGER_SCHEMA,
        "angles": angles,
        "count": len(angles),
        "total": total,
        "limit": bounded_limit,
        "truncated": total > len(angles),
    }


async def coverage_history(
    conn: Any, *, hunt_run_id: str, limit: int,
) -> dict[str, Any]:
    """Return every event in sequence order, marking the ones a later event superseded."""
    bounded_limit = max(1, int(limit))
    rows = await conn.fetch(
        """SELECT e.*, c.status AS candidate_status,
                  LEAD(e.id) OVER (
                      PARTITION BY e.fingerprint ORDER BY e.event_seq
                  ) AS superseded_by_event_id,
                  COUNT(*) OVER() AS total_count
           FROM hunt_coverage_angle_events e
           LEFT JOIN investigation_candidates c ON c.id=e.candidate_id
           WHERE e.hunt_run_id=$1::uuid
           ORDER BY e.event_seq ASC
           LIMIT $2""",
        hunt_run_id,
        bounded_limit,
    )
    events = []
    for row in rows:
        event = _public_row(row)
        event.pop("total_count", None)
        superseded_by = dict(row).get("superseded_by_event_id")
        event["superseded"] = superseded_by is not None
        event["superseded_by_event_id"] = str(superseded_by) if superseded_by else None
        events.append(event)
    total = int(dict(rows[0]).get("total_count") or 0) if rows else 0
    return {
        "schema_version": COVERAGE_HISTORY_SCHEMA,
        "events": events,
        "event_count": len(events),
        "event_total": total,
        "event_limit": bounded_limit,
        "events_truncated": total > len(events),
        "current_state_rule": (
            "Each fingerprint's current state is its highest-sequence event; earlier "
            "events stay listed with superseded=true."
        ),
        "advisory_only": True,
    }


_CONTINUATION_SQL = _LATEST_ANGLES_CTE + """,
           open_angles AS (
               SELECT latest.*, c.status AS candidate_status
               FROM latest
               LEFT JOIN investigation_candidates c ON c.id=latest.candidate_id
               WHERE latest.status <> 'negative'
                 AND NOT (
                     latest.status='candidate'
                     AND COALESCE(c.status, '') IN ('verified','refuted','expired')
                 )
           )
           SELECT open_angles.*, COUNT(*) OVER() AS continuation_total
           FROM open_angles
           ORDER BY CASE status
                        WHEN 'candidate' THEN 0 WHEN 'partial' THEN 1
                        WHEN 'testing' THEN 2 WHEN 'planned' THEN 3
                        WHEN 'blocked' THEN 4 ELSE 99 END,
                    family, fingerprint
           LIMIT $2"""


async def build_hunt_checkpoint(
    conn: Any, *, run: Mapping[str, Any],
) -> dict[str, Any]:
    """Build a bounded server-derived handoff for resume or context compaction."""
    hunt_run_id = str(run["id"])
    coverage = await list_coverage_angles(
        conn, hunt_run_id=hunt_run_id, limit=MAX_CHECKPOINT_ANGLES,
    )
    # The queue is selected and counted in SQL over every open angle, not derived from
    # the newest-first angle window, so older open work cannot fall off unreported.
    continuation_rows = await conn.fetch(
        _CONTINUATION_SQL, hunt_run_id, MAX_CHECKPOINT_CONTINUATION,
    )
    candidate_rows = await conn.fetch(
        """SELECT c.id, c.family, c.title, c.status, c.claimed_severity,
                  c.fingerprint, c.canonical_locus, c.verifier_contract_id,
                  c.last_seen_at, COUNT(*) OVER() AS total_count
           FROM investigation_candidates c
           WHERE EXISTS (
               SELECT 1 FROM investigation_candidate_observations o
               WHERE o.candidate_id=c.id AND o.hunt_run_id=$1::uuid
           )
           ORDER BY c.last_seen_at DESC, c.id DESC
           LIMIT $2""",
        hunt_run_id,
        MAX_CHECKPOINT_CANDIDATES,
    )
    action_rows = await conn.fetch(
        """SELECT status, COUNT(*) AS count
           FROM hunt_actions
           WHERE hunt_run_id=$1::uuid
           GROUP BY status
           ORDER BY status""",
        hunt_run_id,
    )

    coverage_status_rows = await conn.fetch(
        """WITH latest AS (
               SELECT DISTINCT ON (fingerprint) fingerprint, status
               FROM hunt_coverage_angle_events
               WHERE hunt_run_id=$1::uuid
               ORDER BY fingerprint, event_seq DESC
           )
           SELECT status, COUNT(*) AS count
           FROM latest
           GROUP BY status
           ORDER BY status""",
        hunt_run_id,
    )
    coverage_family_rows = await conn.fetch(
        """WITH latest AS (
               SELECT DISTINCT ON (fingerprint) fingerprint, family
               FROM hunt_coverage_angle_events
               WHERE hunt_run_id=$1::uuid
               ORDER BY fingerprint, event_seq DESC
           )
           SELECT family, COUNT(*) AS count
           FROM latest
           GROUP BY family
           ORDER BY family""",
        hunt_run_id,
    )

    candidates = [
        {
            "id": str(row["id"]),
            "family": str(row["family"] or ""),
            "title": str(row["title"] or ""),
            "status": str(row["status"] or ""),
            "severity": str(row["claimed_severity"] or "info"),
            "fingerprint": str(row["fingerprint"] or ""),
            "canonical_locus": _json_value(row["canonical_locus"]) or {},
            "verifier_contract_id": row["verifier_contract_id"],
            "last_seen_at": (
                row["last_seen_at"].isoformat()
                if hasattr(row.get("last_seen_at"), "isoformat")
                else row.get("last_seen_at")
            ),
        }
        for row in candidate_rows
    ]
    candidate_total = int(candidate_rows[0]["total_count"]) if candidate_rows else 0
    review_queue = [
        {
            "candidate_id": item["id"],
            "family": item["family"],
            "status": item["status"],
            "severity": item["severity"],
            "fingerprint": item["fingerprint"],
            "canonical_locus": item["canonical_locus"],
            "verifier_contract_id": item["verifier_contract_id"],
            "challenge": [
                "attacker_prerequisite",
                "alternative_explanation",
                "impact_ceiling",
                "duplicate_identity",
                "smallest_falsifying_action",
            ],
        }
        for item in candidates
        if item["status"] not in {
            "verified", "refuted", "expired", "verification_queued", "verifying",
        }
    ]

    latest_angles = coverage["angles"]
    status_counts = {
        str(row["status"]): int(row["count"]) for row in coverage_status_rows
    }
    family_counts = {
        str(row["family"]): int(row["count"]) for row in coverage_family_rows
    }
    continuation = []
    for row in continuation_rows:
        item = _public_row(row)
        continuation.append({
            key: item[key] for key in (
                "fingerprint", "family", "locus", "mechanism", "status", "candidate_id",
                "candidate_status", "blocker", "proof_gap", "evidence_action_ids",
            )
        })
    continuation_total = (
        int(dict(continuation_rows[0]).get("continuation_total") or 0)
        if continuation_rows else 0
    )

    return {
        "schema_version": HUNT_CHECKPOINT_SCHEMA,
        "hunt_id": hunt_run_id,
        "run_status": str(run.get("status") or ""),
        "target_kind": str(run.get("target_kind") or ""),
        "objective": str(run.get("objective") or ""),
        "budget": _json_value(run.get("budget_json")) or {},
        "budget_used": _json_value(run.get("budget_used_json")) or {},
        "coverage": {
            "status_counts": dict(sorted(status_counts.items())),
            "family_counts": dict(sorted(family_counts.items())),
            "angle_count": int(coverage["total"]),
            "angles_truncated": bool(coverage["truncated"]),
            "latest_angles": latest_angles,
        },
        "continuation_queue": continuation,
        "continuation_count": len(continuation),
        "continuation_total": continuation_total,
        "continuation_truncated": continuation_total > len(continuation),
        "candidates": candidates,
        "candidate_count": candidate_total,
        "candidates_truncated": candidate_total > len(candidates),
        "review_queue": review_queue,
        "action_outcomes": {
            str(row["status"]): int(row["count"]) for row in action_rows
        },
        "advisory_only": True,
        "proof_boundary": (
            "Coverage and candidates organize investigation. Only registered deterministic "
            "verification may create a verified finding."
        ),
    }


# init.sql carries the same definition for fresh databases. These statements are
# idempotent and also upgrade the table created by the first release of this ledger:
# they add the ordering sequence (numbering existing rows in their previous order), give
# the status check its canonical name, and replace the timestamp-ordered indexes.
COVERAGE_LEDGER_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS hunt_coverage_angle_events (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        hunt_run_id UUID NOT NULL REFERENCES hunt_runs(id) ON DELETE CASCADE,
        fingerprint TEXT NOT NULL,
        family TEXT NOT NULL,
        locus_json JSONB NOT NULL DEFAULT '{}'::jsonb,
        mechanism TEXT NOT NULL DEFAULT '',
        principal_context JSONB NOT NULL DEFAULT '{}'::jsonb,
        hypothesis TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL,
        evidence_action_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
        contradictory_evidence_action_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
        candidate_id UUID,
        blocker TEXT,
        proof_gap TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        event_seq BIGSERIAL,
        CONSTRAINT hunt_coverage_angle_status_check CHECK (
            status IN ('planned','testing','negative','partial','blocked','candidate')
        )
    )
    """,
    """
    DO $coverage$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM pg_attribute
            WHERE attrelid='hunt_coverage_angle_events'::regclass
              AND attname='event_seq' AND NOT attisdropped
        ) THEN
            ALTER TABLE hunt_coverage_angle_events ADD COLUMN event_seq BIGSERIAL;
            UPDATE hunt_coverage_angle_events e
            SET event_seq=ordered.position
            FROM (
                SELECT id, row_number() OVER (ORDER BY created_at, id) AS position
                FROM hunt_coverage_angle_events
            ) ordered
            WHERE e.id=ordered.id;
            PERFORM setval(
                pg_get_serial_sequence('hunt_coverage_angle_events', 'event_seq'),
                GREATEST((SELECT COUNT(*) FROM hunt_coverage_angle_events), 1),
                (SELECT COUNT(*) > 0 FROM hunt_coverage_angle_events)
            );
        END IF;
    END
    $coverage$
    """,
    """
    DO $coverage$
    BEGIN
        IF EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conrelid='hunt_coverage_angle_events'::regclass
              AND conname='hunt_coverage_angle_events_status_check'
        ) AND NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conrelid='hunt_coverage_angle_events'::regclass
              AND conname='hunt_coverage_angle_status_check'
        ) THEN
            ALTER TABLE hunt_coverage_angle_events
            RENAME CONSTRAINT hunt_coverage_angle_events_status_check
            TO hunt_coverage_angle_status_check;
        END IF;
    END
    $coverage$
    """,
    "DROP INDEX IF EXISTS idx_hunt_coverage_angle_events_run",
    "DROP INDEX IF EXISTS idx_hunt_coverage_angle_events_fingerprint",
    """
    CREATE INDEX IF NOT EXISTS idx_hunt_coverage_angle_events_run_seq
    ON hunt_coverage_angle_events(hunt_run_id, event_seq DESC)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_hunt_coverage_angle_events_fingerprint_seq
    ON hunt_coverage_angle_events(hunt_run_id, fingerprint, event_seq DESC)
    """,
)


__all__ = [
    "COVERAGE_ANGLE_STATUSES",
    "COVERAGE_HISTORY_SCHEMA",
    "COVERAGE_LEDGER_SCHEMA",
    "COVERAGE_LEDGER_SCHEMA_STATEMENTS",
    "COVERAGE_LOCUS_KEYS",
    "COVERAGE_WRITABLE_RUN_STATUSES",
    "CoverageLedgerError",
    "HUNT_CHECKPOINT_SCHEMA",
    "MAX_COVERAGE_EVENTS_PER_HUNT",
    "TERMINAL_ACTION_STATUSES",
    "build_hunt_checkpoint",
    "canonical_coverage_locus",
    "coverage_fingerprint",
    "coverage_history",
    "list_coverage_angles",
    "normalize_coverage_angle",
    "record_coverage_angle",
]
