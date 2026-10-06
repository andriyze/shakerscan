"""Evidence-backed Hunt coverage angles and compact continuation checkpoints.

The external planner may describe what it intends to test, but ShakerScan owns the
ledger and only accepts settled coverage claims when they cite terminal actions from
the same Hunt.  Coverage is deliberately finer grained than a vulnerability family:
method, route/object/sink, mechanism, principal context, and application state can all
make one angle materially different from another.

This is investigation state, not proof.  A coverage event can point at a candidate,
but neither a planner-written angle nor a checkpoint may create or verify a finding.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
from typing import Any
from uuid import UUID

COVERAGE_LEDGER_SCHEMA = "hunt-coverage-ledger/v1"
HUNT_CHECKPOINT_SCHEMA = "hunt-checkpoint/v1"

COVERAGE_ANGLE_STATUSES = frozenset({
    "planned",
    "testing",
    "negative",
    "partial",
    "blocked",
    "candidate",
})
TERMINAL_ACTION_STATUSES = frozenset({"completed", "partial", "blocked"})
MAX_EVIDENCE_ACTIONS = 50
MAX_CHECKPOINT_ANGLES = 200
MAX_CHECKPOINT_CANDIDATES = 100
MAX_JSON_BYTES = 16_384

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

_LOCUS_KEYS = (
    "method",
    "route",
    "url",
    "parameter",
    "object_id",
    "transport",
    "port",
    "service_name",
    "operation_id",
    "capability_id",
    "scheme",
    "collection_id",
    "request_id",
    "sink",
    "input_path",
    "application_state",
    "variant",
)


class CoverageLedgerError(ValueError):
    """A coverage event is structurally invalid or overclaims its evidence."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _text(value: Any, *, maximum: int, required: bool = False) -> str:
    result = str(value or "").strip()
    if required and not result:
        raise CoverageLedgerError("coverage_field_required", "Required coverage field is empty")
    return result[:maximum]


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
    return json.loads(encoded)


def canonical_coverage_locus(value: Any) -> dict[str, Any]:
    """Return the bounded dimensions that identify one concrete test angle."""
    source = value if isinstance(value, Mapping) else {}
    result: dict[str, Any] = {}
    for key in _LOCUS_KEYS:
        item = source.get(key)
        if item in (None, "", [], {}):
            continue
        if key == "port":
            try:
                port = int(item)
            except (TypeError, ValueError):
                continue
            if 1 <= port <= 65535:
                result[key] = port
            continue
        text = str(item).strip()
        if key == "method":
            text = text.upper()
        result[key] = text[:1000]
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
        if len(result) >= MAX_EVIDENCE_ACTIONS:
            break
    return result


def coverage_fingerprint(
    *,
    family: Any,
    locus: Any,
    mechanism: Any,
    principal_context: Any,
) -> str:
    material = {
        "family": _text(family, maximum=80, required=True).lower(),
        "locus": canonical_coverage_locus(locus),
        "mechanism": _text(mechanism, maximum=1000).lower(),
        "principal_context": _bounded_json_object(
            principal_context, field="principal_context",
        ),
    }
    if not material["locus"] and not material["mechanism"]:
        raise CoverageLedgerError(
            "coverage_angle_too_broad",
            "Coverage must name a concrete locus or mechanism; a family-level claim is too broad",
        )
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def normalize_coverage_angle(values: Mapping[str, Any]) -> dict[str, Any]:
    status = _text(values.get("status"), maximum=40, required=True).lower()
    if status not in COVERAGE_ANGLE_STATUSES:
        raise CoverageLedgerError(
            "coverage_status_invalid", f"Unsupported coverage status: {status}",
        )

    family = _text(values.get("family"), maximum=80, required=True).lower()
    locus = canonical_coverage_locus(values.get("locus"))
    mechanism = _text(values.get("mechanism"), maximum=1000)
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
    candidate_id = _text(values.get("candidate_id"), maximum=80)
    if candidate_id:
        try:
            candidate_id = str(UUID(candidate_id))
        except ValueError as exc:
            raise CoverageLedgerError(
                "coverage_candidate_id_invalid", "candidate_id must be a UUID",
            ) from exc

    blocker = _text(values.get("blocker"), maximum=2000)
    proof_gap = _text(values.get("proof_gap"), maximum=4000)
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
        "hypothesis": _text(values.get("hypothesis"), maximum=8000),
        "status": status,
        "evidence_action_ids": evidence,
        "contradictory_evidence_action_ids": contradictions,
        "candidate_id": candidate_id or None,
        "blocker": blocker or None,
        "proof_gap": proof_gap or None,
    }


async def _owned_action_statuses(
    conn: Any, *, hunt_run_id: str, action_ids: Sequence[str],
) -> dict[str, str]:
    if not action_ids:
        return {}
    rows = await conn.fetch(
        """SELECT id, status
           FROM hunt_actions
           WHERE hunt_run_id=$1::uuid AND id = ANY($2::uuid[])""",
        hunt_run_id,
        [UUID(item) for item in action_ids],
    )
    statuses = {str(row["id"]): str(row["status"]) for row in rows}
    missing = sorted(set(action_ids) - set(statuses))
    if missing:
        raise CoverageLedgerError(
            "coverage_evidence_not_owned",
            "Coverage evidence must be actions from this exact Hunt",
        )
    nonterminal = {
        action_id: status for action_id, status in statuses.items()
        if status not in TERMINAL_ACTION_STATUSES
    }
    if nonterminal:
        raise CoverageLedgerError(
            "coverage_evidence_not_terminal",
            "Coverage evidence must be a completed, partial, or blocked Hunt action",
        )
    return statuses


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


def _validate_evidence_claim(
    angle: Mapping[str, Any], action_statuses: Mapping[str, str],
) -> None:
    status = str(angle["status"])
    evidence_ids = list(angle.get("evidence_action_ids") or [])
    evidence_statuses = [action_statuses.get(item) for item in evidence_ids]
    if status == "negative" and any(item != "completed" for item in evidence_statuses):
        raise CoverageLedgerError(
            "coverage_negative_requires_completed_actions",
            "Negative coverage may cite only completed actions; partial/blocked work is a gap",
        )
    if status == "candidate" and any(item == "blocked" for item in evidence_statuses):
        raise CoverageLedgerError(
            "coverage_candidate_requires_executed_evidence",
            "Candidate coverage cannot be based only on a blocked action",
        )


def _public_row(row: Mapping[str, Any]) -> dict[str, Any]:
    item = dict(row)
    result = {
        "id": str(item.get("id") or ""),
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
    conn: Any, *, hunt_run_id: str, values: Mapping[str, Any],
) -> dict[str, Any]:
    """Append one immutable angle event after binding evidence to this Hunt."""
    angle = normalize_coverage_angle(values)
    all_refs = list(dict.fromkeys(
        list(angle["evidence_action_ids"])
        + list(angle["contradictory_evidence_action_ids"])
    ))
    statuses = await _owned_action_statuses(
        conn, hunt_run_id=hunt_run_id, action_ids=all_refs,
    )
    _validate_evidence_claim(angle, statuses)
    await _require_owned_candidate(
        conn, hunt_run_id=hunt_run_id, candidate_id=angle["candidate_id"],
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
        """WITH latest AS (
               SELECT DISTINCT ON (fingerprint) *
               FROM hunt_coverage_angle_events
               WHERE hunt_run_id=$1::uuid
               ORDER BY fingerprint, created_at DESC, id DESC
           )
           SELECT latest.*, COUNT(*) OVER() AS total_count
           FROM latest
           WHERE ($2::text IS NULL OR status=$2)
             AND ($3::text IS NULL OR family=$3)
           ORDER BY created_at DESC, id DESC
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
        "truncated": total > len(angles),
    }


async def build_hunt_checkpoint(
    conn: Any, *, run: Mapping[str, Any],
) -> dict[str, Any]:
    """Build a bounded server-derived handoff for resume or context compaction."""
    hunt_run_id = str(run["id"])
    coverage = await list_coverage_angles(
        conn, hunt_run_id=hunt_run_id, limit=MAX_CHECKPOINT_ANGLES,
    )
    candidate_rows = await conn.fetch(
        """SELECT c.id, c.family, c.title, c.status, c.claimed_severity,
                  c.verifier_contract_id, c.last_seen_at, COUNT(*) OVER() AS total_count
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
               ORDER BY fingerprint, created_at DESC, id DESC
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
               ORDER BY fingerprint, created_at DESC, id DESC
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

    latest_angles = coverage["angles"]
    status_counts = {
        str(row["status"]): int(row["count"]) for row in coverage_status_rows
    }
    family_counts = {
        str(row["family"]): int(row["count"]) for row in coverage_family_rows
    }

    priority = {"candidate": 0, "partial": 1, "testing": 2, "planned": 3, "blocked": 4}
    continuation = sorted(
        (
            {
                "fingerprint": item["fingerprint"],
                "family": item["family"],
                "locus": item["locus"],
                "mechanism": item["mechanism"],
                "status": item["status"],
                "candidate_id": item["candidate_id"],
                "blocker": item["blocker"],
                "proof_gap": item["proof_gap"],
                "evidence_action_ids": item["evidence_action_ids"],
            }
            for item in latest_angles
            if item["status"] != "negative"
        ),
        key=lambda item: (
            priority.get(str(item["status"]), 99),
            str(item["family"]),
            str(item["fingerprint"]),
        ),
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
        "candidates": candidates,
        "candidate_count": candidate_total,
        "candidates_truncated": candidate_total > len(candidates),
        "action_outcomes": {
            str(row["status"]): int(row["count"]) for row in action_rows
        },
        "advisory_only": True,
        "proof_boundary": (
            "Coverage and candidates organize investigation. Only registered deterministic "
            "verification may create a verified finding."
        ),
    }


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
        CONSTRAINT hunt_coverage_angle_status_check CHECK (
            status IN ('planned','testing','negative','partial','blocked','candidate')
        )
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_hunt_coverage_angle_events_run
    ON hunt_coverage_angle_events(hunt_run_id, created_at DESC, id DESC)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_hunt_coverage_angle_events_fingerprint
    ON hunt_coverage_angle_events(hunt_run_id, fingerprint, created_at DESC, id DESC)
    """,
)


__all__ = [
    "COVERAGE_ANGLE_STATUSES",
    "COVERAGE_LEDGER_SCHEMA",
    "COVERAGE_LEDGER_SCHEMA_STATEMENTS",
    "CoverageLedgerError",
    "HUNT_CHECKPOINT_SCHEMA",
    "build_hunt_checkpoint",
    "canonical_coverage_locus",
    "coverage_fingerprint",
    "list_coverage_angles",
    "normalize_coverage_angle",
    "record_coverage_angle",
]
