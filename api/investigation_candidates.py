"""Durable, non-authoritative hunt candidates shared by web and device planes.

Candidates are observations awaiting a registered server-side verifier. They never carry promotion
authority and are intentionally separate from finding proof state.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


PLANES = frozenset({"web", "device"})
STATUSES = frozenset({
    "new", "verification_queued", "verifying", "verified", "refuted",
    "inconclusive", "blocked", "expired",
})
TERMINAL_STATUSES = frozenset({"verified", "refuted", "expired"})
IN_FLIGHT_STATUSES = frozenset({"verification_queued", "verifying"})
SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})

DEVICE_VERIFIER_CONTRACTS: dict[str, str] = {
    "device_service_exposure": "device.service_exposure",
    "device_tls": "device.tls",
    "device_auth_bypass": "device.auth_bypass",
    "device_control_authorization": "device.control_authorization",
    "device_firmware_advisory": "device.firmware_advisory",
    "device_ssh_posture": "device.ssh_posture",
}


class CandidateLifecycleError(ValueError):
    """A Hunt attempted an invalid candidate lifecycle transition."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return dict(decoded) if isinstance(decoded, dict) else {}
    return {}


def _json_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return list(value)
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            return []
        return list(decoded) if isinstance(decoded, list) else []
    return []


def canonical_family(value: Any) -> str:
    normalized = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "idor": "bola",
        "sql_injection": "sqli",
        "cross_site_scripting": "xss",
        "information_disclosure": "data_exposure",
        "service_exposure": "device_service_exposure",
        "tls": "device_tls",
        "firmware_advisory": "device_firmware_advisory",
        "ssh_posture": "device_ssh_posture",
        "control_authorization": "device_control_authorization",
    }
    return aliases.get(normalized, normalized)[:80] or "unknown"


def canonical_locus(value: Any) -> dict[str, Any]:
    source = value if isinstance(value, dict) else {}
    allowed = (
        "method", "route", "url", "parameter", "object_id", "transport", "port",
        "service_name", "operation_id", "capability_id", "scheme",
        "collection_id", "request_id", "advisory_id", "cpe", "version",
        "host_key_fingerprint",
    )
    result: dict[str, Any] = {}
    for key in allowed:
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


def candidate_fingerprint(
    *, plane: str, target_ref: str, family: Any, locus: Any,
) -> str:
    normalized_plane = str(plane or "").strip().lower()
    if normalized_plane not in PLANES:
        raise ValueError(f"unsupported candidate plane:{normalized_plane or 'empty'}")
    material = {
        "plane": normalized_plane,
        "target_ref": str(target_ref),
        "family": canonical_family(family),
        "locus": canonical_locus(locus),
    }
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def normalize_candidate(
    *,
    plane: str,
    target_id: str | None = None,
    device_target_id: str | None = None,
    research_episode_id: str | None = None,
    agent_hunt_run_id: str | None = None,
    device_agent_run_id: str | None = None,
    hunt_run_id: str | None = None,
    family: Any,
    locus: Any,
    title: Any,
    claim: Any,
    severity: Any = "info",
    evidence_refs: Any = None,
    verifier_contract_id: Any = None,
    source_kind: Any = None,
) -> dict[str, Any]:
    normalized_plane = str(plane or "").strip().lower()
    if normalized_plane not in PLANES:
        raise ValueError(f"unsupported candidate plane:{normalized_plane or 'empty'}")
    if normalized_plane == "web" and (not target_id or device_target_id):
        raise ValueError("web candidates require target_id only")
    if normalized_plane == "device" and (not device_target_id or target_id):
        raise ValueError("device candidates require device_target_id only")
    target_ref = str(target_id or device_target_id)
    normalized_severity = str(severity or "info").strip().lower()
    if normalized_severity not in SEVERITIES:
        normalized_severity = "info"
    refs = list(dict.fromkeys(
        str(item).strip()[:120]
        for item in (evidence_refs or [])
        if str(item).strip()
    ))[:100]
    normalized_locus = canonical_locus(locus)
    normalized_family = canonical_family(family)
    if normalized_plane == "device":
        normalized_family = {
            "auth_bypass": "device_auth_bypass",
        }.get(normalized_family, normalized_family)
    normalized_verifier = (
        DEVICE_VERIFIER_CONTRACTS.get(normalized_family)
        if normalized_plane == "device"
        else (str(verifier_contract_id).strip()[:160] if verifier_contract_id else None)
    )
    return {
        "plane": normalized_plane,
        "target_id": str(target_id) if target_id else None,
        "device_target_id": str(device_target_id) if device_target_id else None,
        "research_episode_id": str(research_episode_id) if research_episode_id else None,
        "agent_hunt_run_id": str(agent_hunt_run_id) if agent_hunt_run_id else None,
        "device_agent_run_id": str(device_agent_run_id) if device_agent_run_id else None,
        "hunt_run_id": str(hunt_run_id) if hunt_run_id else None,
        "family": normalized_family,
        "canonical_locus": normalized_locus,
        "title": str(title or "Investigation candidate").strip()[:300],
        "claim": str(claim or title or "Investigation candidate").strip()[:8000],
        "claimed_severity": normalized_severity,
        "evidence_refs": refs,
        "verifier_contract_id": normalized_verifier,
        "source_kind": str(source_kind or "hunt").strip()[:80],
        "fingerprint": candidate_fingerprint(
            plane=normalized_plane,
            target_ref=target_ref,
            family=normalized_family,
            locus=normalized_locus,
        ),
    }


async def upsert_candidate(
    conn: Any,
    candidate: dict[str, Any],
    *,
    created_by: str,
    observation_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Insert/refresh a candidate and append one immutable, run-bound observation.

    Verified/refuted/expired candidate assertions are immutable. A later hunt may update only
    ``last_seen_at`` on the canonical row while its distinct claim and provenance remain in the
    observation ledger.
    """
    row = await conn.fetchrow(
        """INSERT INTO investigation_candidates (
               plane, target_id, device_target_id, research_episode_id, agent_hunt_run_id,
               device_agent_run_id, hunt_run_id,
               family, canonical_locus, title, claim, claimed_severity, evidence_refs,
               verifier_contract_id, source_kind, fingerprint, status, created_by
           ) VALUES (
               $1,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6::uuid,$7::uuid,$8,$9::jsonb,$10,$11,$12,$13::jsonb,
               $14,$15,$16,'new',$17
           )
           ON CONFLICT (fingerprint) DO UPDATE SET
               title=CASE WHEN investigation_candidates.status IN ('verified','refuted','expired')
                          THEN investigation_candidates.title ELSE EXCLUDED.title END,
               claim=CASE WHEN investigation_candidates.status IN ('verified','refuted','expired')
                          THEN investigation_candidates.claim ELSE EXCLUDED.claim END,
               claimed_severity=CASE WHEN investigation_candidates.status IN ('verified','refuted','expired')
                          THEN investigation_candidates.claimed_severity ELSE EXCLUDED.claimed_severity END,
               evidence_refs=CASE WHEN investigation_candidates.status IN ('verified','refuted','expired')
                          THEN investigation_candidates.evidence_refs ELSE EXCLUDED.evidence_refs END,
               verifier_contract_id=CASE WHEN investigation_candidates.status IN ('verified','refuted','expired')
                          THEN investigation_candidates.verifier_contract_id
                          ELSE COALESCE(EXCLUDED.verifier_contract_id, investigation_candidates.verifier_contract_id) END,
               last_seen_at=NOW(),
               updated_at=NOW()
           RETURNING id, status, fingerprint, created_at, updated_at, (xmax = 0) AS inserted""",
        candidate["plane"], candidate.get("target_id"), candidate.get("device_target_id"),
        candidate.get("research_episode_id"), candidate.get("agent_hunt_run_id"),
        candidate.get("device_agent_run_id"), candidate.get("hunt_run_id"), candidate["family"],
        json.dumps(candidate["canonical_locus"]), candidate["title"], candidate["claim"],
        candidate["claimed_severity"], json.dumps(candidate["evidence_refs"]),
        candidate.get("verifier_contract_id"), candidate.get("source_kind"), candidate["fingerprint"],
        str(created_by or "hunt")[:120],
    )
    await conn.execute(
        """INSERT INTO investigation_candidate_observations (
               candidate_id, research_episode_id, agent_hunt_run_id, device_agent_run_id, hunt_run_id,
               source_kind, title, claim, claimed_severity, evidence_refs,
               verifier_contract_id, observation_context, created_by
           ) VALUES (
               $1,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6,$7,$8,$9,$10::jsonb,$11,$12::jsonb,$13
           )""",
        row["id"], candidate.get("research_episode_id"), candidate.get("agent_hunt_run_id"),
        candidate.get("device_agent_run_id"), candidate.get("hunt_run_id"), candidate.get("source_kind"), candidate["title"],
        candidate["claim"], candidate["claimed_severity"], json.dumps(candidate["evidence_refs"]),
        candidate.get("verifier_contract_id"), json.dumps(observation_context or {}),
        str(created_by or "hunt")[:120],
    )
    return {
        "id": str(row["id"]),
        "status": str(row["status"]),
        "fingerprint": str(row["fingerprint"]),
        "inserted": bool(row.get("inserted", False)),
        "authoritative": False,
    }


async def _hunt_owned_candidate(
    conn: Any, *, hunt_run_id: str, candidate_id: str,
) -> dict[str, Any]:
    """Lock one candidate that this exact Hunt produced or observed."""
    row = await conn.fetchrow(
        """SELECT c.* FROM investigation_candidates c
           WHERE c.id=$1::uuid
             AND EXISTS (
                 SELECT 1 FROM investigation_candidate_observations o
                 WHERE o.candidate_id=c.id AND o.hunt_run_id=$2::uuid
             )
           FOR UPDATE""",
        candidate_id,
        hunt_run_id,
    )
    if row is None:
        raise CandidateLifecycleError(
            "candidate_not_owned",
            "Candidate was not produced or observed by this Hunt",
        )
    return dict(row)


def _require_candidate_mutable(row: dict[str, Any]) -> None:
    status = str(row.get("status") or "")
    if status in TERMINAL_STATUSES:
        raise CandidateLifecycleError(
            "candidate_terminal",
            f"Candidate is {status}; its proof history is immutable",
        )
    if status in IN_FLIGHT_STATUSES:
        raise CandidateLifecycleError(
            "candidate_verification_in_flight",
            f"Candidate is {status}; wait for verification to settle before changing it",
        )


async def _append_hunt_lifecycle_observation(
    conn: Any,
    *,
    row: dict[str, Any],
    hunt_run_id: str,
    created_by: str,
    event: str,
    changed_fields: list[str],
) -> None:
    """Preserve an immutable before/after audit point for Hunt metadata edits."""
    await conn.execute(
        """INSERT INTO investigation_candidate_observations (
               candidate_id, hunt_run_id, source_kind, title, claim,
               claimed_severity, evidence_refs, verifier_contract_id,
               observation_context, created_by
           ) VALUES ($1,$2::uuid,$3,$4,$5,$6,$7::jsonb,$8,$9::jsonb,$10)""",
        row["id"],
        hunt_run_id,
        str(row.get("source_kind") or "hunt_v2")[:80],
        str(row.get("title") or "Investigation candidate")[:300],
        str(row.get("claim") or row.get("title") or "Investigation candidate")[:8000],
        str(row.get("claimed_severity") or "info"),
        json.dumps(_json_list(row.get("evidence_refs"))),
        row.get("verifier_contract_id"),
        json.dumps({
            "event": event,
            "changed_fields": sorted(set(changed_fields)),
            "authoritative": False,
            "verification_state_mutated": False,
        }),
        str(created_by or "hunt")[:120],
    )


async def update_candidate_for_hunt(
    conn: Any,
    *,
    hunt_run_id: str,
    candidate_id: str,
    changes: dict[str, Any],
    created_by: str,
) -> dict[str, Any]:
    """Update only non-authoritative metadata on a candidate owned by one Hunt.

    Family, locus, fingerprint, proof state, and verification identifiers are deliberately
    absent from ``changes``. Changing identity creates a new candidate; deterministic
    verification remains the only promotion path.
    """
    allowed = {
        "title", "claim", "severity", "evidence_refs", "verifier_contract_id",
    }
    unknown = sorted(set(changes) - allowed)
    if unknown:
        raise CandidateLifecycleError(
            "candidate_update_field_forbidden",
            f"Candidate update cannot change: {', '.join(unknown)}",
        )
    if not changes:
        raise CandidateLifecycleError(
            "candidate_update_empty", "Candidate update must change at least one field",
        )
    current = await _hunt_owned_candidate(
        conn, hunt_run_id=hunt_run_id, candidate_id=candidate_id,
    )
    _require_candidate_mutable(current)
    normalized = normalize_candidate(
        plane=str(current["plane"]),
        target_id=str(current["target_id"]) if current.get("target_id") else None,
        device_target_id=(
            str(current["device_target_id"])
            if current.get("device_target_id") else None
        ),
        hunt_run_id=hunt_run_id,
        family=current["family"],
        locus=_json_object(current.get("canonical_locus")),
        title=changes.get("title", current["title"]),
        claim=changes.get("claim", current["claim"]),
        severity=changes.get("severity", current["claimed_severity"]),
        evidence_refs=changes.get(
            "evidence_refs", _json_list(current.get("evidence_refs")),
        ),
        verifier_contract_id=(
            changes.get("verifier_contract_id")
            if "verifier_contract_id" in changes
            else current.get("verifier_contract_id")
        ),
        source_kind=current.get("source_kind") or "hunt_v2",
    )
    if not normalized["evidence_refs"]:
        raise CandidateLifecycleError(
            "candidate_evidence_required",
            "A Hunt candidate must retain at least one evidence reference",
        )
    updated = await conn.fetchrow(
        """UPDATE investigation_candidates
           SET title=$2, claim=$3, claimed_severity=$4, evidence_refs=$5::jsonb,
               verifier_contract_id=$6,
               status=CASE WHEN status IN ('inconclusive','blocked') THEN 'new' ELSE status END,
               latest_verification_id=CASE
                   WHEN status IN ('inconclusive','blocked') THEN NULL
                   ELSE latest_verification_id END,
               last_seen_at=NOW(), updated_at=NOW()
           WHERE id=$1
           RETURNING *""",
        current["id"],
        normalized["title"],
        normalized["claim"],
        normalized["claimed_severity"],
        json.dumps(normalized["evidence_refs"]),
        normalized.get("verifier_contract_id"),
    )
    updated_row = dict(updated)
    await _append_hunt_lifecycle_observation(
        conn,
        row=updated_row,
        hunt_run_id=hunt_run_id,
        created_by=created_by,
        event="candidate.updated",
        changed_fields=list(changes),
    )
    return {
        "id": str(updated_row["id"]),
        "status": str(updated_row["status"]),
        "updated_fields": sorted(changes),
        "authoritative": False,
        "verified": False,
    }


async def expire_candidate_for_hunt(
    conn: Any,
    *,
    hunt_run_id: str,
    candidate_id: str,
    created_by: str,
) -> dict[str, Any]:
    """Remove a Hunt candidate from active use while retaining its audit ledger."""
    current = await _hunt_owned_candidate(
        conn, hunt_run_id=hunt_run_id, candidate_id=candidate_id,
    )
    if str(current.get("status") or "") == "expired":
        return {
            "id": str(current["id"]),
            "status": "deleted",
            "candidate_status": "expired",
            "recoverable_audit_record": True,
            "idempotent_replay": True,
            "authoritative": False,
            "verified": False,
        }
    _require_candidate_mutable(current)
    expired = await conn.fetchrow(
        """UPDATE investigation_candidates
           SET status='expired', updated_at=NOW()
           WHERE id=$1
           RETURNING *""",
        current["id"],
    )
    expired_row = dict(expired)
    await _append_hunt_lifecycle_observation(
        conn,
        row=expired_row,
        hunt_run_id=hunt_run_id,
        created_by=created_by,
        event="candidate.deleted",
        changed_fields=["status"],
    )
    return {
        "id": str(expired_row["id"]),
        "status": "deleted",
        "candidate_status": "expired",
        "recoverable_audit_record": True,
        "authoritative": False,
        "verified": False,
    }
