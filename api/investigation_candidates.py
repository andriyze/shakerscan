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
SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})


def canonical_family(value: Any) -> str:
    normalized = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "idor": "bola",
        "sql_injection": "sqli",
        "cross_site_scripting": "xss",
        "information_disclosure": "data_exposure",
    }
    return aliases.get(normalized, normalized)[:80] or "unknown"


def canonical_locus(value: Any) -> dict[str, Any]:
    source = value if isinstance(value, dict) else {}
    allowed = (
        "method", "route", "url", "parameter", "object_id", "transport", "port",
        "service_name", "operation_id", "capability_id",
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
    device_agent_run_id: str | None = None,
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
    return {
        "plane": normalized_plane,
        "target_id": str(target_id) if target_id else None,
        "device_target_id": str(device_target_id) if device_target_id else None,
        "research_episode_id": str(research_episode_id) if research_episode_id else None,
        "device_agent_run_id": str(device_agent_run_id) if device_agent_run_id else None,
        "family": normalized_family,
        "canonical_locus": normalized_locus,
        "title": str(title or "Investigation candidate").strip()[:300],
        "claim": str(claim or title or "Investigation candidate").strip()[:8000],
        "claimed_severity": normalized_severity,
        "evidence_refs": refs,
        "verifier_contract_id": (
            str(verifier_contract_id).strip()[:160] if verifier_contract_id else None
        ),
        "source_kind": str(source_kind or "hunt").strip()[:80],
        "fingerprint": candidate_fingerprint(
            plane=normalized_plane,
            target_ref=target_ref,
            family=normalized_family,
            locus=normalized_locus,
        ),
    }


async def upsert_candidate(conn: Any, candidate: dict[str, Any], *, created_by: str) -> dict[str, Any]:
    """Insert or refresh a candidate without granting it finding or proof authority."""
    row = await conn.fetchrow(
        """INSERT INTO investigation_candidates (
               plane, target_id, device_target_id, research_episode_id, device_agent_run_id,
               family, canonical_locus, title, claim, claimed_severity, evidence_refs,
               verifier_contract_id, source_kind, fingerprint, status, created_by
           ) VALUES (
               $1,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6,$7::jsonb,$8,$9,$10,$11::jsonb,
               $12,$13,$14,'new',$15
           )
           ON CONFLICT (fingerprint) DO UPDATE SET
               title=EXCLUDED.title,
               claim=EXCLUDED.claim,
               claimed_severity=EXCLUDED.claimed_severity,
               evidence_refs=EXCLUDED.evidence_refs,
               verifier_contract_id=COALESCE(EXCLUDED.verifier_contract_id, investigation_candidates.verifier_contract_id),
               last_seen_at=NOW(),
               updated_at=NOW()
           RETURNING id, status, fingerprint, created_at, updated_at""",
        candidate["plane"], candidate.get("target_id"), candidate.get("device_target_id"),
        candidate.get("research_episode_id"), candidate.get("device_agent_run_id"),
        candidate["family"], json.dumps(candidate["canonical_locus"]), candidate["title"],
        candidate["claim"], candidate["claimed_severity"], json.dumps(candidate["evidence_refs"]),
        candidate.get("verifier_contract_id"), candidate.get("source_kind"),
        candidate["fingerprint"], str(created_by or "hunt")[:120],
    )
    return {
        "id": str(row["id"]),
        "status": str(row["status"]),
        "fingerprint": str(row["fingerprint"]),
        "authoritative": False,
    }
