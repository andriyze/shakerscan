"""Promote a trusted-workflow proof to a finding that names the object its evidence proves.

A workflow proof replays the operation with objects it creates for itself (a second user's
basket, a fresh record for a mass-assignment check), so the concrete object in its evidence URL
is the replay's own. The finding used to take its title verbatim from the hypothesis, which was
written about whatever object the planner had seen: a finding could read "/objects/7" while its
evidence proved "/objects/51" (PR #340's "Not changed" note). ``proven_finding_title`` rewrites
the hypothesis title's mention of the route to the proven concrete path, or names the proven
operation when the title mentions none. A refreshed finding keeps its own title, re-pointed at
the object the new proof proved; it never takes the hypothesis title, which the hypothesis row
shares across Hunts and keeps from whichever Hunt wrote it first (D29).

Moved out of the api.py monolith, which was at its module-size ratchet; api.py keeps its old
names as aliases and the arsenal still reaches the promotion through its injected callables.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any
import urllib.parse
import uuid

try:
    from api_utils import _optional_uuid, _uuid_or_400
    from arsenal_routes.router import _finding_vulnerability_key
    from evidence_triage import redact_finding_evidence as _redact_finding_evidence
    import family_proof
    from serialization import _decode_json_value
except ModuleNotFoundError:  # package import in host-side tests
    from ..api_utils import _optional_uuid, _uuid_or_400
    from ..arsenal_routes.router import _finding_vulnerability_key
    from ..evidence_triage import redact_finding_evidence as _redact_finding_evidence
    from .. import family_proof
    from ..serialization import _decode_json_value

from .vulnerability_identity import (
    canonical_vulnerability_key,
    canonical_vulnerability_route,
    research_vulnerability_dimensions,
)

# A path or URL mentioned in a title: "/api/Users/7", "https://host/objects/7".
_TITLE_LOCATION = re.compile(r"(?:https?://[^\s/]+)?/[^\s,;()\"'<>]*")
_TITLE_LIMIT = 500


def proven_finding_title(
    title: Any, *, family: str, method: str, route: Any, concrete_path: str,
) -> str:
    """The finding title, describing the concrete object the evidence proves.

    Every path in ``title`` that addresses the proven route but another object is replaced by
    the proven concrete path. A title that then still does not name the proven path gets the
    proven operation appended, so title and evidence URL always agree.
    """
    text = " ".join(str(title or "").split()) or (
        f"Verified {str(family or 'workflow').replace('_', ' ')} invariant violation"
    )
    proven = str(concrete_path or route or "").strip()
    canonical = canonical_vulnerability_route(route) if route else None
    if not proven:
        return text[:_TITLE_LIMIT]

    def _swap(match: re.Match[str]) -> str:
        found = match.group(0)
        location = found.rstrip(".:!?")
        trailing = found[len(location):]
        path = urllib.parse.urlsplit(location).path if "://" in location else location
        if canonical and path != proven and canonical_vulnerability_route(path) == canonical:
            return proven + trailing
        return found

    rewritten = _TITLE_LOCATION.sub(_swap, text)
    if proven not in rewritten:
        operation = f"{method.upper()} {proven}" if method else proven
        suffix = f" ({operation})"
        rewritten = rewritten[: max(0, _TITLE_LIMIT - len(suffix))].rstrip() + suffix
    return rewritten[:_TITLE_LIMIT]


def trusted_workflow_proven_operation(
    execution: dict[str, Any], *, method: str, route: str,
) -> dict[str, Any]:
    """Return the concrete request whose operation satisfied the family proof."""
    for observation in execution.get("observations") or []:
        if not isinstance(observation, dict):
            continue
        request = observation.get("request") if isinstance(observation.get("request"), dict) else {}
        request_method = str(request.get("method") or "GET").upper()
        request_path = str(request.get("path") or request.get("url") or "").strip()
        if request_method == method and canonical_vulnerability_route(request_path) == route:
            return request
    return {}


async def research_promotion_provenance(conn: Any, hypothesis_id: uuid.UUID) -> dict[str, str | None]:
    row = await conn.fetchrow(
        """
        SELECT rd.id AS decision_id, rd.episode_id, re.campaign_id
        FROM research_decisions rd
        JOIN research_episodes re ON re.id=rd.episode_id
        WHERE rd.hypothesis_id=$1
          AND rd.action->>'command'='experiment.workflow'
        ORDER BY rd.created_at DESC
        LIMIT 1
        """,
        hypothesis_id,
    )
    if not row:
        return {"decision_id": None, "episode_id": None, "campaign_id": None}
    return {
        "decision_id": str(row.get("decision_id")) if row.get("decision_id") else None,
        "episode_id": str(row.get("episode_id")) if row.get("episode_id") else None,
        "campaign_id": str(row.get("campaign_id")) if row.get("campaign_id") else None,
    }


async def promote_trusted_workflow_finding(
    conn: Any,
    *,
    target_uuid: uuid.UUID,
    target_url: str,
    hypothesis_id: str,
    workflow_id: str,
    proof: dict[str, Any],
    first: dict[str, Any],
    replay: dict[str, Any],
    evidence_instance_id: str | None,
    tool_receipt_id: str | None,
) -> dict[str, Any] | None:
    promotable, _reason = family_proof.promotion_gate(proof)
    if not promotable or not hypothesis_id:
        return None
    hypothesis_row = await conn.fetchrow(
        "SELECT * FROM hypotheses WHERE id=$1 AND target_id=$2",
        _uuid_or_400(hypothesis_id, "hypothesis id"),
        target_uuid,
    )
    if not hypothesis_row:
        return None
    # Only the stored title, family, severity, description and metadata are read here.
    hypothesis = dict(hypothesis_row)
    hypothesis["metadata_json"] = _decode_json_value(hypothesis.get("metadata_json")) or {}
    family = str(proof.get("family") or "workflow")
    if family_proof.canonical_family(hypothesis.get("family")) != family_proof.canonical_family(family):
        return None
    hypothesis_metadata = (
        hypothesis.get("metadata_json") if isinstance(hypothesis.get("metadata_json"), dict) else {}
    )
    dedupe_dimensions = (
        hypothesis_metadata.get("dedupe_dimensions")
        if isinstance(hypothesis_metadata.get("dedupe_dimensions"), dict)
        else {}
    )
    # Bind promotion to routes that the stable family predicates themselves proved. Merely touching
    # a hypothesis route elsewhere in the workflow is not causal evidence for that route.
    proven_routes = {
        canonical_vulnerability_route(route) for route in (proof.get("proof_routes") or [])
    }
    proven_routes.discard(None)
    if len(proven_routes) != 1:
        return None
    hypothesis_route = canonical_vulnerability_route(
        dedupe_dimensions.get("route") or hypothesis_metadata.get("route")
    )
    if hypothesis_route and hypothesis_route not in proven_routes:
        return None
    hypothesis_method = str(dedupe_dimensions.get("method") or hypothesis_metadata.get("method") or "").upper()
    proof_methods = {str(method).upper() for method in (proof.get("proof_methods") or []) if str(method).strip()}
    if hypothesis_method and hypothesis_method not in proof_methods:
        return None
    proven_method = hypothesis_method or (next(iter(proof_methods)) if len(proof_methods) == 1 else "")
    finding_route = hypothesis_route or (sorted(proven_routes)[0] if proven_routes else None)
    vulnerability_dimensions = research_vulnerability_dimensions(
        hypothesis.get("family") or family,
        dedupe_dimensions,
        hypothesis_metadata,
        {"predicates": proof.get("stable_predicates") or []},
    )
    vulnerability_key = canonical_vulnerability_key(
        family=family,
        route=finding_route,
        method=proven_method or None,
        dimensions=vulnerability_dimensions,
    )
    if not vulnerability_key:
        return None
    # Suppress only the same operation. Include earlier autonomous promotions so the same
    # vulnerability is refreshed, rather than cloned once per planner hypothesis.
    candidate_vulnerability_keys = {vulnerability_key}
    known_rows = await conn.fetch(
        """
        SELECT id, status, tool, cwe, title, url, evidence, request
        FROM findings
        WHERE target_id=$1
          AND status IN ('active','resolved','accepted_risk')
        ORDER BY last_seen_at DESC
        LIMIT 2000
        """,
        target_uuid,
    )
    known_match = next(
        (
            row for row in known_rows
            if _finding_vulnerability_key(row) in candidate_vulnerability_keys
        ),
        None,
    )
    # A prior SUSPECTED autonomous-agent finding for this same vuln is exactly the thing being
    # UPGRADED to verified — it must not suppress its own promotion. This is DEDUP logic only; the
    # proof gate above (promotion_gate) is unchanged, so recognizing the upgrade cannot promote
    # anything unproven. A DAST/other-tool finding still suppresses (we don't re-clone what another
    # detector already owns). The superseded suspected row is resolved by the caller after promotion.
    _upgradeable_prior_tools = {"autonomous_workflow", "autonomous_agent"}
    if known_match and str(known_match.get("tool") or "") not in _upgradeable_prior_tools:
        proof["novelty_gate"] = "known_vulnerability_already_covered"
        proof["known_finding_id"] = str(known_match["id"])
        await conn.execute(
            """
            UPDATE hypotheses SET status='dead',
                terminal_reason='known_vulnerability_already_covered',
                version=version+1, updated_at=NOW()
            WHERE id=$1
            """,
            uuid.UUID(hypothesis_id),
        )
        return None
    fingerprint = hashlib.sha256(
        f"{target_uuid}:autonomous_workflow:{vulnerability_key}".encode()
    ).hexdigest()[:32]
    severity = str(hypothesis.get("severity_guess") or "high").lower()
    if severity not in {"critical", "high", "medium", "low", "info"}:
        severity = "high"
    proven_operation = trusted_workflow_proven_operation(
        first, method=proven_method, route=str(finding_route),
    )
    concrete_path = str(proven_operation.get("path") or finding_route or "/")
    # The title names the object this proof's own replay created and the evidence URL points
    # at, not the one the hypothesis was written about.
    title = proven_finding_title(
        hypothesis.get("title"), family=family, method=proven_method,
        route=finding_route, concrete_path=concrete_path,
    )
    finding_url = urllib.parse.urljoin(target_url.rstrip("/") + "/", concrete_path.lstrip("/"))
    raw_request_body = proven_operation.get("json_body") or proven_operation.get("form_body")
    request_body = (
        json.dumps(raw_request_body, sort_keys=True, separators=(",", ":"))
        if isinstance(raw_request_body, (dict, list))
        else str(raw_request_body or "")
    )
    retest_type = "bola" if family_proof.canonical_family(family) == "bola" else "generic_http"
    provenance = await research_promotion_provenance(conn, uuid.UUID(hypothesis_id))
    prior_evidence = _decode_json_value(known_match.get("evidence")) if known_match else {}
    prior_evidence = prior_evidence if isinstance(prior_evidence, dict) else {}
    provenance_history = [
        item for item in (prior_evidence.get("research_provenance_history") or [])
        if isinstance(item, dict)
    ]
    prior_provenance = prior_evidence.get("research_provenance")
    if isinstance(prior_provenance, dict):
        provenance_history.append(prior_provenance)
    provenance_history.append(provenance)
    unique_provenance: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in provenance_history:
        key = (
            str(item.get("campaign_id") or ""),
            str(item.get("episode_id") or ""),
            str(item.get("decision_id") or ""),
        )
        if any(key):
            unique_provenance[key] = item
    evidence = _redact_finding_evidence({
        "proof": "Independent live workflow replay satisfied the deterministic family-proof contract.",
        "type": retest_type,
        "retest_type": retest_type,
        "route": finding_route,
        "method": proven_method,
        "url": finding_url,
        "canonical_vulnerability_key": vulnerability_key,
        "canonical_vulnerability_key_version": "v3",
        "canonical_vulnerability_dimensions": vulnerability_dimensions,
        "dedupe_dimensions": dedupe_dimensions,
        "family_proof": proof,
        "autonomous_workflow": {
            "family": family,
            "route": finding_route,
            "method": proven_method,
            "url": finding_url,
            "request_body": request_body or None,
            "workflow_id": workflow_id,
            "hypothesis_id": hypothesis_id,
            "reproduction_count": 2,
            "first_assertions": first.get("assertion_results") or [],
            "replay_assertions": replay.get("assertion_results") or [],
            "restoration_verified": proof.get("restoration_verified"),
            "evidence_instance_id": evidence_instance_id,
            "tool_receipt_id": tool_receipt_id,
        },
        "research_provenance": provenance,
        "research_provenance_history": list(unique_provenance.values()),
    })
    existing = known_match if known_match else await conn.fetchrow(
        "SELECT id, status, title FROM findings WHERE target_id=$1 AND fingerprint=$2",
        target_uuid,
        fingerprint,
    )
    if existing:
        finding_id = existing["id"]
        # D29: the hypothesis row is shared per (target, family, route) and keeps the title of
        # whichever Hunt wrote it first, tags and masking included. A refresh therefore keeps the
        # finding's own title and only re-points it at the object this proof proved.
        title = proven_finding_title(
            existing.get("title") or title, family=family, method=proven_method,
            route=finding_route, concrete_path=concrete_path,
        )
        status = "resurfaced" if str(existing.get("status") or "") == "resolved" else "duplicate"
        await conn.execute(
            """
            UPDATE findings SET status='active', last_seen_at=NOW(),
                last_verification_status='still_vulnerable',
                last_verification_verdict='exploited',
                last_verification_confidence=1.0, last_verified_at=NOW(),
                fingerprint=$2, url=$3, source='autonomous', tool='autonomous_workflow',
                evidence=$4::jsonb, title=$5, updated_at=NOW()
            WHERE id=$1
            """,
            finding_id,
            fingerprint,
            finding_url,
            json.dumps(evidence),
            title,
        )
    else:
        finding_id = await conn.fetchval(
            """
            INSERT INTO findings (
                target_id, fingerprint, title, description, severity, cvss_score,
                tool, cwe, url, evidence, notes, source, status,
                last_verification_status, last_verification_verdict,
                last_verification_confidence, last_verified_at
            ) VALUES (
                $1,$2,$3,$4,$5,$6,'autonomous_workflow',$7,$8,$9::jsonb,
                $10,'autonomous','active','still_vulnerable','exploited',1.0,NOW()
            ) RETURNING id
            """,
            target_uuid,
            fingerprint,
            title,
            str(hypothesis.get("description") or "Verified by two independent live workflow executions with deterministic assertions and restoration checks."),
            severity,
            {"critical": 9.1, "high": 8.1, "medium": 5.3, "low": 3.1, "info": 0.0}[severity],
            proof.get("cwe"),
            finding_url,
            json.dumps(evidence),
            "Created only after trusted live replay passed family proof and promotion gates.",
        )
        status = "created"
    if evidence_instance_id and _optional_uuid(evidence_instance_id):
        await conn.execute(
            "UPDATE evidence_instances SET finding_id=$1, proof_state='verified' WHERE id=$2",
            finding_id,
            uuid.UUID(evidence_instance_id),
        )
    await conn.execute(
        """
        UPDATE hypotheses SET status='promoted',
            promoted_finding_ids=(SELECT COALESCE(jsonb_agg(DISTINCT value), '[]'::jsonb)
                FROM jsonb_array_elements_text(promoted_finding_ids || $2::jsonb) AS value),
            terminal_reason='trusted_workflow_family_proof', version=version+1, updated_at=NOW()
        WHERE id=$1
        """,
        uuid.UUID(hypothesis_id),
        json.dumps([str(finding_id)]),
    )
    return {"finding_id": str(finding_id), "fingerprint": fingerprint, "status": status}
