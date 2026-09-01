"""Materialize findings only from canonical Hunt proof observations.

Planner-created findings deliberately remain unverified.  This module is the
separate server-owned bridge for capability outputs whose parser contract
already carries deterministic execution proof.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping
import urllib.parse
import uuid


def verified_xss_observations(
    observations: Any, *, target_url: str,
) -> list[dict[str, Any]]:
    """Return bounded, content-free XSS proof records on the bound origin."""
    try:
        target = urllib.parse.urlsplit(target_url)
        target_origin = (target.scheme.lower(), target.hostname, target.port)
    except ValueError:
        return []
    accepted: list[dict[str, Any]] = []
    for raw in observations if isinstance(observations, (list, tuple)) else ():
        if (
            not isinstance(raw, Mapping)
            or raw.get("kind") != "xss_alert"
            or raw.get("proof_state") != "verified"
            or not raw.get("url")
            or not raw.get("payload_sha256")
        ):
            continue
        try:
            observed = urllib.parse.urlsplit(str(raw["url"]))
            observed_origin = (
                observed.scheme.lower(), observed.hostname, observed.port,
            )
        except ValueError:
            continue
        if observed_origin != target_origin:
            continue
        parameter = str(raw.get("param") or "").strip()[:200] or None
        # Store the vulnerable operation, never Dalfox's proof payload.
        query = urllib.parse.urlencode([(parameter, "")]) if parameter else ""
        public_url = urllib.parse.urlunsplit((
            observed.scheme, observed.netloc, observed.path or "/", query, "",
        ))
        accepted.append({
            "url": public_url,
            "path": observed.path or "/",
            "param": parameter,
            "payload_sha256": str(raw["payload_sha256"])[:64],
            "alert_type": str(raw.get("alert_type") or "")[:40] or None,
        })
        if len(accepted) >= 20:
            break
    return accepted


async def materialize_verified_hunt_findings(
    conn: Any,
    hunt_id: uuid.UUID,
    action_id: uuid.UUID,
    target_id: uuid.UUID,
    target_url: str,
    capability_name: str,
    receipt_id: uuid.UUID,
    observations: Any,
) -> list[str]:
    """Persist proof-bearing capability output without trusting planner fields."""
    if capability_name != "xss.verify":
        return []
    findings: list[str] = []
    for proof in verified_xss_observations(observations, target_url=target_url):
        identity = json.dumps({
            "family": "xss",
            "target_id": str(target_id),
            "path": proof["path"],
            "param": proof["param"],
        }, sort_keys=True, separators=(",", ":"))
        fingerprint = "t:" + hashlib.sha256(identity.encode()).hexdigest()[:16]
        evidence = {
            "schema_version": "hunt-deterministic-finding/v1",
            "authoritative": True,
            "proof_state": "verified",
            "finding_verdict": "verified",
            "canonical_capability": capability_name,
            "proof_contract": "dalfox_browser_or_alert_execution/v1",
            "hunt_id": str(hunt_id),
            "source_action_id": str(action_id),
            "tool_receipt_id": str(receipt_id),
            **proof,
        }
        finding_id = await conn.fetchval(
            """INSERT INTO findings (
                   target_id, hunt_run_id, fingerprint, title, description,
                   severity, cvss_score, tool, cwe, url, evidence, source, status,
                   last_verification_status, last_verification_verdict,
                   last_verification_confidence, last_verified_at, verification_count
               ) VALUES (
                   $1,$2,$3,'Verified cross-site scripting',
                   'Dalfox observed deterministic browser or alert execution on the bound target.',
                   'high',8.1,'dalfox','CWE-79',$4,$5::jsonb,'deep_hunt','active',
                   'still_vulnerable','exploited',1.0,NOW(),1
               ) ON CONFLICT (target_id, fingerprint) WHERE target_id IS NOT NULL
               DO UPDATE SET
                   hunt_run_id=EXCLUDED.hunt_run_id, status='active', resolved_at=NULL,
                   last_seen_at=NOW(), url=EXCLUDED.url, evidence=EXCLUDED.evidence,
                   last_verification_status='still_vulnerable',
                   last_verification_verdict='exploited',
                   last_verification_confidence=1.0, last_verified_at=NOW(),
                   verification_count=findings.verification_count + 1,
                   updated_at=NOW()
               RETURNING id""",
            target_id,
            hunt_id,
            fingerprint,
            proof["url"],
            json.dumps(evidence),
        )
        await conn.execute(
            """INSERT INTO finding_verifications (
                   finding_id, target_id, requested_by, status, result_status,
                   verdict, verdict_reason, finding_type, target_url, original_url,
                   proof, confidence, verification_mode, contract_id,
                   contract_version, proof_basis, started_at, completed_at, updated_at
               ) VALUES (
                   $1,$2,$3,'completed','success','exploited',
                   'Canonical Dalfox execution proof','xss',$4,$4,$5::jsonb,1.0,
                   'deterministic','dalfox_browser_or_alert_execution',
                   'v1','tool_execution',NOW(),NOW(),NOW()
               )""",
            finding_id,
            target_id,
            f"hunt_v2:{hunt_id}"[:120],
            proof["url"],
            json.dumps(evidence),
        )
        findings.append(str(finding_id))
    if findings:
        await conn.execute(
            """UPDATE targets t SET active_findings_count=(
                   SELECT COUNT(*) FROM findings f
                   WHERE f.target_id=t.id AND f.status='active'
               ), updated_at=NOW() WHERE t.id=$1""",
            target_id,
        )
    return findings


__all__ = ["materialize_verified_hunt_findings", "verified_xss_observations"]
