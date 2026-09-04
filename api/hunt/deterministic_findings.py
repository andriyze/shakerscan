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

try:
    from findings import template_path, templated_finding_identity
except ModuleNotFoundError:
    from scanner.findings import template_path, templated_finding_identity

try:
    from scanner_tools.url_redaction import redact_client_route
    from scanner_tools.xss_evidence import apply_xss_execution_evidence
except ModuleNotFoundError:
    from scanner.scanner_tools.url_redaction import redact_client_route
    from scanner.scanner_tools.xss_evidence import apply_xss_execution_evidence


def _origin(value: urllib.parse.SplitResult) -> tuple[str, str | None, int | None]:
    scheme = value.scheme.lower()
    default_port = 443 if scheme == "https" else 80 if scheme == "http" else None
    return scheme, value.hostname, value.port or default_port


def _verified_xss_fingerprint(proof: Mapping[str, Any], *, method: str) -> str:
    """Use Scan's canonical endpoint identity, extended for client-side routes."""
    normalized_method = str(method or "GET").strip().upper()
    if not normalized_method.isalpha() or not 3 <= len(normalized_method) <= 12:
        normalized_method = "GET"
    client_route = str(proof.get("client_route") or "")
    if client_route:
        parsed_route = urllib.parse.urlsplit(client_route.lstrip("!"))
        parameters = {
            str(name).strip()
            for name, _value in urllib.parse.parse_qsl(
                parsed_route.query, keep_blank_values=True,
            )
            if str(name).strip()
        }
        if proof.get("param"):
            parameters.add(str(proof["param"]))
        identity = (
            f"CWE-79|{normalized_method}|"
            f"{template_path(str(proof.get('path') or '/'))}#"
            f"{template_path(parsed_route.path or '/')}|"
            f"{','.join(sorted(parameters))}"
        )
    else:
        identity = templated_finding_identity({
            "cwe": "CWE-79",
            "tool": "dalfox",
            "url": proof.get("url"),
            "evidence": {
                "method": normalized_method,
                "param": proof.get("param"),
            },
        })
        if not identity:
            raise ValueError("verified XSS proof has no canonical endpoint identity")
    return "t:" + hashlib.sha256(identity.encode()).hexdigest()[:16]


def verified_xss_observations(
    observations: Any, *, target_url: str,
) -> list[dict[str, Any]]:
    """Return bounded, content-free XSS proof records on the bound origin."""
    try:
        target = urllib.parse.urlsplit(target_url)
        target_origin = _origin(target)
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
            observed_origin = _origin(observed)
        except ValueError:
            continue
        if observed_origin != target_origin:
            continue
        parameter = str(raw.get("param") or "").strip()[:200] or None
        # Store the vulnerable operation, never Dalfox's proof payload.
        query = urllib.parse.urlencode([(parameter, "")]) if parameter else ""
        client_route = redact_client_route(raw.get("client_route"))
        public_url = urllib.parse.urlunsplit((
            observed.scheme, observed.netloc, observed.path or "/", query,
            client_route or "",
        ))
        proof = {
            "url": public_url,
            "path": observed.path or "/",
            "param": parameter,
            "payload_sha256": str(raw["payload_sha256"])[:64],
            "alert_type": str(raw.get("alert_type") or "")[:40] or None,
        }
        if client_route:
            proof["client_route"] = client_route
        accepted.append(proof)
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
    capability_input: Mapping[str, Any],
    observations: Any,
) -> list[str]:
    """Persist proof-bearing capability output without trusting planner fields."""
    if capability_name != "xss.verify":
        return []
    findings: list[str] = []
    method = str(capability_input.get("method") or "GET").strip().upper()
    if not method.isalpha() or not 3 <= len(method) <= 12:
        method = "GET"
    for proof in verified_xss_observations(observations, target_url=target_url):
        fingerprint = _verified_xss_fingerprint(proof, method=method)
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
            "method": method,
            **proof,
        }
        apply_xss_execution_evidence(
            {"evidence": evidence},
            location="client_route" if proof.get("client_route") else "request_parameter",
            parameter=proof.get("param"), signal="browser_or_alert_execution", verifier=capability_name,
        )
        finding_id = await conn.fetchval(
            """INSERT INTO findings (
                   target_id, hunt_run_id, fingerprint, title, description,
                   severity, cvss_score, tool, cwe, url, evidence, source, status,
                   last_verification_status, last_verification_verdict,
                   last_verification_confidence, last_verified_at, verification_count
               ) VALUES (
                   $1,$2,$3,'Verified cross-site scripting',
                   'Dalfox observed deterministic browser or alert execution on the bound target.',
                   'high',NULL,'dalfox','CWE-79',$4,$5::jsonb,'deep_hunt','active',
                   'still_vulnerable','exploited',1.0,NOW(),1
               ) ON CONFLICT (target_id, fingerprint) WHERE target_id IS NOT NULL
               DO UPDATE SET
                   hunt_run_id=EXCLUDED.hunt_run_id, status='active', resolved_at=NULL,
                   last_seen_at=NOW(), url=EXCLUDED.url,
                   evidence=EXCLUDED.evidence || CASE
                       WHEN findings.evidence ? 'cvss'
                       THEN jsonb_build_object('cvss', findings.evidence->'cvss')
                       ELSE '{}'::jsonb END,
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
