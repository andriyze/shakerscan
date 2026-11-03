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

from .finding_verifications import record_hunt_verification
from .service_identity import _origin, service_identity_suffix

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


def _verified_xss_fingerprint(
    proof: Mapping[str, Any], *, method: str, target_url: str,
) -> str:
    """Use Scan's canonical endpoint identity, extended for client-side routes."""
    normalized_method = str(method or "GET").strip().upper()
    if not normalized_method.isalpha() or not 3 <= len(normalized_method) <= 12:
        normalized_method = "GET"
    identity = templated_finding_identity({
        "cwe": "CWE-79", "tool": "dalfox", "url": proof.get("url"),
        "evidence": {"method": normalized_method, "param": proof.get("param"),
                     "client_route": proof.get("client_route")},
    })
    if not identity:
        raise ValueError("verified XSS proof has no canonical endpoint identity")
    return "t:" + hashlib.sha256(identity.encode()).hexdigest()[:16]


def verified_xss_observations(
    observations: Any, *, target_url: str,
    allowed_origins: tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    """Return bounded, content-free XSS proof records on admitted service origins."""
    try:
        target = urllib.parse.urlsplit(target_url)
        target_origin = _origin(target)
    except ValueError:
        return []
    admitted = {target_origin} if target_origin[0] in {"http", "https"} else set()
    for value in allowed_origins:
        try:
            origin = _origin(urllib.parse.urlsplit(value))
        except ValueError:
            continue
        if origin[0] in {"http", "https"} and origin[1]:
            admitted.add(origin)
    accepted: list[dict[str, Any]] = []
    for raw in observations if isinstance(observations, (list, tuple)) else ():
        if not isinstance(raw, Mapping) or raw.get("proof_state") != "verified":
            continue
        kind = str(raw.get("kind") or "")
        if kind == "xss_alert":
            # Dalfox: a verified PoC with the injected URL and its payload receipt.
            observed_url = raw.get("url")
            parameter = str(raw.get("param") or "").strip()[:200] or None
            raw_client_route = raw.get("client_route")
            producer = "dalfox"
        elif kind == "xss_browser_proof":
            # The pinned browser prover: the marker executed in the DOM or reached the
            # console on the payload URL it built, which it publishes with the payload
            # already stripped (`request_url`) and names the parameter it injected.
            observed_url = raw.get("request_url")
            parameter = str(raw.get("parameter_name") or "").strip()[:200] or None
            raw_client_route = urllib.parse.urlsplit(str(observed_url or "")).fragment
            producer = "browser"
        else:
            continue
        if not observed_url or not raw.get("payload_sha256"):
            continue
        try:
            observed = urllib.parse.urlsplit(str(observed_url))
            observed_origin = _origin(observed)
        except ValueError:
            continue
        if observed_origin not in admitted:
            continue
        # Store the vulnerable operation, never the proof payload.
        query = urllib.parse.urlencode([(parameter, "")]) if parameter else ""
        client_route = redact_client_route(raw_client_route)
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
        if producer == "browser":
            proof["proof_producer"] = "browser"
            proof["dom_marker_executed"] = bool(raw.get("dom_marker_executed"))
            technique = str(raw.get("technique") or "")[:40] or None
            if technique:
                proof["technique"] = technique
        accepted.append(proof)
        if len(accepted) >= 20:
            break
    return accepted


def _xss_finding_records(
    hunt_id: uuid.UUID, action_id: uuid.UUID, target_url: str,
    capability_name: str, receipt_id: uuid.UUID,
    capability_input: Mapping[str, Any], observations: Any,
    *, allowed_origins: tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    method = str(capability_input.get("method") or "GET").strip().upper()
    if not method.isalpha() or not 3 <= len(method) <= 12:
        method = "GET"
    for proof in verified_xss_observations(
        observations, target_url=target_url, allowed_origins=allowed_origins,
    ):
        fingerprint = _verified_xss_fingerprint(
            proof, method=method, target_url=target_url,
        )
        browser_proof = proof.get("proof_producer") == "browser"
        proof_contract = (
            "xss_browser_proof/v1" if browser_proof
            else "dalfox_browser_or_alert_execution/v1"
        )
        tool = "playwright" if browser_proof else "dalfox"
        description = (
            "The pinned browser executed the injected payload on the bound target's "
            "client route and observed the deterministic DOM marker."
            if browser_proof else
            "Dalfox observed deterministic browser or alert execution on the bound target."
        )
        verdict_reason = (
            "Canonical browser DOM execution proof" if browser_proof
            else "Canonical Dalfox execution proof"
        )
        evidence = {
            "schema_version": "hunt-deterministic-finding/v1",
            "authoritative": True,
            "proof_state": "verified",
            "finding_verdict": "verified",
            "canonical_capability": capability_name,
            "proof_contract": proof_contract,
            "hunt_id": str(hunt_id),
            "source_action_id": str(action_id),
            "tool_receipt_id": str(receipt_id),
            "method": method,
            **proof,
        }
        apply_xss_execution_evidence(
            {"evidence": evidence},
            location="client_route" if proof.get("client_route") else "request_parameter",
            parameter=proof.get("param"),
            signal="dom_execution" if browser_proof else "browser_or_alert_execution",
            verifier=capability_name,
            dom_marker_executed=proof.get("dom_marker_executed") if browser_proof else None,
        )
        records.append({
            "fingerprint": fingerprint, "url": proof["url"], "evidence": evidence,
            "title": "Verified cross-site scripting", "description": description,
            "tool": tool, "cwe": "CWE-79", "finding_type": "xss",
            "verdict_reason": verdict_reason, "contract_id": proof_contract.split("/", 1)[0],
        })
    return records


def _sqli_finding_records(
    hunt_id: uuid.UUID, action_id: uuid.UUID, target_url: str,
    capability_name: str, receipt_id: uuid.UUID, observations: Any,
    *, allowed_origins: tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    """Verified findings from the Scan's deterministic SQLi proof, under the Scan's standard.

    sqlmap's own "is vulnerable" line stays a candidate (``scan/finalizer.py``); only a
    ``sqli_proof`` that holds its contract over two repetitions becomes a finding.
    """
    try:
        admitted = {_origin(urllib.parse.urlsplit(value)) for value in (target_url, *allowed_origins)}
    except ValueError:
        return []
    records: list[dict[str, Any]] = []
    for raw in observations if isinstance(observations, (list, tuple)) else ():
        if not (
            isinstance(raw, Mapping) and raw.get("kind") == "sqli_proof"
            and raw.get("proof_state") == "verified" and raw.get("finding_verdict") == "verified"
            and str(raw.get("proof_contract") or "").startswith("sqli_")
            and int(raw.get("repetitions") or 0) >= 2 and raw.get("field_path")
        ):
            continue
        try:
            origin = urllib.parse.urlsplit(str(raw.get("origin") or ""))
            if _origin(origin) not in admitted:
                continue
        except ValueError:
            continue
        path = str(raw.get("canonical_path") or "/")
        method = str(raw.get("method") or "GET").upper()
        field = str(raw["field_path"])[:200]
        url = urllib.parse.urlunsplit((origin.scheme, origin.netloc, path, "", ""))
        identity = templated_finding_identity({
            "cwe": "CWE-89", "tool": "shakerscan_sqli_proof", "url": url,
            "evidence": {"method": method, "param": field},
        })
        if not identity:
            continue
        auth_bypass = raw.get("proof_contract") == "sqli_authentication_bypass/v1"
        proof_contract = str(raw["proof_contract"])
        evidence = {
            "schema_version": "hunt-deterministic-finding/v1",
            "authoritative": True, "proof_state": "verified", "finding_verdict": "verified",
            "canonical_capability": capability_name, "proof_contract": proof_contract,
            "hunt_id": str(hunt_id), "source_action_id": str(action_id),
            "tool_receipt_id": str(receipt_id), "origin": _origin_text(origin),
            "url": url, "path": path, "method": method, "param": field, "field_path": field,
            **{key: raw.get(key) for key in (
                "request_class", "technique", "repetitions", "response_pairs",
                "database_error_signatures", "redacted_excerpt", "payload_shape", "timing_ms",
                "session_state_discarded",
            ) if raw.get(key) is not None},
            "proof_producer": "shakerscan", "evidence_type": "deterministic_differential",
        }
        records.append({
            "fingerprint": "t:" + hashlib.sha256(identity.encode()).hexdigest()[:16],
            "url": url, "evidence": evidence,
            "title": ("Verified SQL injection authentication bypass" if auth_bypass
                      else "Verified SQL injection"),
            "description": (
                "A repeated payload/control differential on the bound target proved that the "
                f"{field} input reaches a SQL query."
            ),
            "tool": "shakerscan_sqli_proof", "cwe": "CWE-89", "finding_type": "sqli",
            "verdict_reason": "Repeated deterministic SQL injection differential satisfied",
            "contract_id": proof_contract.split("/", 1)[0],
            "severity": "critical",
        })
    return records


def _origin_text(parts: urllib.parse.SplitResult) -> str:
    return f"{parts.scheme.lower()}://{parts.netloc.rpartition('@')[2].lower()}"


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
    *, target_kind: str = "web", capability_receipt: Any = None,
    allowed_origins: tuple[str, ...] = (), evidence_principals: tuple[str, ...] = (),
) -> list[str]:
    """Persist receipt-backed verifier outputs through one finding/verification path.

    Caller holds the Hunt row lock and settlement transaction. Action redelivery
    uses the settled result; it must not invoke materialization a second time.
    """
    if capability_name == "xss.verify":
        records = _xss_finding_records(hunt_id, action_id, target_url, capability_name,
                                      receipt_id, capability_input, observations,
                                      allowed_origins=allowed_origins)
    elif capability_name == "sqli.verify":
        records = _sqli_finding_records(hunt_id, action_id, target_url, capability_name,
                                        receipt_id, observations, allowed_origins=allowed_origins)
    elif capability_name == "authz.verify":
        from .authz_findings import authz_finding_records
        records = authz_finding_records(capability_receipt, hunt_id=hunt_id,
            action_id=action_id, target_id=target_id, receipt_id=receipt_id,
            allowed_origins=allowed_origins or (target_url,), target_url=target_url,
            target_kind=target_kind)
    else:
        return []
    target_column = "device_target_id" if target_kind == "device" else "target_id"
    target_table = "device_targets" if target_kind == "device" else "targets"
    findings: list[str] = []
    principals = sorted({str(slot) for slot in evidence_principals} - {"", "anonymous"})
    for record in records:
        evidence = record["evidence"]
        if principals:
            # The identity the proof ran as: a retest cannot send it, so it must not judge it.
            evidence["evidence_principals"] = principals
        try:
            from scan.finding_reconciliation import reconcile_legacy_finding_row
        except ModuleNotFoundError:
            from ..scan.finding_reconciliation import reconcile_legacy_finding_row
        await reconcile_legacy_finding_row(
            conn, target_uuid=target_id, fingerprint=record["fingerprint"],
            finding=record, target_kind=target_kind,
        )
        finding_id = await conn.fetchval(
            f"""INSERT INTO findings (
                   {target_column}, hunt_run_id, fingerprint, title, description,
                   severity, cvss_score, tool, cwe, url, evidence, source, status,
                   last_verification_status, last_verification_verdict,
                   last_verification_confidence, last_verified_at, verification_count
               ) VALUES (
                   $1,$2,$3,$8,
                   $6,
                   $10,NULL,$7,$9,$4,$5::jsonb,'deep_hunt','active',
                   'still_vulnerable','exploited',1.0,NOW(),1
               ) ON CONFLICT ({target_column}, fingerprint) WHERE {target_column} IS NOT NULL
               DO UPDATE SET
                   -- The first verifying Hunt keeps the finding (D21); a later Hunt's proof
                   -- is recorded in finding_hunt_verifications below instead.
                   hunt_run_id=COALESCE(findings.hunt_run_id, EXCLUDED.hunt_run_id),
                   status='active', resolved_at=NULL,
                   last_seen_at=NOW(), url=EXCLUDED.url,
                   evidence=EXCLUDED.evidence || CASE
                       WHEN findings.evidence ? 'cvss'
                       THEN jsonb_build_object('cvss', findings.evidence->'cvss')
                       ELSE '{{}}'::jsonb END,
                   last_verification_status='still_vulnerable',
                   last_verification_verdict='exploited',
                   last_verification_confidence=1.0, last_verified_at=NOW(),
                   verification_count=findings.verification_count + 1,
                   updated_at=NOW()
               RETURNING id""",
            target_id,
            hunt_id,
            record["fingerprint"],
            record["url"],
            json.dumps(evidence),
            record["description"],
            record["tool"],
            record["title"],
            record["cwe"],
            record.get("severity") or "high",
        )
        await record_hunt_verification(
            conn, finding_id=finding_id, hunt_id=hunt_id, action_id=action_id,
        )
        await conn.execute(
            f"""INSERT INTO finding_verifications (
                   finding_id, {target_column}, requested_by, status, result_status,
                   verdict, verdict_reason, finding_type, target_url, original_url,
                   proof, confidence, verification_mode, contract_id,
                   contract_version, proof_basis, started_at, completed_at, updated_at
               ) VALUES (
                   $1,$2,$3,'completed','success','exploited',
                   $6,$8,$4,$4,$5::jsonb,1.0,
                   'deterministic',$7,
                   'v1','tool_execution',NOW(),NOW(),NOW()
               )""",
            finding_id,
            target_id,
            f"hunt_v2:{hunt_id}"[:120],
            record["url"],
            json.dumps(evidence),
            record["verdict_reason"],
            record["contract_id"],
            record["finding_type"],
        )
        findings.append(str(finding_id))
    if findings:
        await conn.execute(
            f"""UPDATE {target_table} t SET active_findings_count=(
                   SELECT COUNT(*) FROM findings f
                   WHERE f.{target_column}=t.id AND f.status='active'
               ), updated_at=NOW() WHERE t.id=$1""",
            target_id,
        )
    return findings


__all__ = [
    "materialize_verified_hunt_findings", "service_identity_suffix", "verified_xss_observations",
]
