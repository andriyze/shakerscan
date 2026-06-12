"""
Shared Verification Engine - unified ladder executor for scan-time and post-scan paths.

Both the scan-time verification phase (verification_phase.py) and the
post-scan retest worker (api/worker.py) delegate prover dispatch through
this module so that:
  - The same attempt ladders from retest_contract drive both pipelines.
  - Prover functions are called identically regardless of entry point.
  - Downgrade logic is consistent.

Scan-time path:  verify_finding(..., skip_ai=True)  → no DB writes, no queue
Post-scan path:  verify_finding(..., skip_ai=False) → caller persists to DB
"""

from __future__ import annotations

import asyncio
import sys
from dataclasses import dataclass, field
from typing import Any


SEVERITY_ORDER: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

# Mirror of retest_contract.ATTEMPT_LADDERS so this module is self-contained
# (scanner container doesn't have access to api/retest_contract.py).
ATTEMPT_LADDERS: dict[str, list[str]] = {
    "xss": ["headless_dom_execution", "reflection_context", "alternate_payloads", "ai_reasoning"],
    "sqli": ["dbms_extraction", "boolean_diff", "timing_fallback", "ai_reasoning"],
    "ssrf": ["oob_callback", "internal_resource_access", "ai_reasoning"],
    "path_traversal": ["direct_traversal", "encoding_bypass", "ai_reasoning"],
    "open_redirect": ["query_redirect_param", "post_redirect_param", "location_header_check", "ai_reasoning"],
    "cors": ["origin_reflection_probe", "wildcard_credentials_probe", "ai_reasoning"],
    "2fa_bypass": ["otp_bruteforce_window", "ai_reasoning"],
    "command_injection": ["oob_callback", "time_delay_proof", "output_injection", "ai_reasoning"],
    "ssti": ["template_expression_proof", "error_based_detection", "ai_reasoning"],
    "xxe": ["oob_xxe", "file_read_xxe", "ai_reasoning"],
    "jwt": ["none_algorithm", "weak_secret_bruteforce", "signature_strip", "ai_reasoning"],
    "idor": ["cross_user_access", "sequential_id_probe", "ai_reasoning"],
    "bola": ["cross_user_access", "sequential_id_probe", "ai_reasoning"],
}

# Type alias mapping (subset of retest_contract.RETEST_TYPE_ALIASES)
TYPE_ALIASES: dict[str, str] = {
    "xss": "xss", "cross-site-scripting": "xss", "cross_site_scripting": "xss",
    "sqli": "sqli", "sql-injection": "sqli", "sql_injection": "sqli",
    "ssrf": "ssrf", "server-side-request-forgery": "ssrf", "server_side_request_forgery": "ssrf",
    "path_traversal": "path_traversal", "path-traversal": "path_traversal", "lfi": "path_traversal",
    "open_redirect": "open_redirect", "open-redirect": "open_redirect",
    "cors": "cors", "cors_misconfiguration": "cors",
    "2fa_bypass": "2fa_bypass", "2fa-bypass": "2fa_bypass", "mfa_bypass": "2fa_bypass",
    "command_injection": "command_injection", "command-injection": "command_injection",
    "os_command_injection": "command_injection", "rce": "command_injection",
    "ssti": "ssti", "server_side_template_injection": "ssti", "template_injection": "ssti",
    "xxe": "xxe", "xml_external_entity": "xxe",
    "jwt": "jwt", "jwt_weakness": "jwt", "jwt_vulnerability": "jwt",
    "idor": "idor", "bola": "bola",
    "insecure_direct_object_reference": "idor",
    "broken_object_level_authorization": "bola",
}


def normalize_finding_type(value: str | None) -> str | None:
    """Normalize a finding type string to its canonical form."""
    if not value:
        return None
    return TYPE_ALIASES.get(str(value).strip().lower())


def get_ladder(finding_type: str | None) -> list[str]:
    """Get the attempt ladder for a normalized finding type."""
    normalized = normalize_finding_type(finding_type)
    if not normalized:
        return []
    return list(ATTEMPT_LADDERS.get(normalized, []))


@dataclass
class VerificationResult:
    """Outcome of walking an attempt ladder for one finding."""
    proven: bool = False
    verdict: str = "inconclusive"
    confidence: float | None = None
    succeeded_step: str | None = None
    proof: Any | None = None          # ExploitProof or dict
    steps_tried: list[str] = field(default_factory=list)
    step_attempts: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    deterministic_exhausted: bool = False
    has_ai_step: bool = False

    def to_dict(self) -> dict[str, Any]:
        proof_dict = None
        if self.proof is not None:
            proof_dict = self.proof.to_dict() if hasattr(self.proof, "to_dict") else self.proof
        return {
            "proven": self.proven,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "succeeded_step": self.succeeded_step,
            "proof": proof_dict,
            "steps_tried": self.steps_tried,
            "step_attempts": self.step_attempts,
            "error": self.error,
            "deterministic_exhausted": self.deterministic_exhausted,
            "has_ai_step": self.has_ai_step,
        }


def dispatch_ladder_step(
    finding_type: str,
    step_name: str,
    url: str,
    param: str,
    payload: str | None,
    evidence: dict[str, Any] | None = None,
    *,
    prove_xss=None,
    prove_xss_headless=None,
    prove_sqli=None,
    prove_ssrf=None,
    prove_ssrf_oob=None,
    prove_path_traversal=None,
    prove_open_redirect=None,
    prove_cors=None,
    prove_command_injection=None,
    prove_ssti=None,
    prove_xxe=None,
    prove_jwt=None,
    prove_bola=None,
    prove_exposed_file=None,
) -> tuple[Any | None, dict[str, Any]]:
    """Map a ladder step name + finding type to a prover coroutine.

    Returns (coroutine_or_None, step_meta_dict).

    Callers must pass the prover functions they have available — this avoids
    hard import coupling so both scanner-side and worker-side can use this.
    """
    step_meta: dict[str, Any] = {"step": step_name}
    evidence = evidence or {}

    if finding_type == "xss":
        pl = payload or "<script>alert(1)</script>"
        if step_name == "headless_dom_execution" and prove_xss_headless:
            step_meta["payload"] = pl
            return prove_xss_headless(url, param, pl), step_meta
        if step_name == "reflection_context":
            pl = "<script>alert(1)</script>"
        elif step_name == "alternate_payloads":
            pl = "<svg onload=alert(1)>"
        step_meta["payload"] = pl
        if prove_xss:
            return prove_xss(url, param, "", pl), step_meta
        return None, step_meta

    if finding_type == "sqli":
        dbms_hint = evidence.get("dbms")
        if step_name == "boolean_diff":
            dbms_hint = None
        elif step_name == "timing_fallback":
            dbms_hint = "generic"
        step_meta["dbms_hint"] = dbms_hint or "auto"
        if prove_sqli:
            return prove_sqli(url, param, "", dbms_hint), step_meta
        return None, step_meta

    if finding_type == "ssrf":
        step_meta["strategy"] = step_name
        if step_name == "oob_callback" and prove_ssrf_oob:
            return prove_ssrf_oob(url, param, ""), step_meta
        if prove_ssrf:
            return prove_ssrf(url, param, ""), step_meta
        return None, step_meta

    if finding_type == "path_traversal":
        step_meta["strategy"] = step_name
        if prove_path_traversal:
            return prove_path_traversal(url, param, ""), step_meta
        return None, step_meta

    if finding_type == "open_redirect":
        step_meta["strategy"] = step_name
        if prove_open_redirect:
            return prove_open_redirect(url, param, ""), step_meta
        return None, step_meta

    if finding_type == "cors":
        step_meta["strategy"] = step_name
        if prove_cors:
            return prove_cors(url), step_meta
        return None, step_meta

    if finding_type == "command_injection":
        step_meta["strategy"] = step_name
        if prove_command_injection:
            return prove_command_injection(url, param, payload or "; id"), step_meta
        return None, step_meta

    if finding_type == "ssti":
        step_meta["strategy"] = step_name
        if prove_ssti:
            return prove_ssti(url, param, payload or "{{7*7}}"), step_meta
        return None, step_meta

    if finding_type == "xxe":
        step_meta["strategy"] = step_name
        if prove_xxe:
            return prove_xxe(url, param, payload or ""), step_meta
        return None, step_meta

    if finding_type == "jwt":
        step_meta["strategy"] = step_name
        if prove_jwt:
            return prove_jwt(url, param, payload or ""), step_meta
        return None, step_meta

    if finding_type in ("idor", "bola"):
        step_meta["strategy"] = step_name
        if prove_bola:
            return prove_bola(url, param, ""), step_meta
        return None, step_meta

    if finding_type == "exposed_file":
        step_meta["strategy"] = step_name
        if prove_exposed_file:
            return prove_exposed_file(url, evidence=evidence), step_meta
        return None, step_meta

    return None, step_meta


async def verify_finding(
    finding_type: str,
    ladder: list[str],
    url: str,
    param: str,
    payload: str | None,
    evidence: dict[str, Any] | None = None,
    skip_ai: bool = True,
    provers: dict[str, Any] | None = None,
) -> VerificationResult:
    """Walk the attempt ladder, return first proven result or exhaustion.

    Args:
        finding_type: Normalized type (xss, sqli, ssrf, etc.)
        ladder: Ordered list of step names from get_attempt_ladder()
        url: Target URL to test
        param: Parameter name to inject into
        payload: Initial payload (type-specific default if None)
        evidence: Finding evidence dict for context (e.g. dbms hint)
        skip_ai: If True, skip "ai_reasoning" steps (scan-time mode)
        provers: Dict of prover function references keyed by name
    """
    provers = provers or {}
    result = VerificationResult()
    result.has_ai_step = "ai_reasoning" in ladder
    effective_ladder = ladder if ladder else ["default"]

    for step in effective_ladder:
        if step == "ai_reasoning":
            if skip_ai:
                continue
            else:
                # AI step is handled externally by the caller (worker)
                continue

        result.steps_tried.append(step)
        try:
            coro, step_meta = dispatch_ladder_step(
                finding_type, step, url, param, payload,
                evidence=evidence,
                **provers,
            )
            if coro is None:
                result.error = f"No prover for step={step} type={finding_type}"
                result.step_attempts.append({"step": step, "error": result.error})
                break

            proof = await coro
            step_record = {
                "step": step,
                "meta": step_meta,
                "proven": bool(getattr(proof, "proven", False)) if proof else False,
                "confidence": getattr(proof, "confidence", None) if proof else None,
                "technique": getattr(proof, "technique", None) if proof else None,
            }
            result.step_attempts.append(step_record)

            if proof and getattr(proof, "proven", False):
                result.proven = True
                result.verdict = "exploited"
                result.confidence = getattr(proof, "confidence", None)
                result.succeeded_step = step
                result.proof = proof
                break
        except Exception as step_err:
            result.error = str(step_err)
            result.step_attempts.append({"step": step, "error": result.error})
            continue

    result.deterministic_exhausted = True
    if not result.proven:
        result.verdict = "inconclusive"
    return result


def downgrade_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Apply consistent severity downgrade for unverified findings.

    Used by both scan-time verification and display filters.
    """
    finding = dict(finding)
    severity = str(finding.get("severity") or "").lower()
    if severity == "critical":
        finding["severity"] = "high"
        finding["confidence"] = min(finding.get("confidence", 0.75), 0.75)
    elif severity == "high":
        finding["severity"] = "medium"
        finding["confidence"] = min(finding.get("confidence", 0.65), 0.65)
    evidence = finding.get("evidence", [])
    if isinstance(evidence, list):
        evidence.append("Verification failed or skipped - downgraded severity")
    finding["evidence"] = evidence
    finding["verification_attempted"] = True
    finding["verified"] = False
    return finding
