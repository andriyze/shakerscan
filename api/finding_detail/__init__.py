"""Per-class finding detail ("the brief"): what is wrong, where, the proof, why it matters, how sure
we are, how to reproduce, a fix for the observed stack, how to verify, and why this severity.

The brief is computed on read from the stored finding only (no network, no scanner call), so the
page stays fast and historical findings gain it without a migration. Classes without a specific
renderer get the generic brief: the stored description and visible scalar evidence.
"""

from __future__ import annotations

from typing import Any, Mapping

from . import exposure, http, injection, other, posture, tls
from .common import DETAIL_SCHEMA, record, text
from .severity import severity_section

_CONFIRMED_NOTES = {
    "tls": "Read directly from the TLS handshake with this server; nothing is inferred.",
    "header": "Read from the scan's recorded response of this origin.",
    "cookie": "Read from the Set-Cookie header of the scan's recorded response.",
    "exposure": "The response matched a content signature for this class; the scanner did not rely on the status code alone.",
    "cors": "Read from the CORS headers of the scan's recorded response to the probe Origin.",
    "redirect": "Read from the Location header of the scan's recorded response; the redirect was not followed.",
    "dns": "Read from the DNS answers the scan recorded.",
}


def _builder(finding: Mapping[str, Any], evidence: Mapping[str, Any]):
    tool = text(finding.get("tool"), 80)
    check = text(evidence.get("check"), 120)
    if finding.get("source") == "ai_gate" or finding.get("ai_target_id"):
        return other.build_ai
    if tool == "tls.inspect":
        return tls.build
    if check.startswith("missing_header_") or (evidence.get("template_id") == "http-missing-security-headers" and evidence.get("header_name")):
        return http.build_missing_header
    if check.startswith("session_cookie_missing_"):
        return http.build_cookie
    if check.startswith("weak_header_"):
        return http.build_weak_header
    if check.startswith("cors_"):
        return posture.build_cors
    if check == "open_redirect":
        return posture.build_open_redirect
    if tool == "dns.inspect" and check:
        return posture.build_dns
    if tool == "shakerscan_exposure_probe" and evidence.get("exposure_class"):
        return exposure.build
    if tool in {"shakerscan_sqli_proof", "sqlmap", "request_sqli_differential"}:
        return injection.build_sqli
    if tool == "shakerscan_nosqli_verify":
        return injection.build_nosqli
    if tool in {"dalfox", "shakerscan_browser_proof", "request_xss_differential"} or (
        str(finding.get("cwe") or "") == "CWE-79" and evidence.get("payload_sha256")
    ):
        return injection.build_xss
    if tool in {"smart_authz", "shakerscan_authz_surface"}:
        return injection.build_authz
    if tool == "shakerscan_graphql_probe":
        return other.build_graphql
    if tool == "subdomain_takeover":
        return other.build_takeover
    if tool == "nuclei" or evidence.get("template_id"):
        return other.build_template
    return other.build_generic


def _confidence(finding: Mapping[str, Any], evidence: Mapping[str, Any], family: str) -> dict[str, str]:
    state = text(finding.get("proof_state"), 40).lower()
    reason = text(finding.get("verification_reason"), 400)
    if finding.get("source") == "ai_gate" or finding.get("ai_target_id"):
        judge = text(evidence.get("judge_layer"), 60).replace("_", " ")
        return {"level": "likely" if state == "verified" else "tentative",
                "reason": f"Judged from the model's response{f' by the {judge}' if judge else ''}; model behaviour varies between runs, so retest before concluding."}
    if state == "verified" or finding.get("verified") is True:
        note = _CONFIRMED_NOTES.get(family, "")
        return {"level": "confirmed", "reason": " ".join(part for part in (reason + "." if reason and not reason.endswith(".") else reason, note) if part)}
    if state in {"likely_vulnerable", "suspected"} or finding.get("suspected") is True and state != "candidate":
        return {"level": "likely", "reason": reason or "A strong signal was observed, but the deterministic proof has not run or did not complete."}
    return {"level": "tentative", "reason": reason or "A pattern matched; nothing has confirmed the issue yet. Retest to prove or refute it."}


def build_finding_detail(finding: Mapping[str, Any]) -> dict[str, Any]:
    """The brief for one stored finding (already redacted by the read path)."""
    evidence = record(finding.get("evidence"))
    try:
        brief = _builder(finding, evidence)(finding, evidence) or other.build_generic(finding, evidence)
    except Exception:  # a malformed historical row falls back to the generic brief
        brief = other.build_generic(finding, evidence)
    if not brief.get("class"):
        brief = other.build_generic(finding, evidence)
    family = str(brief["class"]).split(".", 1)[0]
    brief = {key: value for key, value in brief.items() if value not in (None, "", [], {})}
    brief["schema"] = DETAIL_SCHEMA
    brief["confidence"] = _confidence(finding, evidence, family)
    brief["severity"] = severity_section(finding, evidence, )
    if "secret_refs" not in brief:
        refs = exposure.secret_refs(evidence)
        if refs:
            brief["secret_refs"] = refs
    return brief


# Related findings: the same certificate, origin or class on the same target.
RELATED_SQL = """
    SELECT id, title, severity, url, tool, status, last_seen_at,
           evidence->>'check' AS check_id,
           evidence->>'exposure_class' AS exposure_class,
           COALESCE(evidence->>'certificate_sha256', evidence->'certificate'->>'sha256') AS certificate_sha256
    FROM findings
    WHERE target_id = $1 AND id <> $2 AND status = 'active'
    ORDER BY created_at DESC
    LIMIT 200
"""
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def related_findings(finding: Mapping[str, Any], rows: list[Mapping[str, Any]], limit: int = 8) -> list[dict[str, Any]]:
    """Rank ``rows`` (from ``RELATED_SQL``) by how they relate to ``finding``; bounded and value-free."""
    from .common import origin_of
    evidence = record(finding.get("evidence"))
    cert = text(evidence.get("certificate_sha256") or record(evidence.get("certificate")).get("sha256"), 64)
    origin = origin_of(finding.get("url"))
    tool = text(finding.get("tool"), 80)
    exposure_class = text(evidence.get("exposure_class"), 80)
    ranked: list[tuple[int, int, dict[str, Any]]] = []
    for row in rows:
        reason = ""
        priority = 9
        if cert and row.get("certificate_sha256") == cert:
            reason, priority = "Same certificate", 0
        elif exposure_class and row.get("exposure_class") and origin_of(row.get("url")) == origin:
            reason, priority = "Other exposed content on this origin", 1
        elif tool and row.get("tool") == tool and origin and origin_of(row.get("url")) == origin:
            reason, priority = "Same check on this origin", 2
        elif origin and origin_of(row.get("url")) == origin and _SEVERITY_RANK.get(str(row.get("severity")), 5) <= 2:
            reason, priority = "Other significant finding on this origin", 3
        if not reason:
            continue
        ranked.append((priority, _SEVERITY_RANK.get(str(row.get("severity")), 5), {
            "id": str(row.get("id")), "title": text(row.get("title"), 200), "severity": text(row.get("severity"), 20),
            "url": text(row.get("url"), 400), "relation": reason,
        }))
    ranked.sort(key=lambda item: (item[0], item[1]))
    return [item[2] for item in ranked[:limit]]


__all__ = ["RELATED_SQL", "build_finding_detail", "related_findings"]
