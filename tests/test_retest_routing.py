"""Which retest a finding gets, from its tool and title.

A finding is retested only by a prover of the same kind of check. The tool decides: a tool in
``RETEST_TOOL_TYPE_MAP`` names its prover; title guessing runs only for a finding with no tool or
with one of the tools the scanner stored before the current Scan (``PRE_V2_TITLE_INFERENCE_TOOLS``),
and matches whole words. Every other tool gets no retest type and a reason: a template finding
needs its template replayed, an exposure is checked again by a Scan, the rest by a new Scan.

The titles below are the ones the 2.11 Scan emits (finalizer, posture rules, the template names
the active and passive sets produce), plus findings stored by earlier releases.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from capabilities.exposure_probe import EXPOSURE_PROOF_CONTRACTS
from retest_contract import (
    PRE_V2_POSTURE_TOOLS,
    PRE_V2_TITLE_INFERENCE_TOOLS,
    RETEST_TOOL_TYPE_MAP,
    infer_type_from_title_tool,
    retest_unsupported_reason,
    title_inference_allowed,
)

ROOT = Path(__file__).resolve().parents[1]
RESCAN = "retest_by_rescan_only"
TEMPLATE = "retest_needs_template_replay"
EXPOSURE = "retest_exposure_by_rescan"

# (tool, title, retest type or None, reason when None)
SCAN_TITLES = [
    ("dns.inspect", "No CAA record", None, RESCAN),
    ("dns.inspect", "No DMARC record", None, RESCAN),
    ("dns.inspect", "No SPF record", None, RESCAN),
    ("dns.inspect", "Multiple SPF records", None, RESCAN),
    ("dns.inspect", "DMARC policy is p=none (monitoring only)", None, RESCAN),
    ("dns.inspect", "SPF record authorizes every sender (+all)", None, RESCAN),
    ("dns.inspect", "SPF record ends in ?all (neutral)", None, RESCAN),
    ("dns.inspect", "SPF record exceeds 10 DNS lookups", None, RESCAN),
    # The CORS prover sends one attacker origin; these checks are the baseline's own probes.
    ("http_baseline", "CORS policy reflects any origin", None, RESCAN),
    ("http_baseline", "CORS policy trusts the null origin", None, RESCAN),
    ("http_baseline", "CORS wildcard combined with credentials", None, RESCAN),
    ("http_baseline", "Missing Content Security Policy header", None, RESCAN),
    ("http_baseline", "Missing HTTP Strict Transport Security header", None, RESCAN),
    ("http_baseline", "Missing Permissions Policy header", None, RESCAN),
    ("http_baseline", "Missing Referrer Policy header", None, RESCAN),
    ("http_baseline", "Session cookie without HttpOnly flag", None, RESCAN),
    ("http_baseline", "Session cookie without Secure flag", None, RESCAN),
    ("http_baseline", "Session cookie without SameSite flag", None, RESCAN),
    ("http_baseline", "Weak Content-Security-Policy header value", None, RESCAN),
    ("http_baseline", "Weak Permissions-Policy header value", None, RESCAN),
    ("http_baseline", "Weak Referrer-Policy header value", None, RESCAN),
    ("http_baseline", "Weak Strict-Transport-Security header value", None, RESCAN),
    ("http_baseline", "Weak X-Content-Type-Options header value", None, RESCAN),
    ("http_baseline", "Weak X-Frame-Options header value", None, RESCAN),
    # Template names: "Path Traversal", "Remote Code Execution", "JWT" and ".env" in a template's
    # name say nothing about which prover could replay it.
    ("nuclei", "AWS Credentials - Detect", None, TEMPLATE),
    ("nuclei", "Apache 2.4.49 - Path Traversal and Remote Code Execution", None, TEMPLATE),
    ("nuclei", "Apache Tomcat Manager Default Login", None, TEMPLATE),
    ("nuclei", "Apache htpasswd Config - Detect", None, TEMPLATE),
    ("nuclei", "Application Setting file disclosure", None, TEMPLATE),
    ("nuclei", "Codeigniter - .env File Discovery", None, TEMPLATE),
    ("nuclei", "Django Secret Key Exposure", None, TEMPLATE),
    ("nuclei", "Docker Container - Misconfiguration Exposure", None, TEMPLATE),
    ("nuclei", "Docker Daemon Exposed", None, TEMPLATE),
    ("nuclei", "Generic Env File Disclosure", None, TEMPLATE),
    ("nuclei", "Git Configuration - Detect", None, TEMPLATE),
    ("nuclei", "Git Credentials - Detect", None, TEMPLATE),
    ("nuclei", "Laravel - Sensitive Information Disclosure", None, TEMPLATE),
    ("nuclei", "Missing HTTP response header: Content-Security-Policy", None, TEMPLATE),
    ("nuclei", "Missing HTTP response header: Cross-Origin-Embedder-Policy", None, TEMPLATE),
    ("nuclei", "Missing HTTP response header: Cross-Origin-Opener-Policy", None, TEMPLATE),
    ("nuclei", "Missing HTTP response header: Cross-Origin-Resource-Policy", None, TEMPLATE),
    ("nuclei", "Missing HTTP response header: Permissions-Policy", None, TEMPLATE),
    ("nuclei", "Missing HTTP response header: Referrer-Policy", None, TEMPLATE),
    ("nuclei", "Missing HTTP response header: Strict-Transport-Security", None, TEMPLATE),
    ("nuclei", "Missing HTTP response header: X-Content-Type-Options", None, TEMPLATE),
    ("nuclei", "Missing HTTP response header: X-Frame-Options", None, TEMPLATE),
    ("nuclei", "Missing HTTP response header: X-Permitted-Cross-Domain-Policies", None, TEMPLATE),
    ("nuclei", "Netrc - Config File Discovery", None, TEMPLATE),
    ("nuclei", "OpenAPI - Detect", None, TEMPLATE),
    ("nuclei", "SSL/SSH/TLS/JWT Keys - Detect", None, TEMPLATE),
    ("shakerscan_browser_proof", "Verified cross-site scripting", "xss", None),
    ("dalfox", "Verified cross-site scripting", "xss", None),
    ("playwright", "Verified cross-site scripting", "xss", None),
    ("request_xss_differential", "Potential reflected cross-site scripting", "xss", None),
    ("request_sqli_differential", "Potential SQL injection", "sqli", None),
    ("sqlmap", "Potential SQL injection", "sqli", None),
    ("shakerscan_sqli_proof", "Verified SQL injection", "sqli", None),
    ("shakerscan_sqli_proof", "Verified SQL injection authentication bypass", "sqli", None),
    ("shakerscan_nosqli_verify", "Verified NoSQL injection", "nosqli", None),
    ("shakerscan_nosqli_verify", "Verified NoSQL injection authentication bypass", "nosqli", None),
    ("shakerscan_redirect_probe", "Open redirect", "open_redirect", None),
    ("shakerscan_graphql_probe", "GraphQL alias limit absent (100 aliases in one query)", None, RESCAN),
    ("shakerscan_graphql_probe", "GraphQL duplicate field limit absent (100 duplicates in one query)",
     None, RESCAN),
    ("shakerscan_graphql_probe", "GraphQL field suggestions enabled", None, RESCAN),
    ("smart_authz", "Verified broken object authorization", None, RESCAN),
    ("shakerscan_authz_surface",
     "Endpoint serves identical data to anonymous and authenticated principals", None, RESCAN),
    ("subdomain_takeover",
     "Subdomain takeover: old.example.com points to an unclaimed GitHub Pages resource", None, RESCAN),
    ("tls.inspect", "Legacy TLS protocol negotiated", None, RESCAN),
    ("tls.inspect", "TLS certificate chain is not trusted", None, RESCAN),
    ("tls.inspect", "TLS certificate expires within 30 days", None, RESCAN),
    ("tls.inspect", "TLS certificate hostname mismatch", None, RESCAN),
    ("tls.inspect", "TLS certificate is expired", None, RESCAN),
    ("tls.inspect", "TLS certificate is not yet valid", None, RESCAN),
    ("tls.inspect", "TLS certificate uses a weak public key", None, RESCAN),
    ("tls.inspect", "TLS certificate uses a weak signature", None, RESCAN),
    ("tls.inspect", "Weak TLS cipher negotiated", None, RESCAN),
    ("autonomous_workflow", "Verified stored cross-site scripting", "generic_http", None),
]

# Findings stored by earlier scanners: an empty tool, or a tool of the scanner before the
# current Scan. Title guessing still routes them, by whole words only.
EARLIER_TITLES = [
    ("", "SQL Injection in id parameter", "sqli", None),
    ("", "NoSQL Injection Vulnerability", "nosqli", None),
    ("smart_sqli", "NoSQL Injection in username", "nosqli", None),
    ("", "Command Injection in cmd parameter", "command_injection", None),
    ("", "Remote Code Execution via template", "command_injection", None),
    ("", "RCE in upload handler", "command_injection", None),
    ("", "JWT signature not validated", "jwt", None),
    ("jwt_vulnerability", "JWT accepts alg=none", "jwt", None),
    ("", "SSTI in template parameter", "ssti", None),
    ("ssti", "Server-side template injection in name", "ssti", None),
    ("ssrf", "SSRF via url parameter", "ssrf", None),
    ("path_traversal", "Path traversal in file parameter", "path_traversal", None),
    ("", "LFI via ../ in page", "path_traversal", None),
    ("open_redirect", "Open Redirect in next parameter", "open_redirect", None),
    ("cors_check", "CORS misconfiguration: credentials with reflected origin", "cors", None),
    ("xxe_injection", "XXE in XML upload", "xxe", None),
    ("stored_xss", "Stored XSS in comment", "xss", None),
    ("", "Broken Function Level Authorization: /api/users", "bola", None),
    ("", "Broken access control on /admin", "bola", None),
    ("", "IDOR on /api/orders/{id}", "idor", None),
    ("exposed_files", "Exposed file: id_rsa (confidence: high)", "exposed_file", None),
    ("forced_browsing", "Accessible Sensitive File: /wp-config.php", "exposed_file", None),
    ("forced_browsing", "Accessible Backup File: /dump.sql", "exposed_file", None),
    ("", "Exposed file: .env", "exposed_file", None),
    ("api_security", "Sensitive data exposed in API response", None, RESCAN),
    # An earlier posture or exposure check names a header, a file, a library or a secret's kind,
    # never the kind of attack a prover replays: its title is not guessed.
    ("http_headers", "Missing X-XSS-Protection header", None, RESCAN),
    ("js_secret", "Hardcoded Secret in JavaScript: JWT token", None, RESCAN),
    ("js_dependency", "Vulnerable JavaScript Library: jquery 1.8.1 (XSS)", None, RESCAN),
    ("input_validation", "Input not validated: possible RCE", None, RESCAN),
    ("backup_file", "Exposed Backup File: /jwt.key.bak", None, RESCAN),
    ("csp_evaluator", "CSP allows inline script (XSS risk)", None, RESCAN),
    # Substrings of other words never route: "rce" in "enforced", "force" and "source".
    ("http_headers", "HSTS not enforced", None, RESCAN),
    ("bruteforce_protection", "Brute-force protection absent", None, RESCAN),
    ("rate_limiting", "Rate limit not enforced", None, RESCAN),
    ("", "Sensitive exposure: backup or source artifact", None, RESCAN),
    ("", "Resource enforced by policy", None, RESCAN),
    ("subdomain_takeover_advanced", "Subdomain takeover candidate: shop.example.com", None, RESCAN),
]


def _exposure_titles() -> list[tuple[str, str, None, str]]:
    graphql = {
        "graphql_introspection_enabled": "GraphQL introspection enabled",
        "graphql_ide_exposure": "GraphQL IDE served publicly",
    }
    return [
        ("shakerscan_exposure_probe",
         graphql.get(name) or f"Sensitive exposure: {name.replace('_', ' ')}", None, EXPOSURE)
        for name in sorted(EXPOSURE_PROOF_CONTRACTS)
    ]


@pytest.mark.parametrize(
    "tool,title,retest_type,reason", SCAN_TITLES + EARLIER_TITLES + _exposure_titles(),
)
def test_every_emitted_title_routes_to_its_own_kind_of_check_or_to_none(tool, title, retest_type, reason):
    assert infer_type_from_title_tool(title, tool) == retest_type
    if retest_type is None:
        assert retest_unsupported_reason(tool) == reason


def test_exposure_titles_never_reach_another_prover_without_a_tool():
    # An exposure finding stored without its tool is still not guessed into an injection prover.
    for _tool, title, _type, _reason in _exposure_titles():
        assert infer_type_from_title_tool(title, "") is None, title


def _string_kwargs(path: Path, name: str) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        keyword.value.value for node in ast.walk(tree) if isinstance(node, ast.Call)
        for keyword in node.keywords
        if keyword.arg == name and isinstance(keyword.value, ast.Constant)
        and isinstance(keyword.value.value, str)
    }


#: The tool values the current Scan and Hunt store on findings (finalizer, posture rules, retired
#: findings, Hunt browser proofs, Deep Hunt promotion, Model Intake).
CURRENT_TOOLS = frozenset({
    "dalfox", "dns.inspect", "http_baseline", "nuclei", "playwright",
    "request_sqli_differential", "request_xss_differential",
    "shakerscan_authz_surface", "shakerscan_browser_proof", "shakerscan_exposure_probe",
    "shakerscan_graphql_probe", "shakerscan_nosqli_verify", "shakerscan_redirect_probe",
    "shakerscan_sqli_proof", "smart_authz", "sqlmap", "subdomain_takeover", "tls.inspect",
    "autonomous_workflow", "model_intake",
})


def test_the_current_tools_are_the_ones_the_scan_stores():
    stored = set()
    for relative in ("api/scan/finalizer.py", "api/scan/posture_findings.py",
                     "api/scan/retired_findings.py"):
        stored |= _string_kwargs(ROOT / relative, "tool")
    stored |= {"request_xss_differential", "request_sqli_differential"}  # f"request_{family}_differential"
    stored |= {"playwright", "autonomous_workflow", "model_intake"}  # Hunt, Deep Hunt, Model Intake
    assert stored == CURRENT_TOOLS
    # None of them is title-guessed: each names its prover or gets a reason.
    for tool in CURRENT_TOOLS:
        assert not title_inference_allowed(tool), tool
        if tool not in RETEST_TOOL_TYPE_MAP and tool != "model_intake":
            assert infer_type_from_title_tool("Verified SQL injection RCE XSS", tool) is None, tool
            assert infer_type_from_title_tool("Verified NoSQL injection", tool) is None, tool


def _legacy_scanner_tools() -> set[str]:
    """Tool names the scanner before the current Scan passed to ``normalize_finding``."""
    tools: set[str] = set()
    for path in sorted((ROOT / "scanner").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", None))
                    == "normalize_finding" and node.args):
                continue
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                tools.add(first.value)
            elif isinstance(first, ast.Call) and len(first.args) == 2 and isinstance(first.args[1], ast.Constant):
                tools.add(str(first.args[1].value))  # finding.get("tool", "<default>")
            elif isinstance(first, ast.Call) and isinstance(first.args[0] if first.args else None, ast.BoolOp):
                tools.add(str(first.args[0].values[-1].value))  # str(f.get("tool") or "<default>")
    return tools - {"tool"}


def test_title_guessing_runs_only_for_the_earlier_scanners_tools():
    legacy = _legacy_scanner_tools()
    # Shared with the current Scan, so never guessed; and the tools that name a prover directly.
    # The rest are split: checks that sent attack input, whose title names what they injected,
    # and posture or exposure checks, whose title names a header, file, library or secret.
    assert PRE_V2_TITLE_INFERENCE_TOOLS | PRE_V2_POSTURE_TOOLS == frozenset(
        legacy - CURRENT_TOOLS - set(RETEST_TOOL_TYPE_MAP))
    assert not PRE_V2_TITLE_INFERENCE_TOOLS & PRE_V2_POSTURE_TOOLS
    for tool in PRE_V2_POSTURE_TOOLS:
        assert not title_inference_allowed(tool), tool
        assert infer_type_from_title_tool("Reflected XSS, SQL injection and RCE via JWT", tool) is None
        assert retest_unsupported_reason(tool) == RESCAN
    assert title_inference_allowed("") and title_inference_allowed(None)
    assert title_inference_allowed("jwt_none_algorithm") and title_inference_allowed("graphql_batching")
    assert not title_inference_allowed("an_unknown_tool")
    assert infer_type_from_title_tool("SQL injection in id", "an_unknown_tool") is None
    assert retest_unsupported_reason("an_unknown_tool") == RESCAN
