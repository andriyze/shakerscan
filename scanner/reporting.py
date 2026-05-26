"""
Report generation and finding emission utilities.

This module handles:
- Emitting configuration-based findings from HTTP headers, TLS, DNS, etc.
- Reproduction command generation for findings
- AI verdict heuristics
- Text masking and redaction for AI/reporting

Extracted from scanner.py for better maintainability.
"""
from __future__ import annotations

import json
import re
import shlex
import urllib.parse
from typing import Any

# Support both package import and script import
try:
    from .findings import normalize_finding
except ImportError:
    from findings import normalize_finding


# ---------- Reproduction command helpers ----------

def _reproCurlHost(base_url: str) -> str:
    return f"curl -sIL {shlex.quote(base_url)}"


def _reproCurlCors(url: str, origin: str = "https://evil.com") -> str:
    return f"curl -sI -H 'Origin: {origin}' -H 'Access-Control-Request-Method: GET' -X OPTIONS {shlex.quote(url)}"


def _reproDig(name: str, rtype: str = "TXT") -> str:
    return f"dig +short {shlex.quote(name)} {rtype}"


def _reproDelv(domain: str) -> str:
    return f"delv @1.1.1.1 {shlex.quote(domain)} A"


def _reproTLS(host: str, port: int) -> str:
    return f"testssl.sh -e --fast {shlex.quote(host)}:{port}"


# ---------- Configuration findings emission ----------

def emit_config_findings(report: dict[str, Any]) -> None:
    """Translate HTTP header/CSP/cookies/TLS/DNS/CORS/cloud/WAF data into normalized findings.
    This mirrors how Nuclei emits issues: one finding per concrete misconfiguration.
    """
    base_url = report.get("http", {}).get("final_url") or f"https://{report['input']['normalized_host']}"
    host = report.get("input", {}).get("normalized_host") or ""
    port = report.get("input", {}).get("port") or 443
    http = report.get("http", {})
    dns = report.get("dns", {})
    tls = report.get("tls", {})
    discovery = report.get("discovery", {})

    # ---- HTTP security headers ----
    sec = http.get("security_headers", {}) or {}
    # HSTS
    if not sec.get("hsts"):
        report["findings"].append(normalize_finding(
            "http_headers",
            "HSTS header missing",
            "medium",
            {"header": "strict-transport-security", "missing": True, "reproduction": _reproCurlHost(base_url)},
            "CWE-693"
        ))
    # X-Frame-Options
    if not sec.get("x_frame_options"):
        report["findings"].append(normalize_finding(
            "http_headers",
            "X-Frame-Options missing",
            "low",
            {"header": "x-frame-options", "missing": True, "reproduction": _reproCurlHost(base_url)},
            "CWE-693"
        ))
    # X-Content-Type-Options
    xcto = sec.get("x_content_type_options")
    if not xcto or xcto.lower() != "nosniff":
        report["findings"].append(normalize_finding(
            "http_headers",
            "X-Content-Type-Options not 'nosniff'",
            "low",
            {"header": "x-content-type-options", "current_value": xcto, "reproduction": _reproCurlHost(base_url)},
            "CWE-16"
        ))
    # Referrer-Policy
    if not sec.get("referrer_policy"):
        report["findings"].append(normalize_finding(
            "http_headers",
            "Referrer-Policy missing",
            "low",
            {"header": "referrer-policy", "missing": True, "reproduction": _reproCurlHost(base_url)},
            "CWE-200"
        ))
    # Permissions-Policy
    if not sec.get("permissions_policy"):
        report["findings"].append(normalize_finding(
            "http_headers",
            "Permissions-Policy missing",
            "low",
            {"header": "permissions-policy", "missing": True, "reproduction": _reproCurlHost(base_url)},
            "CWE-693"
        ))

    # ---- CSP ----
    csp_eval = http.get("csp_evaluation", {}) or {}
    csp_present = csp_eval.get("present", False)
    if not csp_present:
        report["findings"].append(normalize_finding(
            "csp_evaluator",
            "CSP header missing",
            "medium",
            {"present": False, "reproduction": _reproCurlHost(base_url)},
            "CWE-693"
        ))
    else:
        issues = csp_eval.get("issues", []) or []
        directives = csp_eval.get("directives", {}) or {}
        missing_default = "default-src" not in directives
        missing_script = "script-src" not in directives
        # If both are missing, emit a single high-severity finding and skip individual missing-* issues to avoid noise
        if missing_default and missing_script:
            finding = normalize_finding(
                "csp_evaluator",
                "CSP: default-src and script-src missing",
                "high",
                {
                    "present": True,
                    "grade": csp_eval.get("grade"),
                    "issue": "both default-src and script-src missing",
                    "reproduction": _reproCurlHost(base_url)
                },
                "CWE-693"
            )
            finding["template_id"] = "http/csp/missing-default-and-script-src"
            finding["category"] = "http.csp"
            report["findings"].append(finding)
        for issue in issues:
            if missing_default and missing_script and "both default-src and script-src missing" in issue.lower():
                continue
            sev = "medium"
            title = f"CSP: {issue}"
            template_id = None
            # Simple templating for common patterns
            low_patterns = ["upgrade-insecure-requests missing", "Trusted Types not required"]
            if any(lp in issue for lp in low_patterns):
                sev = "low"
            if "missing default-src" in issue.lower():
                template_id = "http/csp/missing-default-src"
                # Skip individual issue if both are missing (already emitted combined)
                if missing_default and missing_script:
                    continue
            elif "unsafe-inline" in issue.lower():
                template_id = "http/csp/unsafe-inline"
            elif "unsafe-eval" in issue.lower():
                template_id = "http/csp/unsafe-eval"
            elif "object-src" in issue.lower():
                template_id = "http/csp/object-src-weak"
            elif "frame-ancestors" in issue.lower():
                template_id = "http/csp/frame-ancestors-weak"
            elif "missing script-src" in issue.lower():
                template_id = "http/csp/missing-script-src"
                if missing_default and missing_script:
                    continue
            finding = normalize_finding("csp_evaluator", title, sev, {
                "present": True,
                "grade": csp_eval.get("grade"),
                "issue": issue,
                "reproduction": _reproCurlHost(base_url)
            }, "CWE-693")
            if template_id:
                finding["template_id"] = template_id
            finding["category"] = "http.csp"
            report["findings"].append(finding)

    # ---- Cookies ----
    cookies = http.get("cookies", {}) or {}
    for det in cookies.get("details", [])[:10]:
        raw = det.get("raw", "")
        # Determine issues for this cookie
        if not det.get("secure", False):
            report["findings"].append(normalize_finding(
                "cookies_analyzer",
                "Cookie without Secure flag",
                "medium",
                {"raw_sample": raw[:200], "cookie_secure": False, "reproduction": _reproCurlHost(base_url)},
                "CWE-614"
            ))
        if not det.get("httponly", False):
            report["findings"].append(normalize_finding(
                "cookies_analyzer",
                "Cookie without HttpOnly flag",
                "medium",
                {"raw_sample": raw[:200], "cookie_httponly": False, "reproduction": _reproCurlHost(base_url)},
                "CWE-1004"
            ))
        if det.get("samesite") is None:
            report["findings"].append(normalize_finding(
                "cookies_analyzer",
                "Cookie without SameSite attribute",
                "low",
                {"raw_sample": raw[:200], "cookie_samesite": None, "reproduction": _reproCurlHost(base_url)},
                "CWE-16"
            ))

    # ---- Redirect to HTTPS ----
    if http.get("scheme_redirect") == "none":
        report["findings"].append(normalize_finding(
            "redirect_check",
            "Does not redirect HTTP to HTTPS",
            "medium",
            {"detail": "HTTP did not redirect to HTTPS", "reproduction": f"curl -sI http://{host}"},
            "CWE-319"
        ))

    # ---- TLS/SSL config ----
    sslyze = tls.get("sslyze", {}) or {}
    tlsx_ep = tls.get("endpoints", []) or []
    supports = (sslyze.get("tls_versions") or {})
    legacy = any(k in supports for k in ("ssl_3_0", "tls_1_0", "tls_1_1") if supports.get(k))
    if legacy:
        report["findings"].append(normalize_finding(
            "tls_config",
            "Legacy TLS enabled (<= TLS 1.1)",
            "medium",
            {"tls_versions": list(k for k,v in supports.items() if v), "reproduction": _reproTLS(host, port)},
            "CWE-310"
        ))
    # TLS 1.3 not supported (best-effort)
    has13 = supports.get("tls_1_3") or tls.get("testssl", {}).get("supports_tls13")
    if has13 is False:
        report["findings"].append(normalize_finding(
            "tls_config",
            "TLS 1.3 not supported",
            "low",
            {"detail": "Server does not offer TLS 1.3", "reproduction": _reproTLS(host, port)},
            "CWE-310"
        ))
    # OCSP stapling off
    if not (tls.get("ocsp", {}).get("stapled") or sslyze.get("ocsp_stapling")):
        report["findings"].append(normalize_finding(
            "tls_config",
            "OCSP stapling not detected",
            "low",
            {"detail": "No stapled OCSP response", "reproduction": f"openssl s_client -connect {host}:{port} -servername {host} -status | sed -n '1,120p'"},
            "CWE-310"
        ))
    # Certificate expiry
    cert = tls.get("certificate", {}) or {}
    if isinstance(cert, dict):
        days = cert.get("days_remaining")
        if isinstance(days, int) and days <= 30:
            report["findings"].append(normalize_finding(
                "tls_config",
                "TLS certificate expiring soon (<= 30 days)",
                "medium",
                {"days_remaining": days, "not_after": cert.get("not_after"), "reproduction": f"echo | openssl s_client -connect {host}:{port} -servername {host} 2>/dev/null | openssl x509 -noout -enddate"},
                "CWE-295"
            ))

    # ---- DNS, Email policy & DNSSEC ----
    # Check for MX records - if domain doesn't send email, SPF/DMARC findings are informational only
    mx_records = dns.get("mx", [])
    has_email_capability = bool(mx_records)
    email_policy_severity = "medium" if has_email_capability else "info"

    if not dns.get("spf"):
        title = "SPF missing" if has_email_capability else "SPF missing (no MX records - informational)"
        report["findings"].append(normalize_finding(
            "dns_policy",
            title,
            email_policy_severity,
            {"record": None, "reproduction": _reproDig(host, "TXT")},
            "CWE-16"
        ))
    dmarc = (dns.get("dmarc") or {})
    if not dmarc.get("record"):
        title = "DMARC missing" if has_email_capability else "DMARC missing (no MX records - informational)"
        report["findings"].append(normalize_finding(
            "dns_policy",
            title,
            email_policy_severity,
            {"record": None, "reproduction": _reproDig(f"_dmarc.{host}", "TXT")},
            "CWE-16"
        ))
    else:
        pol = (dmarc.get("fields") or {}).get("p", "").lower()
        if pol not in ("quarantine", "reject"):
            report["findings"].append(normalize_finding(
                "dns_policy",
                "DMARC policy not enforced (p != quarantine/reject)",
                "low",
                {"current_p": pol or "none", "reproduction": _reproDig(f"_dmarc.{host}", "TXT")},
                "CWE-16"
            ))
        if not (dmarc.get("fields") or {}).get("rua"):
            report["findings"].append(normalize_finding(
                "dns_policy",
                "DMARC rua not set",
                "low",
                {"detail": "Aggregate reports not configured", "reproduction": _reproDig(f"_dmarc.{host}", "TXT")},
                "CWE-16"
            ))
    dnssec = (dns.get("dnssec") or {})
    if dnssec.get("status") == "bogus":
        report["findings"].append(normalize_finding(
            "dns_policy",
            "DNSSEC validation failure (bogus)",
            "high",
            {"raw": (dnssec.get("raw") or "")[:400], "reproduction": _reproDelv(host)},
            "CWE-16"
        ))
    elif dnssec.get("status") in ("insecure", None):
        report["findings"].append(normalize_finding(
            "dns_policy",
            "DNSSEC not validated",
            "info",
            {"status": dnssec.get("status"), "reproduction": _reproDelv(host)},
            "CWE-16"
        ))
    # CAA
    caa = (dns.get("caa") or {}).get("records", [])
    if not caa:
        report["findings"].append(normalize_finding(
            "dns_policy",
            "CAA record missing",
            "low",
            {"record": None, "reproduction": _reproDig(host, "CAA")},
            "CWE-16"
        ))
    # MTA-STS / TLS-RPT - only relevant if domain has email capability (MX records)
    mta = dns.get("mta_sts", {}) or {}
    if not mta.get("record") and not mta.get("policy_present"):
        mta_title = "MTA-STS not configured" if has_email_capability else "MTA-STS not configured (no MX records - informational)"
        report["findings"].append(normalize_finding(
            "dns_policy",
            mta_title,
            "low" if has_email_capability else "info",
            {"reproduction": _reproDig(f"_mta-sts.{host}", "TXT")},
            "CWE-16"
        ))
    tlsrpt = dns.get("tls_rpt", {}) or {}
    if not tlsrpt.get("record"):
        tlsrpt_title = "TLS-RPT not configured" if has_email_capability else "TLS-RPT not configured (no MX records - informational)"
        report["findings"].append(normalize_finding(
            "dns_policy",
            tlsrpt_title,
            "low" if has_email_capability else "info",
            {"reproduction": _reproDig(f"_smtp._tls.{host}", "TXT")},
            "CWE-16"
        ))
    # DKIM selectors (if provided)
    if dns.get("dkim"):
        for name, info in (dns["dkim"] or {}).items():
            if not info.get("present"):
                report["findings"].append(normalize_finding(
                    "dns_policy",
                    f"DKIM selector missing: {name}",
                    "low",
                    {"selector": name, "reproduction": _reproDig(name, "TXT")},
                    "CWE-16"
                ))

    # ---- CORS ----
    cors = (discovery.get("cors") or {})
    if cors.get("vulnerable"):
        issues = cors.get("issues", [])
        report["findings"].append(normalize_finding(
            "cors_scanner",
            "CORS misconfiguration",
            "high" if any("*" in i or "Reflects" in i for i in issues) else "medium",
            {
                "url": base_url,
                "issues": issues[:5],
                "access-control-allow-origin": cors.get("access-control-allow-origin"),
                "access-control-allow-credentials": cors.get("access-control-allow-credentials"),
                "reproduction": _reproCurlCors(base_url),
            },
            "CWE-942"
        ))

    # ---- Security.txt ----
    sec_txt = (http.get("security_txt") or {})
    if isinstance(sec_txt, dict) and not sec_txt.get("present"):
        report["findings"].append(normalize_finding(
            "security_txt",
            "security.txt missing",
            "info",
            {"url": sec_txt.get("url"), "reproduction": f"curl -sL {sec_txt.get('url') or urllib.parse.urljoin(base_url, '/.well-known/security.txt')}"},
            "CWE-16"
        ))

    # ---- Cloud/WAF ----
    cloud = (discovery.get("cloud_services") or {})
    for mis in cloud.get("misconfigurations", [])[:5]:
        sev = mis.get("severity", "low").lower()
        title = {
            "s3_public_list": "S3 bucket allows public listing",
            "origin_ip_leak": "Origin IP exposed via headers",
            "cloudflare_ip_leak": "Cloudflare IP leak indicator"
        }.get(mis.get("type"), "Cloud service misconfiguration")
        report["findings"].append(normalize_finding(
            "cloud_scanner",
            title,
            sev if sev in ("critical","high","medium","low","info") else "medium",
            {"details": mis.get("details"), "provider": cloud.get("provider"), "cdn": cloud.get("cdn")},
            "CWE-200" if "leak" in (mis.get("type") or "") else "CWE-16"
        ))
    waf = (discovery.get("waf_detection") or {})
    if waf.get("waf_detected"):
        report["findings"].append(normalize_finding(
            "waf_detector",
            "WAF detected",
            "info",
            {"products": waf.get("waf_products", []), "confidence": waf.get("confidence")},
            "CWE-16"
        ))


# ---------- AI review helpers ----------

def _ai_safe_commands_for_finding(f: dict, base_url: str, host: str) -> list[str]:
    """Generate safe verification commands for a finding."""
    tool = (f.get("tool") or "").lower()
    title = (f.get("title") or "").lower()
    cmds: list[str] = []
    if tool in ("http_headers","csp_evaluator","cookies_analyzer","redirect_check","security_txt"):
        cmds.append(_reproCurlHost(base_url))
    if tool == "cors_scanner":
        cmds.append(_reproCurlCors(base_url))
    if tool.startswith("tls") or "tls" in title or "cipher" in title:
        port = 443
        cmds.append(_reproTLS(host, port))
    if tool == "dns_policy" or any(k in title for k in ["spf","dmarc","dkim","dnssec","caa"]):
        cmds.append(_reproDig(host, "TXT"))
        cmds.append(_reproDelv(host))
    if tool == "exposed_files":
        ev = f.get("evidence", {}) or {}
        url = ev.get("url") or urllib.parse.urljoin(base_url + "/", (ev.get("path") or "").lstrip("/"))
        path_l = (ev.get("path") or "").lower()
        # Always include a HEAD and a short safe preview of the body
        cmds.append(f"curl -sI {shlex.quote(url)}")
        cmds.append(f"curl -sL {shlex.quote(url)} | sed -n '1,40p'")
        # Targeted probes for common high-risk exposures
        if any(k in path_l for k in ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "server.key", "private.key", ".pem"]):
            cmds.append(f"curl -sL {shlex.quote(url)} | grep -E 'BEGIN (OPENSSH|RSA|DSA|EC) PRIVATE KEY' -m1")
        if ".git" in path_l:
            base = base_url.rstrip("/")
            cmds.append(f"curl -sL {shlex.quote(base)}/.git/HEAD")
            cmds.append(f"curl -sL {shlex.quote(base)}/.git/config")
    if tool == "graphql_vulnerability" or ("graphql" in title):
        ev = f.get("evidence", {}) or {}
        # Try to use detected endpoint, else probe common ones
        endpoints: list[str] = []
        if isinstance(ev.get("evidence"), list) and ev["evidence"]:
            ep = ev["evidence"][0].get("endpoint") if isinstance(ev["evidence"][0], dict) else None
            if isinstance(ep, str):
                endpoints.append(ep)
        endpoints += ["/graphql", "/graphql/v2", "/api/graphql", "/query"]
        introspect = '{"query":"{ __schema { types { name } } }"}'
        for ep in endpoints[:2]:
            url = urllib.parse.urljoin(base_url, ep)
            cmds.append(f"curl -sX POST -H 'Content-Type: application/json' -d '{introspect}' {shlex.quote(url)}")
    if tool == "api_security" or ("openapi" in title) or ("swagger" in title):
        # Probe OpenAPI schema endpoints and look for securitySchemes/Bearer/API key hints
        for ep in ["/openapi.json", "/swagger.json", "/swagger/v1/swagger.json"]:
            url = urllib.parse.urljoin(base_url, ep)
            cmds.append(f"curl -sI {shlex.quote(url)}")
            cmds.append(f"curl -sS {shlex.quote(url)} | grep -Ei 'securitySchemes|bearer|apiKey' -m1")
    if "nosql" in title:
        _payload = json.dumps({"$ne": "1"})
        cmds.append(f"curl -i -X POST -H 'Content-Type: application/json' {shlex.quote(base_url)} --data '{_payload}'")
    if tool == "waf_detector":
        cmds.append(f"curl -sIL {shlex.quote(base_url)}?test=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
    return cmds[:3]


# Allowlist of test honeypot domains where vulnerabilities ARE intentional and real
# Findings on these domains should NOT be marked as false positives due to honeypot indicators
HONEYPOT_TEST_DOMAINS = {"honey.shakerscan.com", "test.shakerscan.com"}


def _ai_rule_verdict(f: dict, http_status: str | None, target_host: str = "") -> tuple[str, float, str]:
    """Heuristic verdict when no external AI provider configured."""
    title = (f.get("title") or "").lower()
    tool = (f.get("tool") or "").lower()
    ev = f.get("evidence") or {}
    validation = f.get("validation") if isinstance(f.get("validation"), dict) else {}
    rationale = []
    if (
        f.get("verified") is True
        or f.get("proof_of_exploitation") is True
        or ev.get("verified") is True
        or ev.get("proof_of_exploitation") is True
        or validation.get("verified") is True
        or validation.get("poe_proven") is True
    ):
        rationale.append("Finding includes verified exploitation evidence")
        return "true_positive", 0.95, "; ".join(rationale)

    # Strong true-positives: header/config absences
    if tool in ("http_headers","csp_evaluator","cookies_analyzer","dns_policy","tls_config","cors_scanner","redirect_check","security_txt"):
        rationale.append("Static misconfiguration derived from observed headers/records")
        return "true_positive", 0.95, "; ".join(rationale)

    # Check if this is a known test honeypot domain - skip honeypot detection
    is_test_honeypot = any(domain in target_host.lower() for domain in HONEYPOT_TEST_DOMAINS)

    # Honeypot heuristic (only for non-test domains)
    snippet = (ev.get("response_snippet") or "").lower()
    # Consider nested evidence structures for honeypot indicators
    nested_blob = ""
    try:
        nested_blob = json.dumps(ev, default=str).lower()
    except Exception:
        nested_blob = str(ev).lower()
    if not is_test_honeypot and (
        "honeypot" in snippet or "enterprise security testing honeypot" in snippet or
        "honeypot" in nested_blob or "enterprise security testing honeypot" in nested_blob or
        (http_status and " 405" in http_status)):
        rationale.append("Response indicates honeypot/405 behavior, not exploitable")
        return "false_positive", 0.9, "; ".join(rationale)
    # Known tool vulns: assume likely true
    if tool in ("sslyze","testssl","nuclei","dalfox","sqlmap","xxe_injection","subdomain_takeover_advanced"):
        rationale.append("Detected by specialized security tool")
        return "true_positive", 0.8, "; ".join(rationale)
    # Exposed files: treat medium/high-confidence as true positives; critical markers boost confidence
    if tool == "exposed_files":
        ev = f.get("evidence", {}) or {}
        conf = (ev.get("confidence") or "low").lower()
        path_l = (ev.get("path") or "").lower()
        critical_markers = ["id_rsa","id_dsa","id_ecdsa","id_ed25519","server.key","privatekey","private.key","ssl.key","cert.key","certificate.key",".pem"]
        if conf in ("high","medium"):
            if any(m in path_l for m in critical_markers):
                rationale.append("High-risk secret/key file path with medium/high evidence confidence")
                return "true_positive", 0.98 if conf == "high" else 0.9, "; ".join(rationale)
            rationale.append("Exposed sensitive file confirmed (medium/high confidence)")
            return "true_positive", 0.9 if conf == "high" else 0.8, "; ".join(rationale)
        return "unclear", 0.55, "Low confidence exposed file; verify manually"
    return "unclear", 0.5, "Insufficient evidence without active verification"


# ---------- Text masking and redaction ----------

def _mask_text_host(text: str, host: str, replacement_host: str, scheme: str | None) -> str:
    """Mask host in text for AI/reporting."""
    if not isinstance(text, str) or not host:
        return text
    h = re.escape(host)
    # Replace URLs first to preserve scheme
    def _repl_url(m):
        scheme_used = (scheme or m.group(1) or "https")
        # Pattern has two groups: (https?) and (:\d+)? → group(2) is optional port
        port = m.group(2) or ""
        return f"{scheme_used}://{replacement_host}{port}"
    text = re.sub(r"(?i)(https?)://" + h + r"(:\d+)?", _repl_url, text)
    # Replace bare host occurrences (word boundary or separators) - case-insensitive
    text = re.sub(r"(?i)(?<![\w.-])" + h + r"(?![\w.-])", replacement_host, text)
    # Common www variant
    text = re.sub(r"(?i)www\." + h, "www." + replacement_host, text)
    return text


def _redact_sensitive(text: str) -> str:
    """Redact sensitive tokens from text."""
    if not isinstance(text, str):
        return text
    text = re.sub(r"(?i)(authorization:\s*bearer)\s+[A-Za-z0-9._-]+", r"\1 ***", text)
    text = re.sub(r"(?i)(api[-_ ]?key|token|secret)=([^&\s]+)", r"\1=***", text)
    return text


def _redact_body_value(value: Any) -> Any:
    """Redact a single value."""
    if value is None:
        return None
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return 0
    if isinstance(value, float):
        return 0.0
    if isinstance(value, str):
        return "[REDACTED]"
    return "[REDACTED]"


def _redact_body_structure(value: Any) -> Any:
    """Recursively redact a data structure."""
    if isinstance(value, dict):
        return {k: _redact_body_structure(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_body_structure(v) for v in value]
    return _redact_body_value(value)


def _redact_body_for_report(body: Any, content_type: str | None = None) -> Any:
    """Redact body content for reporting while preserving structure."""
    if body is None:
        return None
    if isinstance(body, (dict, list)):
        return _redact_body_structure(body)
    if not isinstance(body, str):
        return "[REDACTED]"

    stripped = body.strip()
    content_type_l = (content_type or "").lower()
    if "json" in content_type_l or stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(body)
            return json.dumps(_redact_body_structure(parsed))
        except (json.JSONDecodeError, TypeError):
            return "[REDACTED]"

    if "application/x-www-form-urlencoded" in content_type_l:
        try:
            pairs = urllib.parse.parse_qsl(body, keep_blank_values=True)
            redacted_pairs = [(key, "[REDACTED]") for key, _ in pairs]
            return urllib.parse.urlencode(redacted_pairs)
        except Exception:
            return "[REDACTED]"

    return "[REDACTED]"


def _mask_structure(obj: Any, host: str, replacement_host: str, scheme: str | None) -> Any:
    """Recursively mask host in a data structure."""
    if isinstance(obj, dict):
        return {k: _mask_structure(v, host, replacement_host, scheme) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_mask_structure(v, host, replacement_host, scheme) for v in obj]
    if isinstance(obj, str):
        return _redact_sensitive(_mask_text_host(obj, host, replacement_host, scheme))
    return obj


# ---------- Fallback executive summary ----------

def _generate_fallback_executive_summary(
    report: dict[str, Any],
    findings: list[dict[str, Any]],
    tp_count: int,
    fp_count: int,
    unclear_count: int
) -> dict[str, Any]:
    """
    Generate a template-based executive summary when AI is unavailable.

    This provides a baseline summary that can be used for customer-facing reports
    when the AI provider fails or is not configured.
    """
    host = report.get("input", {}).get("normalized_host", "target")
    result = report.get("result", {})
    score = result.get("score", 0)
    grade = result.get("grade", "N/A")

    # Count findings by severity
    critical = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    medium = sum(1 for f in findings if f.get("severity") == "medium")
    low = sum(1 for f in findings if f.get("severity") == "low")
    confirmed = sum(1 for f in findings if f.get("verified") is True)
    review_needed = sum(
        1
        for f in findings
        if f.get("needs_verification") is True
        or f.get("confidence_tier") in ("low", "uncertain")
    )

    # Determine risk level
    if critical > 0:
        risk_level = "Critical"
        risk_description = f"The scan identified {critical} critical vulnerabilities that require immediate attention."
    elif high > 0:
        risk_level = "High"
        risk_description = f"The scan identified {high} high-severity issues that should be prioritized for remediation."
    elif medium > 0:
        risk_level = "Medium"
        risk_description = f"The scan identified {medium} medium-severity issues that should be addressed in your security roadmap."
    else:
        risk_level = "Low"
        risk_description = "No critical or high-severity vulnerabilities were identified. Continue monitoring and maintain security best practices."

    # Build key findings list
    key_findings = []
    for f in findings[:5]:  # Top 5 findings
        sev = f.get("severity", "info").capitalize()
        title = f.get("title", "Unknown issue")
        key_findings.append(f"[{sev}] {title}")

    # Build recommendations
    recommendations = []
    if result.get("focused_active_scope"):
        recommendations.extend(str(item) for item in (result.get("remediation") or []) if item)
        if not recommendations and critical > 0:
            recommendations.append("Address the confirmed critical vulnerability shown in the focused scan evidence.")
    else:
        if critical > 0:
            recommendations.append("Address critical vulnerabilities immediately - these represent exploitable attack vectors.")
        if high > 0:
            recommendations.append("Prioritize high-severity issues in your next sprint or maintenance window.")
        if not report.get("http", {}).get("security_headers", {}).get("hsts"):
            recommendations.append("Enable HTTP Strict Transport Security (HSTS) to protect against protocol downgrade attacks.")
        if report.get("http", {}).get("csp_evaluation", {}).get("grade") in ["D", "F"]:
            recommendations.append("Strengthen your Content Security Policy to mitigate XSS risks.")
        if not report.get("dns", {}).get("dmarc", {}).get("record"):
            recommendations.append("Implement DMARC to protect your domain from email spoofing.")

    confidence_summary = (
        f"{confirmed} confirmed finding(s), {fp_count} likely false positives, "
        f"{review_needed} require verification."
    )
    next_steps = ["Review critical and high-severity findings first."]
    if review_needed:
        next_steps.append("Validate findings marked as 'unclear' manually.")
    next_steps.extend([
        "Implement recommended security controls.",
        "Schedule a follow-up scan after remediation.",
    ])

    return {
        "generated_by": "template_fallback",
        "risk_level": risk_level,
        "overall_summary": f"Security assessment of {host} completed with a score of {score}/100 (Grade: {grade}). {risk_description}",
        "key_findings": key_findings,
        "finding_counts": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "total": len(findings)
        },
        "confidence_summary": confidence_summary,
        "recommendations": recommendations[:5],  # Top 5 recommendations
        "next_steps": next_steps[:4]
    }
