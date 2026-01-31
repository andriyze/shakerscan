"""
DOM XSS Source-Sink Analyzer

Lightweight static analysis for detecting DOM-based XSS vulnerabilities
by tracing data flow from dangerous sources to dangerous sinks.

This supplements dynamic XSS testing by identifying potential DOM XSS
vectors that may not be detected through traditional injection testing.

SECURITY NOTE: This is a security SCANNING tool. The patterns defined below
are DETECTION SIGNATURES used to find vulnerabilities in TARGET applications.
These are NOT insecure patterns in this scanner itself.
"""

import re
from dataclasses import dataclass
from typing import Any


# DOM XSS Sources - User-controllable input vectors (detection patterns)
DOM_XSS_SOURCES = {
    "location": {
        "patterns": [
            r"location\.href",
            r"location\.search",
            r"location\.hash",
            r"location\.pathname",
            r"location\.host",
            r"location\.hostname",
            r"location\.protocol",
            r"location\.origin",
        ],
        "risk": "high",
        "description": "URL components are directly controllable by attackers",
    },
    "document.URL": {
        # Note: document.baseURI is NOT user-controllable (set by <base> tag or page URL)
        # so it's excluded from sources to reduce false positives in framework code
        "patterns": [r"document\.URL", r"document\.documentURI"],
        "risk": "high",
        "description": "Document URL properties reflect the current page URL",
    },
    "document.referrer": {
        "patterns": [r"document\.referrer"],
        "risk": "medium",
        "description": "Referrer can be controlled by linking page",
    },
    "document.cookie": {
        "patterns": [r"document\.cookie"],
        "risk": "medium",
        "description": "Cookies may contain attacker-controlled data",
    },
    "window.name": {
        "patterns": [r"window\.name"],
        "risk": "high",
        "description": "window.name persists across navigations and can be set by other pages",
    },
    "postMessage": {
        "patterns": [r"\.addEventListener\s*\(\s*['\"]message['\"]", r"onmessage\s*="],
        "risk": "high",
        "description": "postMessage can receive data from any origin if not validated",
    },
    "localStorage": {
        "patterns": [r"localStorage\.getItem", r"localStorage\["],
        "risk": "medium",
        "description": "localStorage may contain previously stored attacker data",
    },
    "sessionStorage": {
        "patterns": [r"sessionStorage\.getItem", r"sessionStorage\["],
        "risk": "medium",
        "description": "sessionStorage may contain previously stored attacker data",
    },
    "URL_constructor": {
        "patterns": [r"new\s+URL\s*\(", r"URLSearchParams"],
        "risk": "medium",
        "description": "URL parsing may expose attacker-controlled parameters",
    },
    "input_elements": {
        "patterns": [
            r"\.value\b",
            r"\.innerHTML\b",
            r"\.textContent\b",
            r"\.innerText\b",
        ],
        "risk": "medium",
        "description": "DOM element values may contain attacker input",
    },
}

# DOM XSS Sinks - Dangerous output contexts (detection signatures for scanning)
# These patterns identify VULNERABLE code in target applications
DOM_XSS_SINKS = {
    "innerHTML_assign": {
        "patterns": [r"\.innerHTML\s*=", r"\.innerHTML\s*\+="],
        "risk": "critical",
        "description": "Direct HTML injection allows script execution",
    },
    "outerHTML_assign": {
        "patterns": [r"\.outerHTML\s*="],
        "risk": "critical",
        "description": "Direct HTML injection allows script execution",
    },
    "doc_write": {
        "patterns": [r"document\.write\s*\(", r"document\.writeln\s*\("],
        "risk": "critical",
        "description": "Allows arbitrary HTML/script injection",
    },
    "insertAdjacentHTML": {
        "patterns": [r"\.insertAdjacentHTML\s*\("],
        "risk": "critical",
        "description": "insertAdjacentHTML allows HTML injection",
    },
    "function_constructor": {
        "patterns": [r"\bFunction\s*\("],
        "risk": "critical",
        "description": "Direct JavaScript code execution via Function constructor",
    },
    "timer_string": {
        "patterns": [r"setTimeout\s*\(\s*['\"`]", r"setInterval\s*\(\s*['\"`]"],
        "risk": "critical",
        "description": "String argument to timer functions is executed as code",
    },
    "timer_var": {
        "patterns": [r"setTimeout\s*\(\s*\w+\s*,", r"setInterval\s*\(\s*\w+\s*,"],
        "risk": "high",
        "description": "Variable passed to timer may contain code",
    },
    "script_src": {
        "patterns": [r"\.src\s*=", r"script.*\.src"],
        "risk": "critical",
        "description": "Script src assignment can load attacker-controlled scripts",
    },
    "location_assign": {
        "patterns": [
            r"location\s*=",
            r"location\.href\s*=",
            r"location\.assign\s*\(",
            r"location\.replace\s*\(",
        ],
        "risk": "high",
        "description": "Location assignment can enable open redirect or javascript: URLs",
    },
    "window_open": {
        "patterns": [r"window\.open\s*\("],
        "risk": "high",
        "description": "window.open can navigate to javascript: URLs",
    },
    "href_assign": {
        "patterns": [r"\.href\s*="],
        "risk": "medium",
        "description": "Anchor href can be set to javascript: URL",
    },
    "jquery_html": {
        "patterns": [r"\$\([^)]+\)\.html\s*\(", r"\.html\s*\([^)]+\)"],
        "risk": "critical",
        "description": "jQuery .html() allows HTML injection",
    },
    "jquery_append": {
        "patterns": [
            r"\$\([^)]+\)\.append\s*\(",
            r"\$\([^)]+\)\.prepend\s*\(",
            r"\$\([^)]+\)\.after\s*\(",
            r"\$\([^)]+\)\.before\s*\(",
        ],
        "risk": "high",
        "description": "jQuery DOM manipulation can inject HTML",
    },
    "jquery_constructor": {
        "patterns": [r"\$\s*\(\s*['\"`]<", r"jQuery\s*\(\s*['\"`]<"],
        "risk": "high",
        "description": "jQuery constructor with HTML string creates DOM elements",
    },
    "angular_compile": {
        "patterns": [r"\$compile\s*\(", r"\$sce\.trustAsHtml", r"ng-bind-html"],
        "risk": "critical",
        "description": "Angular template compilation can execute code",
    },
    "react_unsafe": {
        "patterns": [r"SetInnerHTML"],
        "risk": "critical",
        "description": "React unsafe HTML setting bypasses XSS protection",
    },
    "vue_vhtml": {
        "patterns": [r"v-html\s*="],
        "risk": "critical",
        "description": "Vue v-html directive allows HTML injection",
    },
    "postmessage_send": {
        "patterns": [r"\.postMessage\s*\("],
        "risk": "medium",
        "description": "postMessage may leak sensitive data if target origin not verified",
    },
    "iframe_src": {
        "patterns": [r"iframe.*\.src\s*=", r"\.srcdoc\s*="],
        "risk": "high",
        "description": "iframe src/srcdoc can load attacker content",
    },
    "object_data": {
        "patterns": [r"object.*\.data\s*=", r"embed.*\.src\s*="],
        "risk": "high",
        "description": "Object/embed can load malicious content",
    },
}


@dataclass
class DOMXSSFinding:
    """Represents a potential DOM XSS vulnerability in target code."""
    source_type: str
    sink_type: str
    source_line: int
    sink_line: int
    source_code: str
    sink_code: str
    source_risk: str
    sink_risk: str
    data_flow: str
    confidence: str
    description: str


# Files to skip - known libraries/frameworks that produce false positives
LIBRARY_FILE_PATTERNS = [
    "vendor.", "vendor-", "vendors.",
    "angular.", "angular-", "angular/",
    "react.", "react-", "react/",
    "vue.", "vue-", "vue/",
    "jquery.", "jquery-", "jquery/",
    "lodash.", "lodash-",
    "moment.", "moment-",
    "rxjs.", "rxjs-", "rxjs/",
    "zone.", "zone-",
    "polyfill", "polyfills",
    "runtime.", "runtime-",
    "webpack-", "__webpack",
    "node_modules/",
    ".min.js",
    "chunk.", "chunks/",
]


def _is_library_file(filename: str) -> bool:
    """Check if file is a known library/framework that should be skipped."""
    filename_lower = filename.lower()
    return any(pattern in filename_lower for pattern in LIBRARY_FILE_PATTERNS)


def analyze_js_for_dom_xss(
    js_code: str,
    filename: str = "unknown",
    context_lines: int = 50,
) -> dict[str, Any]:
    """
    Analyze JavaScript code for potential DOM XSS vulnerabilities.

    Performs lightweight static analysis to identify source-sink pairs
    that could lead to DOM XSS in the target application.

    Args:
        js_code: JavaScript source code to analyze
        filename: Source filename for reporting
        context_lines: Number of lines to consider for data flow analysis

    Returns:
        Dict with findings and analysis results.
    """
    results: dict[str, Any] = {
        "filename": filename,
        "sources_found": [],
        "sinks_found": [],
        "potential_vulnerabilities": [],
        "high_risk_findings": [],
        "summary": {},
    }

    # Skip known library/framework files to reduce false positives
    # These files contain framework code that uses DOM APIs safely
    if _is_library_file(filename):
        results["skipped"] = True
        results["skip_reason"] = "library_file"
        return results

    lines = js_code.split("\n")

    # Phase 1: Identify all sources
    sources: list[dict[str, Any]] = []
    for source_name, source_info in DOM_XSS_SOURCES.items():
        for pattern in source_info["patterns"]:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    sources.append({
                        "type": source_name,
                        "line": i,
                        "code": line.strip()[:200],
                        "risk": source_info["risk"],
                        "pattern": pattern,
                    })

    results["sources_found"] = sources

    # Phase 2: Identify all sinks
    sinks: list[dict[str, Any]] = []
    for sink_name, sink_info in DOM_XSS_SINKS.items():
        for pattern in sink_info["patterns"]:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    sinks.append({
                        "type": sink_name,
                        "line": i,
                        "code": line.strip()[:200],
                        "risk": sink_info["risk"],
                        "pattern": pattern,
                    })

    results["sinks_found"] = sinks

    # Phase 3: Identify potential source-sink pairs
    findings: list[DOMXSSFinding] = []

    for source in sources:
        source_line = source["line"]

        for sink in sinks:
            sink_line = sink["line"]

            if abs(sink_line - source_line) > context_lines:
                continue

            if sink_line >= source_line:
                confidence = "medium"

                source_vars = set(re.findall(r"\b([a-zA-Z_$][a-zA-Z0-9_$]*)\b", source["code"]))
                sink_vars = set(re.findall(r"\b([a-zA-Z_$][a-zA-Z0-9_$]*)\b", sink["code"]))
                common_vars = source_vars & sink_vars - {"document", "window", "location", "var", "let", "const", "function", "if", "else", "return", "true", "false", "null", "undefined"}

                if common_vars:
                    confidence = "high"
                    data_flow = f"Potential flow through: {', '.join(list(common_vars)[:3])}"
                else:
                    data_flow = "Proximity-based detection"

                if source["risk"] == "high" and sink["risk"] == "critical":
                    confidence = "high"

                finding = DOMXSSFinding(
                    source_type=source["type"],
                    sink_type=sink["type"],
                    source_line=source_line,
                    sink_line=sink_line,
                    source_code=source["code"],
                    sink_code=sink["code"],
                    source_risk=source["risk"],
                    sink_risk=sink["risk"],
                    data_flow=data_flow,
                    confidence=confidence,
                    description=f"Potential DOM XSS: {source['type']} -> {sink['type']}",
                )
                findings.append(finding)

    results["potential_vulnerabilities"] = [
        {
            "source_type": f.source_type,
            "sink_type": f.sink_type,
            "source_line": f.source_line,
            "sink_line": f.sink_line,
            "source_code": f.source_code,
            "sink_code": f.sink_code,
            "data_flow": f.data_flow,
            "confidence": f.confidence,
            "combined_risk": _combine_risk(f.source_risk, f.sink_risk),
            "description": f.description,
        }
        for f in findings
    ]

    results["high_risk_findings"] = [
        f for f in results["potential_vulnerabilities"]
        if f["combined_risk"] in ("critical", "high") and f["confidence"] == "high"
    ]

    results["summary"] = {
        "total_sources": len(sources),
        "total_sinks": len(sinks),
        "potential_vulnerabilities": len(findings),
        "high_risk_count": len(results["high_risk_findings"]),
        "unique_source_types": list(set(s["type"] for s in sources)),
        "unique_sink_types": list(set(s["type"] for s in sinks)),
    }

    return results


def _combine_risk(source_risk: str, sink_risk: str) -> str:
    """Combine source and sink risk levels."""
    risk_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    max_risk = max(risk_order.get(source_risk, 1), risk_order.get(sink_risk, 1))
    for risk, level in risk_order.items():
        if level == max_risk:
            return risk
    return "medium"


def analyze_url_for_dom_xss(
    url: str,
    html_content: str,
) -> dict[str, Any]:
    """
    Analyze a page's HTML and inline scripts for DOM XSS.

    Args:
        url: Page URL
        html_content: Full HTML content of the page

    Returns:
        Dict with analysis results.
    """
    results: dict[str, Any] = {
        "url": url,
        "inline_scripts_analyzed": 0,
        "findings": [],
        "summary": {},
    }

    script_pattern = r"<script[^>]*>(.*?)</script>"
    scripts = re.findall(script_pattern, html_content, re.DOTALL | re.IGNORECASE)

    all_findings: list[dict] = []

    for i, script in enumerate(scripts):
        if not script.strip():
            continue

        results["inline_scripts_analyzed"] += 1

        analysis = analyze_js_for_dom_xss(
            script,
            filename=f"{url}:inline_script_{i}",
        )

        if analysis["potential_vulnerabilities"]:
            all_findings.extend(analysis["potential_vulnerabilities"])

    seen = set()
    unique_findings = []
    for f in all_findings:
        key = (f["source_type"], f["sink_type"], f["source_line"], f["sink_line"])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    results["findings"] = unique_findings
    results["summary"] = {
        "scripts_analyzed": results["inline_scripts_analyzed"],
        "total_findings": len(unique_findings),
        "high_risk_findings": len([f for f in unique_findings if f["combined_risk"] in ("critical", "high")]),
    }

    return results


def check_postmessage_security(js_code: str) -> dict[str, Any]:
    """
    Check for insecure postMessage implementations.

    Args:
        js_code: JavaScript code to analyze

    Returns:
        Dict with postMessage security findings.
    """
    findings: list[dict[str, Any]] = []

    listener_pattern = r"\.addEventListener\s*\(\s*['\"]message['\"][^}]+\}"
    matches = re.findall(listener_pattern, js_code, re.DOTALL | re.IGNORECASE)

    for match in matches:
        has_origin_check = bool(re.search(r"\.origin\s*[!=]==", match))

        if not has_origin_check:
            findings.append({
                "type": "postMessage_no_origin_check",
                "severity": "high",
                "description": "postMessage listener does not validate message origin",
                "code_snippet": match[:200],
                "recommendation": "Always validate event.origin before processing postMessage data",
            })

        for sink_name, sink_info in DOM_XSS_SINKS.items():
            for pattern in sink_info["patterns"]:
                if re.search(pattern, match):
                    findings.append({
                        "type": f"postMessage_to_{sink_name}",
                        "severity": sink_info["risk"],
                        "description": f"postMessage data used in dangerous sink: {sink_name}",
                        "code_snippet": match[:200],
                        "recommendation": f"Sanitize postMessage data before using in {sink_name}",
                    })

    return {
        "postmessage_handlers": len(matches),
        "findings": findings,
        "secure_handlers": len(matches) - len([f for f in findings if "no_origin_check" in f["type"]]),
    }


def generate_dom_xss_report(analysis_results: dict[str, Any]) -> str:
    """
    Generate a human-readable report from DOM XSS analysis.

    Args:
        analysis_results: Results from analyze_js_for_dom_xss or analyze_url_for_dom_xss

    Returns:
        Formatted report string.
    """
    lines = []
    lines.append("=" * 60)
    lines.append("DOM XSS ANALYSIS REPORT")
    lines.append("=" * 60)

    if "filename" in analysis_results:
        lines.append(f"\nFile: {analysis_results['filename']}")
    if "url" in analysis_results:
        lines.append(f"\nURL: {analysis_results['url']}")

    summary = analysis_results.get("summary", {})
    lines.append(f"\nSources Found: {summary.get('total_sources', 0)}")
    lines.append(f"Sinks Found: {summary.get('total_sinks', 0)}")
    lines.append(f"Potential Vulnerabilities: {summary.get('potential_vulnerabilities', 0)}")
    lines.append(f"High Risk Findings: {summary.get('high_risk_count', 0)}")

    if analysis_results.get("high_risk_findings"):
        lines.append("\n" + "-" * 40)
        lines.append("HIGH RISK FINDINGS")
        lines.append("-" * 40)

        for finding in analysis_results["high_risk_findings"]:
            lines.append(f"\n[{finding['combined_risk'].upper()}] {finding['description']}")
            lines.append(f"  Source: {finding['source_type']} (line {finding['source_line']})")
            lines.append(f"  Sink: {finding['sink_type']} (line {finding['sink_line']})")
            lines.append(f"  Data Flow: {finding['data_flow']}")
            lines.append(f"  Confidence: {finding['confidence']}")

    return "\n".join(lines)
