"""
SARIF Output Format for Security Scanner.

This module converts scanner findings to SARIF (Static Analysis Results
Interchange Format) for integration with GitHub Security tab, Azure DevOps,
and other tools that support SARIF.

SARIF Specification: https://sarifweb.azurewebsites.net/

Features:
- Full SARIF 2.1.0 compliance
- GitHub Security tab integration
- Severity mapping to SARIF levels
- CWE and OWASP mapping
- Rule definitions with help text

Usage:
    # Convert scanner report to SARIF
    sarif = convert_to_sarif(scanner_report)

    # Write to file
    with open("results.sarif", "w") as f:
        json.dump(sarif, f, indent=2)
"""

import hashlib
import json
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

# SARIF version
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

# Tool information
TOOL_NAME = "Security Scanner"
TOOL_VERSION = "1.0.0"
TOOL_INFO_URI = "https://github.com/anthropics/security-scanner"
TOOL_ORGANIZATION = "Security Scanner"

# Severity mapping: scanner severity -> SARIF level
SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "informational": "none",
}

# Severity mapping: scanner severity -> SARIF security-severity
SEVERITY_TO_SECURITY_SEVERITY = {
    "critical": "9.0",
    "high": "7.0",
    "medium": "5.0",
    "low": "3.0",
    "info": "1.0",
    "informational": "0.0",
}

# CWE to description mapping (common ones)
CWE_DESCRIPTIONS = {
    "CWE-79": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Improper Certificate Validation",
    "CWE-310": "Cryptographic Issues",
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-312": "Cleartext Storage of Sensitive Information",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-384": "Session Fixation",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-521": "Weak Password Requirements",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-601": "URL Redirection to Untrusted Site ('Open Redirect')",
    "CWE-611": "Improper Restriction of XML External Entity Reference",
    "CWE-614": "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
    "CWE-644": "Improper Neutralization of HTTP Headers for Scripting Syntax",
    "CWE-693": "Protection Mechanism Failure",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-829": "Inclusion of Functionality from Untrusted Control Sphere",
    "CWE-840": "Business Logic Errors",
    "CWE-915": "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-1021": "Improper Restriction of Rendered UI Layers or Frames",
}


def get_rule_id(finding: dict[str, Any]) -> str:
    """Generate a unique rule ID for a finding."""
    tool = finding.get("tool", "scanner")
    finding_id = finding.get("id", "unknown")

    # Extract base rule from finding ID (e.g., "xss:abc123" -> "xss")
    if ":" in finding_id:
        base_rule = finding_id.split(":")[0]
    else:
        base_rule = finding_id

    return f"{tool}/{base_rule}"


def get_cwe_id(finding: dict[str, Any]) -> str | None:
    """Extract CWE ID from finding."""
    cwe = finding.get("cwe")
    if cwe:
        if cwe.startswith("CWE-"):
            return cwe
        return f"CWE-{cwe}"
    return None


def create_rule(finding: dict[str, Any]) -> dict[str, Any]:
    """Create a SARIF rule definition from a finding."""
    rule_id = get_rule_id(finding)
    severity = finding.get("severity", "medium").lower()
    cwe_id = get_cwe_id(finding)

    rule = {
        "id": rule_id,
        "name": finding.get("title", "Security Finding"),
        "shortDescription": {
            "text": finding.get("title", "Security Finding")
        },
        "fullDescription": {
            "text": finding.get("description", finding.get("title", "Security finding detected"))
        },
        "help": {
            "text": finding.get("remediation", "Review and remediate this security finding."),
            "markdown": f"**Remediation:** {finding.get('remediation', 'Review and remediate this security finding.')}"
        },
        "defaultConfiguration": {
            "level": SEVERITY_TO_SARIF_LEVEL.get(severity, "warning")
        },
        "properties": {
            "security-severity": SEVERITY_TO_SECURITY_SEVERITY.get(severity, "5.0"),
            "tags": ["security"]
        }
    }

    # Add OWASP tag if present
    owasp = finding.get("owasp")
    if owasp:
        rule["properties"]["tags"].append("owasp-top-10")
        rule["properties"]["owasp"] = owasp

    # Add CWE information
    if cwe_id:
        rule["properties"]["tags"].append("cwe")
        rule["properties"]["cwe"] = cwe_id
        if cwe_id in CWE_DESCRIPTIONS:
            rule["helpUri"] = f"https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html"

    # Add CVSS score if present
    cvss = finding.get("cvss_score")
    if cvss:
        rule["properties"]["cvss"] = str(cvss)

    return rule


def create_result(finding: dict[str, Any], target_url: str) -> dict[str, Any]:
    """Create a SARIF result from a finding."""
    rule_id = get_rule_id(finding)
    severity = finding.get("severity", "medium").lower()

    result = {
        "ruleId": rule_id,
        "level": SEVERITY_TO_SARIF_LEVEL.get(severity, "warning"),
        "message": {
            "text": finding.get("description", finding.get("title", "Security finding"))
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": target_url,
                        "uriBaseId": "ROOTPATH"
                    }
                }
            }
        ],
        "partialFingerprints": {
            "primaryLocationLineHash": hashlib.sha256(
                f"{rule_id}:{target_url}:{finding.get('title', '')}".encode()
            ).hexdigest()[:16]
        }
    }

    # Add evidence if present
    evidence = finding.get("evidence")
    if evidence:
        if isinstance(evidence, dict):
            evidence_text = json.dumps(evidence, indent=2)
        else:
            evidence_text = str(evidence)
        result["message"]["text"] += f"\n\nEvidence:\n{evidence_text}"

    # Add snippet if URL is present in evidence
    if isinstance(evidence, dict):
        url = evidence.get("url") or evidence.get("endpoint")
        if url:
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = url

    # Add properties
    result["properties"] = {}

    # Add tool info
    if finding.get("tool"):
        result["properties"]["tool"] = finding["tool"]

    # Add CVSS
    if finding.get("cvss_score"):
        result["properties"]["cvss_score"] = finding["cvss_score"]

    # Add OWASP
    if finding.get("owasp"):
        result["properties"]["owasp"] = finding["owasp"]

    return result


def convert_to_sarif(
    report: dict[str, Any],
    include_passed: bool = False
) -> dict[str, Any]:
    """
    Convert scanner report to SARIF format.

    Args:
        report: Scanner report dictionary
        include_passed: Whether to include passed checks (default False)

    Returns:
        SARIF-formatted dictionary
    """
    # Get target information
    input_info = report.get("input", {})
    target = input_info.get("target", "unknown")
    host = input_info.get("normalized_host", urlparse(target).netloc or target)

    # Get findings
    findings = report.get("findings", [])

    # Build rules and results
    rules = {}
    results = []

    for finding in findings:
        # Create rule if not exists
        rule_id = get_rule_id(finding)
        if rule_id not in rules:
            rules[rule_id] = create_rule(finding)

        # Create result
        result = create_result(finding, target)
        results.append(result)

    # Build SARIF document
    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": TOOL_INFO_URI,
                        "organization": TOOL_ORGANIZATION,
                        "rules": list(rules.values())
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": report.get("timestamp_utc", datetime.now(UTC).isoformat())
                    }
                ],
                "originalUriBaseIds": {
                    "ROOTPATH": {
                        "uri": f"https://{host}/"
                    }
                }
            }
        ]
    }

    # Add scan metadata
    scan_metadata = report.get("scan_metadata", {})
    if scan_metadata:
        sarif["runs"][0]["properties"] = {
            "scan_id": scan_metadata.get("scan_id"),
            "target": target,
            "score": report.get("result", {}).get("score"),
            "grade": report.get("result", {}).get("grade")
        }

    return sarif


def sarif_summary(sarif: dict[str, Any]) -> dict[str, Any]:
    """
    Generate a summary of SARIF results.

    Returns counts by severity level.
    """
    summary = {
        "error": 0,
        "warning": 0,
        "note": 0,
        "none": 0,
        "total": 0
    }

    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            level = result.get("level", "warning")
            summary[level] = summary.get(level, 0) + 1
            summary["total"] += 1

    return summary


def quality_gate_check(
    sarif: dict[str, Any],
    max_critical: int = 0,
    max_high: int = 0,
    max_medium: int = -1,  # -1 means unlimited
    max_low: int = -1
) -> dict[str, Any]:
    """
    Check if scan results pass quality gates.

    Args:
        sarif: SARIF document
        max_critical: Maximum allowed critical findings (-1 for unlimited)
        max_high: Maximum allowed high findings (-1 for unlimited)
        max_medium: Maximum allowed medium findings (-1 for unlimited)
        max_low: Maximum allowed low findings (-1 for unlimited)

    Returns:
        Dictionary with pass/fail status and details
    """
    # Count by original severity (from properties)
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }

    for run in sarif.get("runs", []):
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            # Get security-severity score
            props = rule.get("properties", {})
            sec_severity = float(props.get("security-severity", "5.0"))

            # Count results for this rule
            rule_id = rule.get("id")
            rule_results = [r for r in run.get("results", []) if r.get("ruleId") == rule_id]

            # Map security-severity to category
            if sec_severity >= 9.0:
                counts["critical"] += len(rule_results)
            elif sec_severity >= 7.0:
                counts["high"] += len(rule_results)
            elif sec_severity >= 4.0:
                counts["medium"] += len(rule_results)
            elif sec_severity >= 1.0:
                counts["low"] += len(rule_results)
            else:
                counts["info"] += len(rule_results)

    # Check gates
    gates = {
        "critical": {"count": counts["critical"], "max": max_critical, "passed": True},
        "high": {"count": counts["high"], "max": max_high, "passed": True},
        "medium": {"count": counts["medium"], "max": max_medium, "passed": True},
        "low": {"count": counts["low"], "max": max_low, "passed": True},
    }

    for severity, gate in gates.items():
        if gate["max"] >= 0 and gate["count"] > gate["max"]:
            gate["passed"] = False

    overall_passed = all(g["passed"] for g in gates.values())

    return {
        "passed": overall_passed,
        "gates": gates,
        "counts": counts,
        "exit_code": 0 if overall_passed else 1
    }


def write_sarif_file(sarif: dict[str, Any], filepath: str) -> None:
    """Write SARIF document to file."""
    with open(filepath, "w") as f:
        json.dump(sarif, f, indent=2)


def generate_finding_fingerprint(finding: dict[str, Any]) -> str:
    """
    Generate a stable fingerprint for a finding.

    Used for baseline comparison - identifies the same finding across scans.
    """
    components = [
        finding.get("tool", ""),
        finding.get("id", "").split(":")[0] if ":" in finding.get("id", "") else finding.get("id", ""),
        finding.get("title", ""),
        finding.get("severity", ""),
    ]
    # Include specific evidence fields that identify the finding
    evidence = finding.get("evidence", {})
    if isinstance(evidence, dict):
        components.append(evidence.get("url", "") or evidence.get("endpoint", ""))

    fingerprint_str = "|".join(str(c) for c in components)
    return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:32]


def create_baseline(report: dict[str, Any]) -> dict[str, Any]:
    """
    Create a baseline from a scan report.

    A baseline records the fingerprints of all current findings,
    allowing future scans to suppress these known issues.

    Args:
        report: Scanner report dictionary

    Returns:
        Baseline dictionary with fingerprints and metadata
    """
    findings = report.get("findings", [])

    baseline = {
        "version": "1.0",
        "created_at": datetime.now(UTC).isoformat(),
        "target": report.get("input", {}).get("target", "unknown"),
        "findings_count": len(findings),
        "fingerprints": {},
        "metadata": {
            "score": report.get("result", {}).get("score"),
            "grade": report.get("result", {}).get("grade"),
        }
    }

    for finding in findings:
        fingerprint = generate_finding_fingerprint(finding)
        baseline["fingerprints"][fingerprint] = {
            "id": finding.get("id"),
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "tool": finding.get("tool"),
            "suppressed_at": datetime.now(UTC).isoformat(),
            "reason": "baseline"
        }

    return baseline


def load_baseline(filepath: str) -> dict[str, Any]:
    """Load a baseline from file."""
    with open(filepath) as f:
        return json.load(f)


def save_baseline(baseline: dict[str, Any], filepath: str) -> None:
    """Save a baseline to file."""
    with open(filepath, "w") as f:
        json.dump(baseline, f, indent=2)


def filter_by_baseline(
    report: dict[str, Any],
    baseline: dict[str, Any],
    include_suppressed: bool = False
) -> dict[str, Any]:
    """
    Filter scan findings against a baseline.

    Removes (or marks) findings that match the baseline fingerprints.

    Args:
        report: Scanner report dictionary
        baseline: Baseline dictionary with fingerprints
        include_suppressed: If True, include suppressed findings with marker

    Returns:
        Modified report with baseline-filtered findings
    """
    findings = report.get("findings", [])
    fingerprints = baseline.get("fingerprints", {})

    filtered_findings = []
    suppressed_findings = []

    for finding in findings:
        fingerprint = generate_finding_fingerprint(finding)

        if fingerprint in fingerprints:
            # Finding is in baseline
            if include_suppressed:
                finding = finding.copy()
                finding["suppressed"] = True
                finding["suppression_reason"] = fingerprints[fingerprint].get("reason", "baseline")
                finding["suppressed_at"] = fingerprints[fingerprint].get("suppressed_at")
                suppressed_findings.append(finding)
        else:
            # New finding not in baseline
            filtered_findings.append(finding)

    # Create modified report
    filtered_report = report.copy()
    filtered_report["findings"] = filtered_findings

    # Add baseline info to report
    filtered_report["baseline"] = {
        "applied": True,
        "baseline_target": baseline.get("target"),
        "baseline_created_at": baseline.get("created_at"),
        "total_findings": len(findings),
        "new_findings": len(filtered_findings),
        "suppressed_findings": len(findings) - len(filtered_findings),
    }

    if include_suppressed:
        filtered_report["suppressed_findings"] = suppressed_findings

    # Recalculate result based on new findings only
    if filtered_findings:
        severities = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in filtered_findings:
            sev = f.get("severity", "info").lower()
            if sev in severities:
                severities[sev] += 1

        filtered_report["baseline"]["new_by_severity"] = severities

    return filtered_report


def merge_baseline(
    existing_baseline: dict[str, Any],
    new_baseline: dict[str, Any]
) -> dict[str, Any]:
    """
    Merge a new baseline into an existing one.

    Combines fingerprints from both baselines, preserving
    original suppression dates for existing fingerprints.
    """
    merged = existing_baseline.copy()
    merged["fingerprints"] = existing_baseline.get("fingerprints", {}).copy()
    merged["updated_at"] = datetime.now(UTC).isoformat()

    for fingerprint, info in new_baseline.get("fingerprints", {}).items():
        if fingerprint not in merged["fingerprints"]:
            merged["fingerprints"][fingerprint] = info
            merged["findings_count"] = len(merged["fingerprints"])

    return merged


def prune_baseline(
    baseline: dict[str, Any],
    current_report: dict[str, Any]
) -> dict[str, Any]:
    """
    Remove baseline entries that no longer appear in scans.

    Useful for cleaning up baselines when issues are actually fixed.
    """
    findings = current_report.get("findings", [])
    current_fingerprints = {
        generate_finding_fingerprint(f) for f in findings
    }

    pruned = baseline.copy()
    pruned["fingerprints"] = {
        fp: info for fp, info in baseline.get("fingerprints", {}).items()
        if fp in current_fingerprints
    }
    pruned["findings_count"] = len(pruned["fingerprints"])
    pruned["pruned_at"] = datetime.now(UTC).isoformat()

    return pruned


# Export functions
__all__ = [
    "SARIF_VERSION",
    "convert_to_sarif",
    "create_baseline",
    "filter_by_baseline",
    "generate_finding_fingerprint",
    "load_baseline",
    "merge_baseline",
    "prune_baseline",
    "quality_gate_check",
    "sarif_summary",
    "save_baseline",
    "write_sarif_file",
]
