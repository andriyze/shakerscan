"""
Finding Deduplication Engine - Eliminate noise, deliver signal.

This module provides intelligent deduplication of security findings to reduce
noise while preserving actionable signal. It consolidates related findings
from multiple tools into unified, evidence-rich reports.

Philosophy: "One finding per vulnerability, with all evidence consolidated."

Key Features:
1. Cross-tool deduplication (dalfox + nuclei XSS → single finding)
2. Same-endpoint consolidation (GraphQL introspection + depth limit → one finding)
3. Evidence merging (keep all payloads, URLs, responses)
4. Severity promotion (keep highest severity from duplicates)
5. Confidence aggregation (multiple tools = higher confidence)
"""

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse


# =============================================================================
# DEDUPLICATION STRATEGIES
# =============================================================================

@dataclass
class DeduplicationConfig:
    """Configuration for deduplication behavior."""
    # Enable/disable specific dedup strategies
    cross_tool_dedup: bool = True
    same_endpoint_dedup: bool = True
    same_cwe_dedup: bool = True
    subdomain_rollup: bool = False  # Conservative default

    # Thresholds
    title_similarity_threshold: float = 0.8
    max_evidence_items: int = 10

    # Tool groupings for cross-tool dedup
    xss_tools: frozenset = frozenset(["dalfox", "nuclei", "xss_scanner", "xsstrike"])
    sqli_tools: frozenset = frozenset(["sqlmap", "nuclei", "sqli_scanner"])
    cors_tools: frozenset = frozenset(["cors_check", "cors_scanner", "nuclei"])


@dataclass
class FindingGroup:
    """A group of related findings to be consolidated."""
    key: str  # Grouping key (e.g., "CWE-79:/search")
    findings: list[dict] = field(default_factory=list)
    primary: dict | None = None  # The finding to keep after dedup
    merged_evidence: list[dict] = field(default_factory=list)
    tools_involved: set = field(default_factory=set)

    def add(self, finding: dict) -> None:
        """Add a finding to this group."""
        self.findings.append(finding)
        tool = finding.get("tool", "unknown")
        self.tools_involved.add(tool)


# =============================================================================
# GROUPING KEY EXTRACTION
# =============================================================================

def _template_endpoint_path(path: str) -> str:
    """Template volatile id segments (/orders/1 -> /orders/{id}) so per-object-id
    findings group together in-scan, matching the DB fingerprint (docs §5)."""
    try:
        from findings import template_path
        return template_path(path)
    except Exception:
        return path


def extract_endpoint(finding: dict) -> str | None:
    """Extract the endpoint/URL from a finding's evidence (path, id-templated)."""
    evidence = finding.get("evidence", {})
    if isinstance(evidence, dict):
        # Try common evidence keys
        for key in ["url", "endpoint", "path", "target", "affected_url"]:
            if key in evidence:
                val = evidence[key]
                if isinstance(val, str):
                    # Normalize URL to path only, then template volatile id segments
                    try:
                        parsed = urlparse(val)
                        return _template_endpoint_path(parsed.path or "/")
                    except Exception:
                        return val
        # Check nested evidence
        if "details" in evidence and isinstance(evidence["details"], dict):
            for key in ["url", "endpoint", "path"]:
                if key in evidence["details"]:
                    return _template_endpoint_path(str(evidence["details"][key]))
    return None


def extract_vulnerability_type(finding: dict) -> str:
    """Extract normalized vulnerability type from finding."""
    title = finding.get("title", "").lower()
    cwe = finding.get("cwe", "")

    # Map common vulnerability patterns to normalized types
    vuln_patterns = {
        "xss": ["xss", "cross-site scripting", "cross site scripting"],
        "sqli": ["sql injection", "sqli", "sql-injection"],
        "nosql": ["nosql injection", "mongodb injection", "nosql-injection"],
        "cors": ["cors", "cross-origin"],
        "ssrf": ["ssrf", "server-side request"],
        "xxe": ["xxe", "xml external entity"],
        "csrf": ["csrf", "cross-site request forgery"],
        "idor": ["idor", "insecure direct object", "bola"],
        "path_traversal": ["path traversal", "directory traversal", "lfi", "rfi"],
        "open_redirect": ["open redirect", "url redirect"],
        "file_upload": ["file upload", "unrestricted upload"],
        "graphql": ["graphql"],
        "exposed_file": ["exposed file", "exposed config", "sensitive file"],
        "default_creds": ["default credential", "default password"],
        "auth_bypass": ["authentication bypass", "auth bypass"],
    }

    for vuln_type, patterns in vuln_patterns.items():
        if any(p in title for p in patterns):
            return vuln_type

    # Fall back to CWE-based classification
    cwe_mapping = {
        "CWE-79": "xss",
        "CWE-89": "sqli",
        "CWE-943": "nosql",
        "CWE-942": "cors",
        "CWE-918": "ssrf",
        "CWE-611": "xxe",
        "CWE-352": "csrf",
        "CWE-639": "idor",
        "CWE-22": "path_traversal",
        "CWE-601": "open_redirect",
        "CWE-434": "file_upload",
        "CWE-200": "info_disclosure",
        "CWE-287": "auth_bypass",
    }

    if cwe in cwe_mapping:
        return cwe_mapping[cwe]

    return "other"


def generate_grouping_key(finding: dict, strategy: str = "cwe_endpoint") -> str:
    """
    Generate a grouping key for deduplication.

    Strategies:
    - cwe_endpoint: Group by CWE + endpoint (most specific)
    - vuln_type_endpoint: Group by vulnerability type + endpoint
    - cwe_only: Group by CWE only (aggressive)
    - endpoint_only: Group by endpoint only (very aggressive)

    NOTE: Non-endpoint findings (headers, TLS, DNS, config) use a more specific
    key to prevent distinct issues from being incorrectly merged.
    """
    cwe = finding.get("cwe", "unknown")
    endpoint = extract_endpoint(finding)
    vuln_type = extract_vulnerability_type(finding)
    tool = finding.get("tool", "unknown")
    title = finding.get("title", "")

    # For non-endpoint findings, use cwe:title_hash to keep distinct issues separate
    # but still allow same-issue dedup across tools (e.g., HSTS from scanner + nuclei)
    # This prevents "Missing HSTS", "Missing CSP", "Weak TLS" from collapsing together
    # while allowing "Missing HSTS" from different tools to deduplicate
    if endpoint is None:
        # Use title hash to distinguish different issues (without tool, so same-title dedupes)
        title_hash = hashlib.sha256(title.encode()).hexdigest()[:8]
        return f"{cwe}:{title_hash}"

    if strategy == "cwe_endpoint":
        return f"{cwe}:{endpoint}"
    elif strategy == "vuln_type_endpoint":
        return f"{vuln_type}:{endpoint}"
    elif strategy == "cwe_only":
        return cwe
    elif strategy == "endpoint_only":
        return endpoint
    elif strategy == "tool_endpoint":
        return f"{tool}:{endpoint}"
    else:
        return f"{cwe}:{endpoint}"


# =============================================================================
# SEVERITY AND CONFIDENCE HANDLING
# =============================================================================

SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def compare_severity(s1: str, s2: str) -> int:
    """Compare two severities. Returns positive if s1 > s2."""
    return SEVERITY_ORDER.get(s1.lower(), 0) - SEVERITY_ORDER.get(s2.lower(), 0)


def select_primary_finding(group: FindingGroup) -> dict:
    """
    Select the primary finding from a group of duplicates.

    Selection criteria (in order):
    1. Highest severity
    2. Highest CVSS score
    3. Highest confidence (from confidence or ai_confidence fields)
    4. Most evidence
    5. First found (deterministic ordering)
    """
    if not group.findings:
        return {}

    if len(group.findings) == 1:
        return group.findings[0]

    def score_finding(f: dict) -> tuple:
        severity = SEVERITY_ORDER.get(f.get("severity", "info").lower(), 0)
        cvss = f.get("cvss_score", 0) or 0
        # Use confidence field first (new), fall back to ai_confidence (legacy)
        confidence = f.get("confidence") or f.get("ai_confidence", 0.5) or 0.5
        evidence_size = len(str(f.get("evidence", {})))
        # Return tuple for multi-criteria sorting (higher is better)
        return (severity, cvss, confidence, evidence_size)

    # Sort by score (descending) and pick best
    sorted_findings = sorted(group.findings, key=score_finding, reverse=True)
    return sorted_findings[0]


# =============================================================================
# EVIDENCE MERGING
# =============================================================================

def merge_evidence(findings: list[dict], max_items: int = 10) -> dict:
    """
    Merge evidence from multiple findings into a consolidated evidence dict.

    Keeps unique payloads, URLs, response snippets, and tool-specific metadata.
    """
    merged = {
        "payloads": [],
        "urls": [],
        "response_snippets": [],
        "tools": [],
        "additional": [],
        "tool_metadata": [],  # Preserve tool-specific evidence from each finding
    }

    seen_payloads = set()
    seen_urls = set()

    # Tool-specific fields to preserve (Nuclei, scanner, etc.)
    TOOL_SPECIFIC_FIELDS = [
        "template_id", "template_name", "tags", "matcher_name", "matcher_status",
        "remediation", "reference", "references", "curl_command", "request",
        "description", "severity_source", "cve", "cvss", "extracted_results"
    ]

    for finding in findings:
        evidence = finding.get("evidence", {})
        tool = finding.get("tool", "unknown")

        if tool not in merged["tools"]:
            merged["tools"].append(tool)

        # Preserve tool-specific metadata
        if isinstance(evidence, dict):
            tool_meta = {"tool": tool}
            for field in TOOL_SPECIFIC_FIELDS:
                if field in evidence and evidence[field]:
                    tool_meta[field] = evidence[field]
            # Also check top-level finding fields
            for field in TOOL_SPECIFIC_FIELDS:
                if field in finding and finding[field] and field not in tool_meta:
                    tool_meta[field] = finding[field]
            if len(tool_meta) > 1:  # Has more than just "tool"
                merged["tool_metadata"].append(tool_meta)

        if isinstance(evidence, dict):
            # Extract payloads
            for key in ["payload", "payloads", "attack_payload"]:
                if key in evidence:
                    val = evidence[key]
                    if isinstance(val, list):
                        for p in val[:5]:  # Limit per finding
                            p_str = str(p)
                            if p_str not in seen_payloads:
                                seen_payloads.add(p_str)
                                merged["payloads"].append(p_str)
                    elif val and str(val) not in seen_payloads:
                        seen_payloads.add(str(val))
                        merged["payloads"].append(str(val))

            # Extract URLs
            for key in ["url", "urls", "endpoint", "target"]:
                if key in evidence:
                    val = evidence[key]
                    if isinstance(val, list):
                        for u in val[:5]:
                            if u not in seen_urls:
                                seen_urls.add(u)
                                merged["urls"].append(u)
                    elif val and val not in seen_urls:
                        seen_urls.add(val)
                        merged["urls"].append(val)

            # Extract response snippets
            for key in ["response_snippet", "response", "body_sample"]:
                if key in evidence and evidence[key]:
                    snippet = str(evidence[key])[:500]
                    if len(merged["response_snippets"]) < 3:
                        merged["response_snippets"].append(snippet)

    # Trim to max items
    merged["payloads"] = merged["payloads"][:max_items]
    merged["urls"] = merged["urls"][:max_items]

    return merged


# =============================================================================
# MAIN DEDUPLICATION ENGINE
# =============================================================================

def deduplicate_findings(
    findings: list[dict],
    config: DeduplicationConfig | None = None
) -> list[dict]:
    """
    Main deduplication function - consolidate related findings.

    Args:
        findings: List of raw findings from various tools
        config: Deduplication configuration

    Returns:
        Deduplicated list of findings with merged evidence
    """
    if not findings:
        return []

    if config is None:
        config = DeduplicationConfig()

    # Step 1: Group findings by key
    groups: dict[str, FindingGroup] = {}

    for finding in findings:
        # Skip excluded findings
        if finding.get("excluded"):
            continue

        # Generate grouping key based on strategy
        if config.same_cwe_dedup:
            key = generate_grouping_key(finding, "cwe_endpoint")
        else:
            key = generate_grouping_key(finding, "tool_endpoint")

        if key not in groups:
            groups[key] = FindingGroup(key=key)

        groups[key].add(finding)

    # Step 2: Process each group
    deduplicated = []

    for group_key, group in groups.items():
        if len(group.findings) == 1:
            # No deduplication needed
            deduplicated.append(group.findings[0])
        else:
            # Select primary and merge evidence
            primary = select_primary_finding(group)

            # Create consolidated finding
            consolidated = primary.copy()

            # Merge evidence from all findings in group
            merged_evidence = merge_evidence(group.findings, config.max_evidence_items)

            # Update evidence with merged data
            original_evidence = consolidated.get("evidence", {})
            if isinstance(original_evidence, dict):
                merged_update = {
                    **original_evidence,
                    "merged_from_tools": merged_evidence["tools"],
                    "all_payloads": merged_evidence["payloads"],
                    "all_urls": merged_evidence["urls"],
                    "duplicate_count": len(group.findings),
                }
                # Include tool-specific metadata from all findings (not just primary)
                if merged_evidence.get("tool_metadata"):
                    merged_update["tool_metadata"] = merged_evidence["tool_metadata"]
                consolidated["evidence"] = merged_update

            # Update title to indicate consolidation
            if len(group.findings) > 1:
                original_title = consolidated.get("title", "")
                if "(" not in original_title or "occurrence" not in original_title.lower():
                    consolidated["title"] = f"{original_title} ({len(group.findings)} occurrences)"

            # Add dedup metadata
            consolidated["deduplication"] = {
                "consolidated": True,
                "original_count": len(group.findings),
                "tools_involved": list(group.tools_involved),
                "grouping_key": group_key,
            }

            deduplicated.append(consolidated)

    # Step 3: Cross-tool deduplication for same vulnerability type
    if config.cross_tool_dedup:
        deduplicated = _cross_tool_dedup(deduplicated, config)

    return deduplicated


def _cross_tool_dedup(findings: list[dict], config: DeduplicationConfig) -> list[dict]:
    """
    Additional pass to deduplicate across tools for same vulnerability.

    Example: dalfox and nuclei both find XSS on /search → keep dalfox (more trusted)

    NOTE: Non-endpoint findings are skipped from cross-tool dedup to prevent
    distinct config/header/DNS issues from being incorrectly merged.
    """
    # Group by vulnerability type + endpoint
    vuln_groups: dict[str, list[dict]] = {}
    # Non-endpoint findings go directly to result (no cross-tool dedup)
    non_endpoint_findings: list[dict] = []

    for finding in findings:
        endpoint = extract_endpoint(finding)
        # Skip cross-tool dedup for non-endpoint findings (headers, TLS, DNS, config)
        if endpoint is None:
            non_endpoint_findings.append(finding)
            continue

        vuln_type = extract_vulnerability_type(finding)
        key = f"{vuln_type}:{endpoint}"

        if key not in vuln_groups:
            vuln_groups[key] = []
        vuln_groups[key].append(finding)

    # Tool priority (higher = more trusted for that vuln type)
    tool_priority = {
        "dalfox": {"xss": 10},
        "sqlmap": {"sqli": 10},
        "nuclei": {"xss": 5, "sqli": 5, "ssrf": 7, "xxe": 7},
        "nosql_injection": {"nosql": 8},
        "cors_check": {"cors": 8},
        "graphql_vulnerability": {"graphql": 9},
        "exposed_files": {"exposed_file": 9},
    }

    result = []

    for key, group in vuln_groups.items():
        if len(group) == 1:
            result.append(group[0])
        else:
            # Multiple tools found same vuln - select best
            vuln_type = key.split(":")[0]

            def tool_score(f: dict) -> int:
                tool = f.get("tool", "")
                priorities = tool_priority.get(tool, {})
                return priorities.get(vuln_type, 0)

            # Sort by tool priority (descending), then by existing score
            sorted_group = sorted(
                group,
                key=lambda f: (
                    tool_score(f),
                    SEVERITY_ORDER.get(f.get("severity", "info").lower(), 0),
                    f.get("cvss_score", 0) or 0
                ),
                reverse=True
            )

            primary = sorted_group[0].copy()

            # Note that other tools also found this
            if len(sorted_group) > 1:
                other_tools = [f.get("tool") for f in sorted_group[1:]]
                evidence = primary.get("evidence", {})
                if isinstance(evidence, dict):
                    primary["evidence"] = {
                        **evidence,
                        "also_found_by": other_tools,
                    }

            result.append(primary)

    # Include non-endpoint findings that were skipped from cross-tool dedup
    return result + non_endpoint_findings


# =============================================================================
# GRAPHQL-SPECIFIC CONSOLIDATION
# =============================================================================

def consolidate_graphql_findings(findings: list[dict]) -> list[dict]:
    """
    Consolidate multiple GraphQL findings for same endpoint into one.

    Example: introspection_enabled + no_depth_limit + field_suggestions
    → "GraphQL Security Issues (3 issues found)"
    """
    graphql_findings = [f for f in findings if "graphql" in f.get("tool", "").lower()]
    other_findings = [f for f in findings if "graphql" not in f.get("tool", "").lower()]

    if len(graphql_findings) <= 1:
        return findings

    # Group by endpoint
    endpoint_groups: dict[str, list[dict]] = {}
    for f in graphql_findings:
        endpoint = extract_endpoint(f) or "/graphql"
        if endpoint not in endpoint_groups:
            endpoint_groups[endpoint] = []
        endpoint_groups[endpoint].append(f)

    consolidated_graphql = []
    for endpoint, group in endpoint_groups.items():
        if len(group) == 1:
            consolidated_graphql.append(group[0])
        else:
            # Consolidate into single finding
            issues = []
            max_severity = "info"
            max_cvss = 0.0

            for f in group:
                title = f.get("title", "")
                # Extract issue type from title
                if "introspection" in title.lower():
                    issues.append("introspection_enabled")
                elif "depth" in title.lower():
                    issues.append("no_depth_limit")
                elif "suggestion" in title.lower():
                    issues.append("field_suggestions")
                elif "batch" in title.lower():
                    issues.append("batching_enabled")
                else:
                    issues.append(title)

                if compare_severity(f.get("severity", "info"), max_severity) > 0:
                    max_severity = f.get("severity", "info")

                cvss = f.get("cvss_score", 0) or 0
                if cvss > max_cvss:
                    max_cvss = cvss

            # Select primary finding (highest severity) to preserve its metadata
            primary = max(group, key=lambda f: (
                SEVERITY_ORDER.get(f.get("severity", "info").lower(), 0),
                f.get("cvss_score", 0) or 0,
                f.get("confidence", 0.5) or 0.5
            ))

            # Merge metadata from all findings, but only for fields NOT already in primary
            # This ensures we don't overwrite primary's confidence/ai_verdict with weaker values
            metadata_fields = [
                "first_seen", "confidence", "confidence_tier", "ai_verdict",
                "ai_confidence", "soc2", "cwe_name", "remediation"
            ]

            # Start with primary's metadata
            consolidated = primary.copy()

            # Only fill in missing fields from other findings (don't overwrite primary)
            for field in metadata_fields:
                if consolidated.get(field) is None:
                    for f in group:
                        val = f.get(field)
                        if val is not None:
                            consolidated[field] = val
                            break
            consolidated.update({
                "id": f"graphql_consolidated:{hashlib.sha256(endpoint.encode()).hexdigest()[:8]}",
                "tool": "graphql_vulnerability",
                "title": f"GraphQL Security Issues on {endpoint} ({len(issues)} issues)",
                "severity": max_severity,
                "cvss_score": max_cvss,
                "cwe": "CWE-200",
                "owasp": "A05:2021 - Security Misconfiguration",
                "evidence": {
                    "endpoint": endpoint,
                    "issues": issues,
                    "issue_count": len(issues),
                    "consolidated_from": len(group),
                },
                "deduplication": {
                    "consolidated": True,
                    "original_count": len(group),
                    "issue_types": issues,
                },
            })

            consolidated_graphql.append(consolidated)

    return other_findings + consolidated_graphql


# =============================================================================
# PUBLIC API
# =============================================================================

def run_deduplication_pipeline(
    findings: list[dict],
    aggressive: bool = False
) -> list[dict]:
    """
    Run the full deduplication pipeline on findings.

    Args:
        findings: Raw findings list
        aggressive: If True, use more aggressive deduplication

    Returns:
        Deduplicated findings list
    """
    if not findings:
        return []

    # Configure based on mode
    config = DeduplicationConfig(
        cross_tool_dedup=True,
        same_endpoint_dedup=True,
        same_cwe_dedup=True,
        subdomain_rollup=aggressive,
    )

    # Step 1: GraphQL-specific consolidation
    findings = consolidate_graphql_findings(findings)

    # Step 2: General deduplication
    findings = deduplicate_findings(findings, config)

    return findings
