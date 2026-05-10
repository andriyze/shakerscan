import json
import os
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from .common import get_auth_curl_args, now_utc_iso, run
from .signal_types import SEVERITY_WEIGHTS, calculate_weighted_score


@dataclass
class WaveBudget:
    """
    Configuration for yield-based wave budget management.

    Instead of fixed timeouts, waves can exit early if yield drops below
    threshold, or continue longer if yield is high.
    """
    max_duration: int = 120       # Hard cap in seconds
    min_duration: int = 30        # Minimum run time before yield check
    yield_threshold: float = 0.5  # Findings/min threshold for early exit
    extend_on_high_yield: bool = True  # Extend timeout if yield is high
    high_yield_threshold: float = 2.0  # Findings/min to extend timeout
    extension_factor: float = 1.5      # Multiply timeout if high yield

    @classmethod
    def wave1(cls) -> "WaveBudget":
        """Wave 1: Quick critical scan - short timeout."""
        return cls(max_duration=45, min_duration=15, yield_threshold=0.3)

    @classmethod
    def wave2(cls) -> "WaveBudget":
        """Wave 2: Signal expansion - medium timeout."""
        return cls(max_duration=90, min_duration=30, yield_threshold=0.4)

    @classmethod
    def wave3(cls) -> "WaveBudget":
        """Wave 3: Injection focused - longer timeout for complex templates."""
        return cls(max_duration=180, min_duration=45, yield_threshold=0.3)

    @classmethod
    def wave4(cls) -> "WaveBudget":
        """Wave 4: Deep scan - longest timeout."""
        return cls(max_duration=300, min_duration=60, yield_threshold=0.2)


@dataclass
class YieldMetrics:
    """Tracks yield metrics for a Nuclei wave."""
    findings_count: int = 0
    duration_seconds: float = 0.0
    templates_run: int = 0

    @property
    def findings_per_minute(self) -> float:
        """Calculate findings per minute."""
        if self.duration_seconds <= 0:
            return 0.0
        return self.findings_count / (self.duration_seconds / 60.0)

    @property
    def is_high_yield(self) -> bool:
        """Check if yield is above high threshold."""
        return self.findings_per_minute >= 2.0

    @property
    def is_low_yield(self) -> bool:
        """Check if yield is below minimum threshold."""
        return self.findings_per_minute < 0.3

    def should_continue(self, budget: WaveBudget) -> bool:
        """Determine if wave should continue based on yield."""
        if self.duration_seconds < budget.min_duration:
            return True  # Always run minimum duration
        if self.duration_seconds >= budget.max_duration:
            return False  # Never exceed max
        if self.findings_per_minute < budget.yield_threshold:
            return False  # Yield too low
        return True


def calculate_yield_metrics(findings: list[dict], duration_seconds: float) -> YieldMetrics:
    """Calculate yield metrics from wave results."""
    return YieldMetrics(
        findings_count=len(findings),
        duration_seconds=duration_seconds,
    )


def adjust_next_wave_budget(
    current_metrics: YieldMetrics,
    base_budget: WaveBudget,
    signals: dict
) -> WaveBudget:
    """
    Adjust budget for next wave based on current wave yield.

    If current wave had high yield, extend next wave timeout.
    If current wave had low yield, reduce next wave timeout.
    """
    adjusted = WaveBudget(
        max_duration=base_budget.max_duration,
        min_duration=base_budget.min_duration,
        yield_threshold=base_budget.yield_threshold,
        extend_on_high_yield=base_budget.extend_on_high_yield,
        high_yield_threshold=base_budget.high_yield_threshold,
        extension_factor=base_budget.extension_factor,
    )

    # Adjust based on previous wave yield
    if current_metrics.is_high_yield and base_budget.extend_on_high_yield:
        # High yield - extend timeout for next wave
        adjusted.max_duration = int(base_budget.max_duration * base_budget.extension_factor)
        print(f"[nuclei] High yield ({current_metrics.findings_per_minute:.1f}/min) - extending next wave to {adjusted.max_duration}s", file=sys.stderr)
    elif current_metrics.is_low_yield:
        # Low yield - reduce timeout for next wave
        if current_metrics.findings_count == 0:
            adjusted.max_duration = adjusted.min_duration
        else:
            adjusted.max_duration = max(adjusted.min_duration + 10, int(base_budget.max_duration * 0.6))
        print(f"[nuclei] Low yield ({current_metrics.findings_per_minute:.1f}/min) - reducing next wave to {adjusted.max_duration}s", file=sys.stderr)

    # Boost if signals suggest more to find
    if signals.get("sql_errors") or signals.get("xss_reflection") or signals.get("rce_potential"):
        adjusted.max_duration = min(600, int(adjusted.max_duration * 1.2))

    return adjusted


def _normalize_tech_list(detected_tech: list | None) -> list[str]:
    """
    Normalize detected_tech to a list of lowercase strings.

    Handles both:
    - List of strings: ["React", "Express"]
    - List of dicts: [{"name": "React", "version": "18.2.0"}, ...]

    Returns:
        List of lowercase technology names
    """
    if not detected_tech:
        return []

    normalized = []
    for tech in detected_tech:
        if isinstance(tech, dict):
            # Dict format from enhanced fingerprinting
            name = tech.get("name", "")
            if name:
                normalized.append(str(name).lower().strip())
        elif isinstance(tech, str):
            # String format
            normalized.append(tech.lower().strip())
        else:
            # Try to convert to string
            try:
                normalized.append(str(tech).lower().strip())
            except Exception:
                pass

    return [t for t in normalized if t]  # Filter empty strings


_STATIC_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".map",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".mp3", ".avi",
    ".mov", ".zip", ".tar", ".gz", ".rar", ".7z", ".pdf",
}


def _normalize_targets(base_url: str, targets: list[str] | None, max_targets: int | None = None) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()

    def _add(url: str):
        if not url or url in seen:
            return
        seen.add(url)
        normalized.append(url)

    base_url = base_url.strip() if isinstance(base_url, str) else ""
    if base_url:
        _add(base_url)

    if targets:
        for raw in targets:
            if not raw or not isinstance(raw, str):
                continue
            candidate = raw.strip()
            if not candidate:
                continue
            if not candidate.startswith(("http://", "https://")):
                candidate = urllib.parse.urljoin(base_url.rstrip("/") + "/", candidate)
            parsed = urllib.parse.urlparse(candidate)
            if not parsed.scheme or not parsed.netloc:
                continue
            if os.path.splitext(parsed.path.lower())[1] in _STATIC_EXTENSIONS:
                continue
            cleaned = urllib.parse.urlunparse(parsed._replace(fragment=""))
            if parsed.path and cleaned.endswith("/") and parsed.path != "/":
                cleaned = cleaned.rstrip("/")
            _add(cleaned)

    if max_targets and len(normalized) > max_targets:
        normalized = normalized[:max_targets]
    return normalized


def _write_targets_file(targets: list[str]) -> str:
    import tempfile

    fd, path = tempfile.mkstemp(prefix="nuclei_targets_", text=True)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write("\n".join(targets))
    return path


async def _refresh_auth_session(auth_session: Any | None, context: str) -> None:
    """Best-effort auth refresh before running a Nuclei command."""
    if not auth_session:
        return
    try:
        await auth_session.refresh_if_needed(force=False)
    except Exception as e:
        print(f"[nuclei] Auth refresh failed ({context}): {e}", file=sys.stderr)


# ============================================================================
# NUCLEI TEMPLATE DEDUPLICATION
# ============================================================================
# Multiple Nuclei templates can detect the same issue (e.g., 3 templates for
# missing HSTS). We group related templates and keep only the most specific one.

# Template groups for deduplication (templates in same group = same issue)
NUCLEI_TEMPLATE_GROUPS = {
    # Security headers - keep only one finding per header type
    "hsts": [
        "http-missing-security-headers:strict-transport-security",
        "strict-transport-security",
        "hsts-missing",
        "hsts-not-enforced",
    ],
    "csp": [
        "http-missing-security-headers:content-security-policy",
        "content-security-policy",
        "csp-missing",
        "csp-not-enforced",
    ],
    "x-frame-options": [
        "http-missing-security-headers:x-frame-options",
        "x-frame-options",
        "clickjacking",
    ],
    "x-content-type-options": [
        "http-missing-security-headers:x-content-type-options",
        "x-content-type-options",
    ],
    # SSL/TLS issues
    "ssl-weak-cipher": [
        "weak-cipher-suites",
        "ssl-weak-cipher",
        "tls-weak-cipher",
    ],
    "ssl-version": [
        "tls-version",
        "ssl-version",
        "deprecated-tls",
        "old-tls",
    ],
    # Technology detection
    "tech-wordpress": [
        "wordpress-detect",
        "wp-detect",
        "wordpress-version",
    ],
    "tech-nginx": [
        "nginx-version",
        "nginx-detect",
    ],
    "tech-apache": [
        "apache-version",
        "apache-detect",
    ],
}

# High-noise templates to deduplicate aggressively (limit findings per category)
NUCLEI_CATEGORY_LIMITS = {
    "misconfig": 5,      # Max 5 misconfiguration findings
    "exposure": 5,       # Max 5 exposure findings
    "tech": 3,           # Max 3 tech detection findings
    "osint": 3,          # Max 3 OSINT findings
}


def deduplicate_nuclei_findings(findings: list[dict]) -> list[dict]:
    """
    Deduplicate Nuclei findings by grouping related templates.

    Strategy:
    1. Group findings by template group (e.g., all HSTS-related templates)
    2. Keep only the highest severity finding per group
    3. Apply category limits for noisy categories

    Args:
        findings: List of Nuclei findings

    Returns:
        Deduplicated list of findings
    """
    if not findings:
        return []

    # Step 1: Build template ID to group mapping
    template_to_group = {}
    for group_name, templates in NUCLEI_TEMPLATE_GROUPS.items():
        for template in templates:
            template_to_group[template.lower()] = group_name

    # Step 2: Group findings
    groups: dict[str, list[dict]] = {}
    ungrouped: list[dict] = []

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

    for finding in findings:
        template_id = finding.get("template_id", "").lower()

        # Check if template matches any group
        matched_group = None
        for template_pattern, group_name in template_to_group.items():
            if template_pattern in template_id:
                matched_group = group_name
                break

        if matched_group:
            if matched_group not in groups:
                groups[matched_group] = []
            groups[matched_group].append(finding)
        else:
            ungrouped.append(finding)

    # Step 3: Select best finding per group
    deduplicated = []
    for group_name, group_findings in groups.items():
        if len(group_findings) == 1:
            deduplicated.append(group_findings[0])
        else:
            # Sort by severity (ascending = most severe first)
            group_findings.sort(
                key=lambda f: (
                    severity_order.get(f.get("severity", "unknown").lower(), 5),
                    -f.get("cvss_score", 0)  # Higher CVSS = better
                )
            )
            best = group_findings[0].copy()
            # Note that we deduplicated
            best["nuclei_dedup"] = {
                "group": group_name,
                "original_count": len(group_findings),
                "templates_merged": [f.get("template_id") for f in group_findings],
            }
            deduplicated.append(best)

    # Step 4: Add ungrouped findings
    deduplicated.extend(ungrouped)

    # Step 5: Apply category limits
    category_counts: dict[str, int] = {}
    final_findings = []

    for finding in deduplicated:
        tags = finding.get("tags", [])
        tags_lower = [str(t).lower() for t in tags] if tags else []

        # Check if any category is at limit
        over_limit = False
        for category, limit in NUCLEI_CATEGORY_LIMITS.items():
            if category in tags_lower:
                count = category_counts.get(category, 0)
                if count >= limit:
                    over_limit = True
                    break
                category_counts[category] = count + 1

        if not over_limit:
            final_findings.append(finding)

    return final_findings


# ============================================================================
# CVSS SCORE CAPS FOR NON-VULNERABILITY TEMPLATES
# ============================================================================
# Nuclei templates sometimes have inflated CVSS scores for findings that are
# not actual vulnerabilities (e.g., missing SRI at CVSS 9.8 is absurd).
# We cap scores for certain template types to align with industry standards.

# CVSS caps by template tag/category (industry-standard scoring)
CVSS_CAPS_BY_TAG = {
    "misconfig": 5.0,      # Misconfiguration is not critical unless it leads to RCE
    "exposure": 5.0,       # Information exposure
    "tech": 0.0,           # Technology detection is purely informational
    "osint": 0.0,          # OSINT is informational
    "ssl": 4.0,            # SSL issues
    "tls": 4.0,            # TLS issues
}

# CVSS caps by template ID patterns
CVSS_CAPS_BY_TEMPLATE = {
    "sri": 4.0,            # Missing SRI is defense-in-depth, not critical
    "subresource": 4.0,    # Same as SRI
    "dmarc": 3.0,          # Email policy - not a web vuln
    "spf": 3.0,            # Email policy - not a web vuln
    "dkim": 3.0,           # Email policy - not a web vuln
    "robots": 0.0,         # robots.txt is not a vulnerability
    "sitemap": 0.0,        # sitemap.xml is not a vulnerability
    "security-txt": 0.0,   # security.txt is informational
    "http-missing": 4.0,   # Missing HTTP headers
    "x-frame-options": 4.0,  # Missing security header
    "x-content-type": 3.0,   # Missing security header
    "content-security-policy": 4.0,  # CSP issues
    "hsts": 4.0,           # HSTS missing
    "cors": 5.0,           # CORS issues (can be serious but usually medium)
}


def cap_nuclei_cvss(template_id: str, tags: list[str], nuclei_cvss: float, severity: str) -> tuple[float, str]:
    """
    Cap CVSS scores for non-critical template types to prevent false high/critical ratings.

    Args:
        template_id: The nuclei template ID
        tags: List of template tags
        nuclei_cvss: Original CVSS score from nuclei
        severity: Original severity from nuclei

    Returns:
        Tuple of (capped_cvss, adjusted_severity)
    """
    if not nuclei_cvss or nuclei_cvss <= 0:
        return nuclei_cvss, severity

    capped_cvss = nuclei_cvss
    template_id_lower = template_id.lower()
    tags_lower = [str(t).lower() for t in tags] if tags else []

    # IMPORTANT: Don't cap CVEs - they have real CVSS scores from NVD
    # CVE tags indicate actual vulnerabilities, not misconfigurations
    is_cve = any('cve' in tag for tag in tags_lower) or 'cve-' in template_id_lower
    if is_cve:
        return nuclei_cvss, severity

    # Check template ID patterns (only for non-CVE templates)
    for pattern, cap in CVSS_CAPS_BY_TEMPLATE.items():
        if pattern in template_id_lower:
            capped_cvss = min(capped_cvss, cap)
            break

    # Check tags for category caps (only for non-CVE templates)
    for tag in tags_lower:
        if tag in CVSS_CAPS_BY_TAG:
            capped_cvss = min(capped_cvss, CVSS_CAPS_BY_TAG[tag])

    # Adjust severity based on capped CVSS
    if capped_cvss != nuclei_cvss:
        if capped_cvss <= 0:
            adjusted_severity = "info"
        elif capped_cvss <= 3.9:
            adjusted_severity = "low"
        elif capped_cvss <= 6.9:
            adjusted_severity = "medium"
        elif capped_cvss <= 8.9:
            adjusted_severity = "high"
        else:
            adjusted_severity = "critical"
        return capped_cvss, adjusted_severity

    return nuclei_cvss, severity


async def nuclei_scan(
    url: str,
    quick_mode: bool = False,
    targets: list[str] | None = None,
    auth_session: Any | None = None,
    max_targets: int | None = None
) -> dict[str, Any]:
    """Comprehensive vulnerability scanning with Nuclei (standard/quick)."""
    results: dict[str, Any] = {
        "vulnerabilities": [],
        "info": [],
        "scan_completed": False,
        "templates_used": 0,
    }

    nuclei_cmd = "/opt/tools/nuclei" if os.path.exists("/opt/tools/nuclei") else "nuclei"
    test_out, test_err, test_rc = await run([nuclei_cmd, "-version"], timeout=5)
    if test_rc != 0:
        return {"error": "Nuclei not installed", "scan_completed": False}

    targets_to_scan = _normalize_targets(url, targets, max_targets)
    target_file = None
    target_args: list[str] = []
    if targets_to_scan and len(targets_to_scan) > 1:
        target_file = _write_targets_file(targets_to_scan)
        target_args = ["-l", target_file]
    else:
        target_args = ["-u", targets_to_scan[0] if targets_to_scan else url]

    await _refresh_auth_session(auth_session, "smart_nuclei_scan")

    cmd = [
        nuclei_cmd,
        *target_args,
        "-jsonl",
        "-silent",
        "-duc",  # disable-update-check (short form)
        "-timeout", "10",
        "-retries", "2",
        "-rate-limit", "150",
        "-concurrency", "25",
    ]
    cmd.extend(get_auth_curl_args(auth_session))

    if quick_mode:
        cmd.extend(["-severity", "critical,high", "-tags", "cve,osint,tech,exposure", "-exclude-tags", "dos,fuzzing,bruteforce,rate-limit"])
        timeout = 120
    else:
        cmd.extend(["-severity", "critical,high,medium,low,info", "-tags", "cve,osint,tech,exposure,misconfig,takeover,auth,ssrf,sqli,xss,xxe,lfi,rce", "-exclude-tags", "dos,bruteforce,fuzzing,rate-limit"])
        timeout = 300

    # Add template directory (required when HOME=/tmp in containers)
    templates_dir = os.environ.get("NUCLEI_TEMPLATES", "/opt/nuclei-templates")
    if os.path.isdir(templates_dir):
        cmd.extend(["-templates", templates_dir])
    else:
        return {"error": f"Templates directory not found: {templates_dir}", "scan_completed": False}

    out, err, rc = await run(cmd, timeout=timeout, kill_process_group=True)
    if target_file and os.path.exists(target_file):
        try:
            os.unlink(target_file)
        except OSError:
            pass
    if rc == 0:
        # Scan completed successfully (even if no findings)
        results["scan_completed"] = True
        template_count = 0
        if out:
            for line in out.strip().split("\n"):
                if not line:
                    continue
                try:
                    finding = json.loads(line)
                    template_id = finding.get("template-id", "")
                    template_count += 1
                    # Extract raw values
                    raw_severity = finding.get("info", {}).get("severity", "unknown")
                    raw_cvss = finding.get("info", {}).get("classification", {}).get("cvss-score", 0)
                    tags = finding.get("info", {}).get("tags", [])

                    # Apply CVSS cap for non-vulnerability template types
                    capped_cvss, adjusted_severity = cap_nuclei_cvss(
                        template_id, tags, raw_cvss, raw_severity
                    )

                    vuln_data = {
                        "template_id": template_id,
                        "name": finding.get("info", {}).get("name", template_id),
                        "severity": adjusted_severity,  # Use adjusted severity
                        "type": finding.get("type", "http"),
                        "matched_at": finding.get("matched-at", ""),
                        "matcher_name": finding.get("matcher-name", ""),
                        "extracted_results": finding.get("extracted-results", []),
                        "curl_command": finding.get("curl-command", ""),
                        "description": finding.get("info", {}).get("description", ""),
                        "tags": tags,
                        "reference": finding.get("info", {}).get("reference", []),
                        "cwe_ids": finding.get("info", {}).get("classification", {}).get("cwe-id", []),
                        "cvss_metrics": finding.get("info", {}).get("classification", {}).get("cvss-metrics", ""),
                        "cvss_score": capped_cvss,  # Use capped CVSS
                        "original_cvss": raw_cvss if raw_cvss != capped_cvss else None,  # Track if capped
                    }
                    severity = vuln_data["severity"].lower()
                    if severity in ["critical", "high", "medium", "low"]:
                        results["vulnerabilities"].append(vuln_data)
                    else:
                        results["info"].append(vuln_data)
                except json.JSONDecodeError:
                    continue
        results["templates_used"] = template_count

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    results["vulnerabilities"].sort(key=lambda x: severity_order.get(x["severity"].lower(), 5))

    # Apply template deduplication to reduce noise
    original_count = len(results["vulnerabilities"]) + len(results["info"])
    results["vulnerabilities"] = deduplicate_nuclei_findings(results["vulnerabilities"])
    results["info"] = deduplicate_nuclei_findings(results["info"])
    deduped_count = len(results["vulnerabilities"]) + len(results["info"])

    if original_count != deduped_count:
        results["deduplication"] = {
            "original_findings": original_count,
            "after_dedup": deduped_count,
            "removed": original_count - deduped_count,
        }

    return results


async def nuclei_comprehensive_scan(
    url: str,
    rate_limit: int = 5,
    timeout_per_request: int = 15,
    scan_tier: str = "safe",
    targets: list[str] | None = None,
    auth_session: Any | None = None,
    max_targets: int | None = None
) -> dict[str, Any]:
    """Comprehensive Nuclei scan with tiered template selection (safe/full/aggressive)."""
    results: dict[str, Any] = {
        "scan_type": f"nuclei_comprehensive_{scan_tier}",
        "vulnerabilities": {"critical": [], "high": [], "medium": [], "low": [], "info": [], "unknown": []},
        "by_category": {"cve": [], "misconfig": [], "exposure": [], "takeover": [], "sqli": [], "xss": [], "xxe": [], "lfi": [], "rce": [], "ssrf": [], "auth": [], "other": []},
        "statistics": {"templates_loaded": 0, "templates_executed": 0, "requests_made": 0, "duration_seconds": 0, "start_time": now_utc_iso(), "scan_tier": scan_tier, "timeout_seconds": 0},
        "scan_completed": False,
        "errors": [],
    }

    start_time = time.time()
    nuclei_cmd = "/opt/tools/nuclei" if os.path.exists("/opt/tools/nuclei") else "nuclei"
    test_out, test_err, test_rc = await run([nuclei_cmd, "-version"], timeout=5)
    if test_rc != 0:
        results["errors"].append("Nuclei not installed")
        return results

    if scan_tier == "safe":
        template_tags = "cve,osint,tech,exposure,misconfig,takeover,auth,ssrf,sqli,xss,xxe,lfi,rce,iot,network,dns,file,logs,java,wp,adobe,drupal,joomla,magento,jenkins,gitlab,aws,azure,gcp,docker,k8s,cisco"
        scan_timeout = 2700
    elif scan_tier == "full":
        template_tags = "cve,osint,tech,exposure,misconfig,takeover,auth,ssrf,sqli,xss,xxe,lfi,rce,bruteforce,fuzzing,iot,network,dns,file,logs,java,wp,adobe,drupal,joomla,magento,jenkins,gitlab,aws,azure,gcp,docker,k8s,cisco"
        scan_timeout = 10800
    elif scan_tier == "aggressive":
        template_tags = "cve,osint,tech,exposure,misconfig,takeover,auth,ssrf,sqli,xss,xxe,lfi,rce,bruteforce,fuzzing,dos,iot,network,dns,file,logs,java,wp,adobe,drupal,joomla,magento,jenkins,gitlab,aws,azure,gcp,docker,k8s,cisco"
        scan_timeout = 14400
    else:
        template_tags = "cve,osint,tech,exposure,misconfig,takeover,auth,ssrf,sqli,xss,xxe,lfi,rce,iot,network,dns,file,logs,java,wp,adobe,drupal,joomla,magento,jenkins,gitlab,aws,azure,gcp,docker,k8s,cisco"
        scan_timeout = 2700
        results["errors"].append(f"Invalid scan tier '{scan_tier}', defaulting to 'safe'")

    templates_dir = os.environ.get("NUCLEI_TEMPLATES", "/opt/nuclei-templates")

    # Verify templates directory exists
    if not os.path.isdir(templates_dir):
        results["errors"].append(f"Templates directory not found: {templates_dir}")
        return results

    targets_to_scan = _normalize_targets(url, targets, max_targets)
    target_file = None
    target_args: list[str] = []
    if targets_to_scan and len(targets_to_scan) > 1:
        target_file = _write_targets_file(targets_to_scan)
        target_args = ["-l", target_file]
    else:
        target_args = ["-u", targets_to_scan[0] if targets_to_scan else url]

    await _refresh_auth_session(auth_session, "nuclei_scan")

    cmd = [
        nuclei_cmd,
        *target_args,
        "-jsonl",
        "-silent",
        "-duc",  # disable-update-check (short form)
        "-stats",
        "-stats-interval", "30",
        "-severity", "critical,high,medium,low,info,unknown",
        "-timeout", str(timeout_per_request),
        "-retries", "3",
        "-rate-limit", str(rate_limit),
        "-concurrency", "10",
        "-bulk-size", "25",
        "-system-resolvers",
        "-include-rr",
        "-irr",
        "-tags", template_tags,
        "-templates", templates_dir,
    ]
    cmd.extend(get_auth_curl_args(auth_session))

    results["statistics"]["timeout_seconds"] = scan_timeout
    out, err, rc = await run(cmd, timeout=scan_timeout)
    if target_file and os.path.exists(target_file):
        try:
            os.unlink(target_file)
        except OSError:
            pass

    if rc == 0:
        results["scan_completed"] = True
    if rc == 0 and out:
        template_count = 0
        request_count = 0
        for line in out.strip().split("\n"):
            if not line:
                continue
            try:
                finding = json.loads(line)
                if finding.get("type") == "stats":
                    results["statistics"]["templates_loaded"] = finding.get("templates_loaded", 0)
                    results["statistics"]["templates_executed"] = finding.get("templates_executed", 0)
                    results["statistics"]["requests_made"] = finding.get("requests_made", 0)
                    continue
                template_id = finding.get("template-id", "")
                template_count += 1
                request_count += 1
                raw_severity = finding.get("info", {}).get("severity", "unknown").lower()
                raw_cvss = finding.get("info", {}).get("classification", {}).get("cvss-score", 0)
                tags = finding.get("info", {}).get("tags", [])

                # Apply CVSS cap for non-vulnerability template types
                capped_cvss, severity = cap_nuclei_cvss(
                    template_id, tags, raw_cvss, raw_severity
                )

                vuln_data = {
                    "template_id": template_id,
                    "name": finding.get("info", {}).get("name", template_id),
                    "severity": severity,  # Use adjusted severity
                    "type": finding.get("type", "http"),
                    "matched_at": finding.get("matched-at", ""),
                    "matcher_name": finding.get("matcher-name", ""),
                    "extracted_results": finding.get("extracted-results", []),
                    "curl_command": finding.get("curl-command", ""),
                    "description": finding.get("info", {}).get("description", ""),
                    "tags": tags,
                    "reference": finding.get("info", {}).get("reference", []),
                    "cwe_ids": finding.get("info", {}).get("classification", {}).get("cwe-id", []),
                    "cvss_metrics": finding.get("info", {}).get("classification", {}).get("cvss-metrics", ""),
                    "cvss_score": capped_cvss,  # Use capped CVSS
                    "original_cvss": raw_cvss if raw_cvss != capped_cvss else None,  # Track if capped
                    "request": finding.get("request", ""),
                    "response": finding.get("response", ""),
                    "interaction": finding.get("interaction", {}),
                    "remediation": finding.get("info", {}).get("remediation", ""),
                }
                if severity in results["vulnerabilities"]:
                    results["vulnerabilities"][severity].append(vuln_data)
                categorized = False
                for tag in tags:
                    tag_lower = str(tag).lower()
                    if "cve" in tag_lower:
                        results["by_category"]["cve"].append(vuln_data); categorized = True; break
                    elif any(x in tag_lower for x in ["misconfig", "misconfiguration"]):
                        results["by_category"]["misconfig"].append(vuln_data); categorized = True; break
                    elif any(x in tag_lower for x in ["exposure", "exposed"]):
                        results["by_category"]["exposure"].append(vuln_data); categorized = True; break
                    elif "takeover" in tag_lower:
                        results["by_category"]["takeover"].append(vuln_data); categorized = True; break
                    elif "sqli" in tag_lower or "sql" in tag_lower:
                        results["by_category"]["sqli"].append(vuln_data); categorized = True; break
                    elif "xss" in tag_lower:
                        results["by_category"]["xss"].append(vuln_data); categorized = True; break
                    elif "xxe" in tag_lower:
                        results["by_category"]["xxe"].append(vuln_data); categorized = True; break
                    elif "lfi" in tag_lower or "rfi" in tag_lower:
                        results["by_category"]["lfi"].append(vuln_data); categorized = True; break
                    elif "rce" in tag_lower:
                        results["by_category"]["rce"].append(vuln_data); categorized = True; break
                    elif "ssrf" in tag_lower:
                        results["by_category"]["ssrf"].append(vuln_data); categorized = True; break
                    elif "auth" in tag_lower:
                        results["by_category"]["auth"].append(vuln_data); categorized = True; break
                if not categorized:
                    results["by_category"]["other"].append(vuln_data)
            except json.JSONDecodeError:
                continue
            except Exception as e:  # pragma: no cover - defensive
                results["errors"].append(f"Error parsing nuclei output: {e!s}")
                continue
        if template_count > 0:
            results["statistics"]["templates_executed"] = template_count
        if request_count > 0:
            results["statistics"]["requests_made"] = request_count
    elif rc != 0:
        results["errors"].append(f"Nuclei scan failed with return code {rc}")
        if err:
            results["errors"].append(f"Error output: {err[:500]}")

    results["statistics"]["duration_seconds"] = int(time.time() - start_time)
    results["statistics"]["end_time"] = now_utc_iso()

    total_findings = sum(len(v) for v in results["vulnerabilities"].values())
    cvss_scores = [vuln["cvss_score"] for sev in results["vulnerabilities"].values() for vuln in sev if vuln.get("cvss_score", 0) > 0]
    results["summary"] = {
        "total_findings": total_findings,
        "critical_count": len(results["vulnerabilities"]["critical"]),
        "high_count": len(results["vulnerabilities"]["high"]),
        "medium_count": len(results["vulnerabilities"]["medium"]),
        "low_count": len(results["vulnerabilities"]["low"]),
        "info_count": len(results["vulnerabilities"]["info"]),
        "cvss_max": max(cvss_scores) if cvss_scores else 0,
        "cvss_avg": (sum(cvss_scores) / len(cvss_scores)) if cvss_scores else 0,
    }
    return results


# =============================================================================
# SMART NUCLEI SCAN - Technology-Aware Template Selection
# =============================================================================
# Maps detected technologies to relevant Nuclei template tags.
# This reduces scan time by 60-80% by only running relevant templates.

TECH_TO_NUCLEI_TAGS = {
    # Web Frameworks - JavaScript/Node
    "express": ["node", "express", "npm", "javascript", "js"],
    "express.js": ["node", "express", "npm", "javascript", "js"],
    "node": ["node", "npm", "javascript", "js"],
    "node.js": ["node", "npm", "javascript", "js"],
    "next.js": ["node", "nextjs", "react", "javascript", "js"],
    "nextjs": ["node", "nextjs", "react", "javascript", "js"],
    "react": ["react", "javascript", "js"],
    "angular": ["angular", "javascript", "js"],
    "angularjs": ["angular", "javascript", "js"],
    "vue": ["vue", "javascript", "js"],
    "vue.js": ["vue", "javascript", "js"],

    # Web Frameworks - Python
    "django": ["django", "python"],
    "flask": ["flask", "python"],
    "fastapi": ["fastapi", "python"],

    # Web Frameworks - PHP
    "laravel": ["laravel", "php"],
    "symfony": ["symfony", "php"],
    "codeigniter": ["codeigniter", "php"],
    "php": ["php"],

    # Web Frameworks - Ruby
    "rails": ["rails", "ruby"],
    "ruby on rails": ["rails", "ruby"],
    "sinatra": ["ruby"],

    # Web Frameworks - Java
    "spring": ["spring", "java", "actuator"],
    "spring boot": ["spring", "java", "actuator", "springboot"],
    "struts": ["struts", "java", "apache"],
    "tomcat": ["tomcat", "java", "apache"],

    # Web Frameworks - .NET
    "asp.net": ["aspnet", "dotnet", "csharp", "microsoft"],
    ".net": ["aspnet", "dotnet", "csharp", "microsoft"],

    # CMS Platforms
    "wordpress": ["wp", "wordpress", "php"],
    "drupal": ["drupal", "php"],
    "joomla": ["joomla", "php"],
    "magento": ["magento", "php", "adobe"],
    "shopify": ["shopify"],
    "wix": ["wix"],
    "squarespace": ["squarespace"],

    # Web Servers
    "nginx": ["nginx"],
    "apache": ["apache"],
    "iis": ["iis", "microsoft"],
    "lighttpd": ["lighttpd"],
    "openresty": ["openresty", "nginx"],

    # Databases (for error-based detection)
    "mysql": ["mysql", "sql"],
    "postgresql": ["postgresql", "postgres", "sql"],
    "mongodb": ["mongodb", "nosql"],
    "redis": ["redis"],
    "elasticsearch": ["elasticsearch", "elastic"],
    "sqlite": ["sqlite", "sql"],
    "mssql": ["mssql", "sql", "microsoft"],
    "oracle": ["oracle", "sql"],

    # Cloud Providers
    "aws": ["aws", "s3", "ec2", "amazon"],
    "azure": ["azure", "microsoft"],
    "gcp": ["gcp", "google-cloud", "google"],
    "cloudflare": ["cloudflare"],
    "digitalocean": ["digitalocean"],
    "heroku": ["heroku"],

    # DevOps/CI-CD
    "jenkins": ["jenkins", "java"],
    "gitlab": ["gitlab"],
    "github": ["github"],
    "kubernetes": ["kubernetes", "k8s"],
    "docker": ["docker"],
    "grafana": ["grafana"],
    "prometheus": ["prometheus"],

    # Other Technologies
    "jquery": ["jquery", "javascript"],
    "bootstrap": ["bootstrap"],
    "tailwind": ["tailwind"],
}

# Core security tags - always run these regardless of technology
CORE_SECURITY_TAGS = [
    "cve",          # Known CVEs
    "critical",     # Critical severity
    "takeover",     # Subdomain takeover
    "exposure",     # Information exposure
    "default-login", # Default credentials
    "misconfig",    # Misconfigurations
]


async def smart_nuclei_scan(
    url: str,
    detected_tech: list[str] | None = None,
    scan_type: str = "standard",
    targets: list[str] | None = None,
    auth_session: Any | None = None,
    max_targets: int | None = None
) -> dict[str, Any]:
    """
    Technology-aware Nuclei scan that selects templates based on detected stack.

    This dramatically reduces scan time by only running relevant templates:
    - WordPress site: ~400 templates instead of 9000
    - Express/Node API: ~200 templates instead of 9000
    - Unknown stack: ~800 core templates (CVE + exposure + misconfig)

    Estimated time savings: 60-80%

    Args:
        url: Target URL to scan
        detected_tech: List of detected technologies (from tech fingerprinting)
        scan_type: Scan intensity ('quick', 'standard', 'deep', 'full', 'aggressive')

    Returns:
        Dict with vulnerabilities, scan stats, and template selection info
    """
    import sys

    results: dict[str, Any] = {
        "scan_type": "smart_nuclei",
        "vulnerabilities": [],
        "info": [],
        "scan_completed": False,
        "templates_used": 0,
        "tech_detected": detected_tech or [],
        "tags_selected": [],
        "optimization": {},
    }

    nuclei_cmd = "/opt/tools/nuclei" if os.path.exists("/opt/tools/nuclei") else "nuclei"
    test_out, test_err, test_rc = await run([nuclei_cmd, "-version"], timeout=5)
    if test_rc != 0:
        results["error"] = "Nuclei not installed"
        return results

    # Build tag set based on detected technologies
    tags_to_use: set[str] = set(CORE_SECURITY_TAGS)

    # Normalize detected_tech to handle both string and dict formats
    tech_list = _normalize_tech_list(detected_tech)

    if tech_list:
        for tech_lower in tech_list:
            # Direct match
            if tech_lower in TECH_TO_NUCLEI_TAGS:
                tags_to_use.update(TECH_TO_NUCLEI_TAGS[tech_lower])
            else:
                # Partial match
                for pattern, nuclei_tags in TECH_TO_NUCLEI_TAGS.items():
                    if pattern in tech_lower or tech_lower in pattern:
                        tags_to_use.update(nuclei_tags)
                        break

    # Scan type adjustments
    if scan_type in ["full", "aggressive"]:
        # Add more comprehensive tags for thorough scans
        tags_to_use.update(["auth", "ssrf", "sqli", "xss", "xxe", "lfi", "rce", "iot", "network"])
        if scan_type == "aggressive":
            tags_to_use.update(["fuzzing", "bruteforce"])
        timeout = 1800  # 30 minutes
        rate_limit = 100
    elif scan_type == "deep":
        tags_to_use.update(["auth", "ssrf", "sqli", "xss"])
        timeout = 900  # 15 minutes
        rate_limit = 150
    elif scan_type == "quick":
        # Only core security checks for quick scans
        tags_to_use = set(["cve", "critical", "takeover"])
        timeout = 180  # 3 minutes
        rate_limit = 200
    else:  # standard
        timeout = 600  # 10 minutes
        rate_limit = 150

    tags_list = sorted(list(tags_to_use))
    results["tags_selected"] = tags_list

    print(f"[nuclei] Smart scan: {len(tags_list)} tags based on {len(detected_tech or [])} detected technologies", file=sys.stderr)
    print(f"[nuclei] Tags: {', '.join(tags_list[:20])}{'...' if len(tags_list) > 20 else ''}", file=sys.stderr)

    templates_dir = os.environ.get("NUCLEI_TEMPLATES", "/opt/nuclei-templates")
    if not os.path.isdir(templates_dir):
        results["error"] = f"Templates directory not found: {templates_dir}"
        return results

    targets_to_scan = _normalize_targets(url, targets, max_targets)
    target_file = None
    target_args: list[str] = []
    if targets_to_scan and len(targets_to_scan) > 1:
        target_file = _write_targets_file(targets_to_scan)
        target_args = ["-l", target_file]
    else:
        target_args = ["-u", targets_to_scan[0] if targets_to_scan else url]

    await _refresh_auth_session(auth_session, "nuclei_comprehensive_scan")

    cmd = [
        nuclei_cmd,
        *target_args,
        "-jsonl",
        "-silent",
        "-duc",  # disable-update-check
        "-timeout", "10",
        "-retries", "2",
        "-rate-limit", str(rate_limit),
        "-concurrency", "25",
        "-severity", "critical,high,medium,low,info",
        "-tags", ",".join(tags_list),
        "-templates", templates_dir,
    ]
    cmd.extend(get_auth_curl_args(auth_session))

    # Exclude noisy/dangerous tags
    exclude_tags = ["dos", "rate-limit"]
    if scan_type not in ["full", "aggressive"]:
        exclude_tags.extend(["fuzzing", "bruteforce"])
    cmd.extend(["-exclude-tags", ",".join(exclude_tags)])

    start_time = time.time()
    out, err, rc = await run(cmd, timeout=timeout)
    if target_file and os.path.exists(target_file):
        try:
            os.unlink(target_file)
        except OSError:
            pass
    scan_duration = int(time.time() - start_time)

    results["optimization"] = {
        "tags_count": len(tags_list),
        "estimated_full_scan_time_minutes": 45,  # Typical full scan time
        "actual_scan_time_seconds": scan_duration,
        "time_saved_percent": max(0, int((1 - scan_duration / 2700) * 100)),  # Compared to 45 min
    }

    if rc == 0:
        results["scan_completed"] = True
        template_count = 0
        if out:
            for line in out.strip().split("\n"):
                if not line:
                    continue
                try:
                    finding = json.loads(line)
                    template_id = finding.get("template-id", "")
                    template_count += 1

                    raw_severity = finding.get("info", {}).get("severity", "unknown")
                    raw_cvss = finding.get("info", {}).get("classification", {}).get("cvss-score", 0)
                    tags = finding.get("info", {}).get("tags", [])

                    # Apply CVSS cap for non-vulnerability template types
                    capped_cvss, adjusted_severity = cap_nuclei_cvss(
                        template_id, tags, raw_cvss, raw_severity
                    )

                    vuln_data = {
                        "template_id": template_id,
                        "name": finding.get("info", {}).get("name", template_id),
                        "severity": adjusted_severity,
                        "type": finding.get("type", "http"),
                        "matched_at": finding.get("matched-at", ""),
                        "matcher_name": finding.get("matcher-name", ""),
                        "extracted_results": finding.get("extracted-results", []),
                        "curl_command": finding.get("curl-command", ""),
                        "description": finding.get("info", {}).get("description", ""),
                        "tags": tags,
                        "reference": finding.get("info", {}).get("reference", []),
                        "cwe_ids": finding.get("info", {}).get("classification", {}).get("cwe-id", []),
                        "cvss_metrics": finding.get("info", {}).get("classification", {}).get("cvss-metrics", ""),
                        "cvss_score": capped_cvss,
                        "original_cvss": raw_cvss if raw_cvss != capped_cvss else None,
                    }

                    severity = vuln_data["severity"].lower()
                    if severity in ["critical", "high", "medium", "low"]:
                        results["vulnerabilities"].append(vuln_data)
                    else:
                        results["info"].append(vuln_data)
                except json.JSONDecodeError:
                    continue

        results["templates_used"] = template_count
        print(f"[nuclei] Scan complete: {template_count} findings in {scan_duration}s", file=sys.stderr)

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    results["vulnerabilities"].sort(key=lambda x: severity_order.get(x["severity"].lower(), 5))

    # Apply deduplication
    original_count = len(results["vulnerabilities"]) + len(results["info"])
    results["vulnerabilities"] = deduplicate_nuclei_findings(results["vulnerabilities"])
    results["info"] = deduplicate_nuclei_findings(results["info"])
    deduped_count = len(results["vulnerabilities"]) + len(results["info"])

    if original_count != deduped_count:
        results["deduplication"] = {
            "original_findings": original_count,
            "after_dedup": deduped_count,
            "removed": original_count - deduped_count,
        }

    return results


# =============================================================================
# STAGED NUCLEI SCAN - Wave-Based Adaptive Template Selection
# =============================================================================
# Runs Nuclei in intelligent waves, expanding scope based on signals from
# previous waves. This provides faster time-to-first-finding and can early-stop
# when enough high-confidence vulnerabilities are found.


async def _run_nuclei_wave(
    url: str,
    tags: list[str],
    timeout: int = 60,
    rate_limit: int = 50,
    exclude_tags: list[str] | None = None,
    targets: list[str] | None = None,
    auth_session: Any | None = None,
    max_targets: int | None = None
) -> dict[str, Any]:
    """
    Run a single Nuclei wave with specific tags.

    Args:
        url: Target URL
        tags: List of template tags to use
        timeout: Timeout in seconds
        rate_limit: Requests per second
        exclude_tags: Tags to exclude

    Returns:
        Dict with findings and metadata
    """
    import sys

    result = {
        "findings": [],
        "scan_completed": False,
        "tags_used": tags,
        "duration_seconds": 0,
        "templates_executed": 0,
        "templates_loaded": 0,
        "matched_template_ids": [],
    }

    nuclei_cmd = "/opt/tools/nuclei" if os.path.exists("/opt/tools/nuclei") else "nuclei"

    templates_dir = os.environ.get("NUCLEI_TEMPLATES", "/opt/nuclei-templates")
    if not os.path.isdir(templates_dir):
        result["error"] = f"Templates directory not found: {templates_dir}"
        return result

    targets_to_scan = _normalize_targets(url, targets, max_targets)
    target_file = None
    target_args: list[str] = []
    if targets_to_scan and len(targets_to_scan) > 1:
        target_file = _write_targets_file(targets_to_scan)
        target_args = ["-l", target_file]
    else:
        target_args = ["-u", targets_to_scan[0] if targets_to_scan else url]

    await _refresh_auth_session(auth_session, "nuclei_wave")

    cmd = [
        nuclei_cmd,
        *target_args,
        "-jsonl",
        "-silent",
        "-duc",
        "-stats",
        "-stats-interval", "30",
        "-timeout", "10",
        "-retries", "1",
        "-rate-limit", str(rate_limit),
        "-concurrency", "15",
        "-severity", "critical,high,medium,low,info",
        "-tags", ",".join(tags),
        "-templates", templates_dir,
    ]
    cmd.extend(get_auth_curl_args(auth_session))

    if exclude_tags:
        cmd.extend(["-exclude-tags", ",".join(exclude_tags)])

    start_time = time.time()
    out, err, rc = await run(cmd, timeout=timeout)
    if target_file and os.path.exists(target_file):
        try:
            os.unlink(target_file)
        except OSError:
            pass
    result["duration_seconds"] = int(time.time() - start_time)

    if rc == 0:
        result["scan_completed"] = True
        if out:
            matched_templates = set()
            for line in out.strip().split("\n"):
                if not line:
                    continue
                try:
                    finding = json.loads(line)
                    if finding.get("type") == "stats":
                        result["templates_loaded"] = finding.get("templates_loaded", 0)
                        result["templates_executed"] = finding.get("templates_executed", 0)
                        continue
                    template_id = finding.get("template-id", "")
                    if template_id:
                        matched_templates.add(template_id)
                    tags_found = finding.get("info", {}).get("tags", [])
                    raw_severity = finding.get("info", {}).get("severity", "unknown")
                    raw_cvss = finding.get("info", {}).get("classification", {}).get("cvss-score", 0)

                    capped_cvss, adjusted_severity = cap_nuclei_cvss(
                        template_id, tags_found, raw_cvss, raw_severity
                    )

                    result["findings"].append({
                        "template_id": template_id,
                        "name": finding.get("info", {}).get("name", template_id),
                        "severity": adjusted_severity,
                        "type": finding.get("type", "http"),
                        "matched_at": finding.get("matched-at", ""),
                        "tags": tags_found,
                        "cvss_score": capped_cvss,
                        "description": finding.get("info", {}).get("description", ""),
                        "reference": finding.get("info", {}).get("reference", []),
                    })
                except json.JSONDecodeError:
                    continue

            result["matched_template_ids"] = sorted(matched_templates)
            if result["templates_executed"] == 0 and matched_templates:
                result["templates_executed"] = len(matched_templates)

    return result


def _build_wave1_tags(detected_tech: list) -> list[str]:
    """Build Wave 1 tags: critical CVEs + tech-specific templates."""
    base_tags = ["cve", "critical", "takeover", "rce", "default-login"]

    # Normalize detected_tech to handle both string and dict formats
    tech_list = _normalize_tech_list(detected_tech)

    tech_tags = []
    for tech_lower in tech_list:
        if tech_lower in TECH_TO_NUCLEI_TAGS:
            tech_tags.extend(TECH_TO_NUCLEI_TAGS[tech_lower])
        else:
            # Partial match
            for pattern, nuclei_tags in TECH_TO_NUCLEI_TAGS.items():
                if pattern in tech_lower or tech_lower in pattern:
                    tech_tags.extend(nuclei_tags)
                    break

    return list(set(base_tags + tech_tags))


def _build_wave2_tags(signals: dict, detected_tech: list) -> list[str]:
    """Build Wave 2 tags based on signals from Wave 1."""
    tags = ["misconfig", "exposure", "auth"]

    # Expand based on signals
    if signals.get("sql_errors"):
        tags.extend(["sqli", "mysql", "postgresql", "sqlite", "mssql", "oracle", "sql"])
    if signals.get("xss_reflection"):
        tags.extend(["xss", "dom-xss", "reflected-xss"])
    if signals.get("auth_issues"):
        tags.extend(["default-login", "auth-bypass", "jwt", "oauth", "session"])
    if signals.get("file_inclusion"):
        tags.extend(["lfi", "rfi", "path-traversal"])

    # Normalize detected_tech to handle both string and dict formats
    tech_list = _normalize_tech_list(detected_tech)

    # Add tech-specific tags not already covered
    for tech_lower in tech_list:
        if tech_lower in TECH_TO_NUCLEI_TAGS:
            tags.extend(TECH_TO_NUCLEI_TAGS[tech_lower])

    return list(set(tags))


def _update_signals(signals: dict, findings: list[dict]) -> dict:
    """Update signals based on findings from a wave."""
    for f in findings:
        template_id = f.get("template_id", "").lower()
        tags = [t.lower() for t in f.get("tags", [])]
        name = f.get("name", "").lower()
        severity = f.get("severity", "").lower()

        # SQL-related signals
        if any(x in template_id or x in name for x in ["sql", "database", "query", "mysql", "postgres", "sqlite"]):
            signals["sql_errors"] = True
        if "sqli" in tags or "sql" in tags:
            signals["sql_errors"] = True

        # XSS-related signals
        if any(x in template_id or x in name for x in ["xss", "reflect", "cross-site"]):
            signals["xss_reflection"] = True
        if "xss" in tags:
            signals["xss_reflection"] = True

        # Auth-related signals
        if any(x in tags for x in ["auth", "login", "session", "jwt", "oauth", "credential"]):
            signals["auth_issues"] = True
        if "default-login" in tags or "default" in name:
            signals["auth_issues"] = True

        # File inclusion signals
        if any(x in template_id or x in name for x in ["lfi", "rfi", "traversal", "inclusion"]):
            signals["file_inclusion"] = True

        # Track severity counts
        if severity == "critical":
            signals["critical_count"] = signals.get("critical_count", 0) + 1
        elif severity == "high":
            signals["high_count"] = signals.get("high_count", 0) + 1

    return signals


def _should_early_stop(findings: list[dict], signals: dict, threshold: float = 12.0) -> tuple[bool, str]:
    """
    Decide if we have enough high-confidence findings to stop early.

    Uses confidence-weighted scoring instead of simple counts:
    - Critical findings weighted at 4.0
    - High findings weighted at 2.0
    - Medium at 1.0, Low at 0.5, Info at 0.1
    - Multiplied by finding confidence (default 0.65)

    Threshold of 12.0 ≈ 3 high-confidence criticals or 6 high-confidence highs.

    Args:
        findings: List of finding dicts with 'severity' and optional 'confidence'
        signals: Signal dict/SignalSet (for backward compatibility tracking)
        threshold: Weighted score threshold to trigger stop (default 12.0)

    Returns:
        Tuple of (should_stop, reason)
    """
    # Calculate confidence-weighted score
    weighted_score = calculate_weighted_score(findings)

    # Also track counts for logging (backward compat)
    critical_count = signals.get("critical_count", 0) if hasattr(signals, "get") else getattr(signals, "critical_count", 0)
    high_count = signals.get("high_count", 0) if hasattr(signals, "get") else getattr(signals, "high_count", 0)

    if weighted_score >= threshold:
        return True, f"Confidence-weighted score {weighted_score:.1f} exceeds threshold (criticals={critical_count}, highs={high_count})"

    # Legacy fallback: still stop on extreme counts even if confidence is low
    if critical_count >= 5:
        return True, f"Found {critical_count} critical vulnerabilities (legacy threshold)"

    return False, ""


def _has_promising_signals(signals: dict, findings: list[dict]) -> bool:
    """Check if signals suggest more vulnerabilities to find."""
    # If we found SQL/XSS/Auth issues, likely more to find
    if signals.get("sql_errors") or signals.get("xss_reflection") or signals.get("auth_issues"):
        return True

    # If we found some vulns but not many, worth exploring more
    if len(findings) > 0 and len(findings) < 5:
        return True

    return False


async def staged_nuclei_scan(
    url: str,
    detected_tech: list[str] | None = None,
    early_stopping: bool = True,
    max_waves: int = 4,
    targets: list[str] | None = None,
    auth_session: Any | None = None,
    max_targets: int | None = None
) -> dict[str, Any]:
    """
    Run Nuclei in intelligent waves, expanding scope based on signals.

    Wave Strategy with Yield-Based Budgets:
    - Wave 1: Critical CVEs + tech-specific (budget: 60s max, exits early if yield < 0.3/min)
    - Wave 2: Misconfig + exposure + signal-based expansion (budget adjusted by wave 1 yield)
    - Wave 3: Injection templates if signals detected (budget adjusted by wave 2 yield)
    - Wave 4: Full coverage only if promising signals (budget adjusted by wave 3 yield)

    Yield-based budgets allow:
    - Early exit when templates stop finding vulnerabilities
    - Extended runtime when yield is high (finding many vulns)
    - Adaptive timeout based on previous wave results

    Args:
        url: Target URL to scan
        detected_tech: List of detected technologies
        early_stopping: Whether to stop early when confidence is high
        max_waves: Maximum number of waves to run
        targets: List of target URLs
        auth_session: Authentication session for authenticated scans
        max_targets: Maximum targets to scan

    Returns:
        Dict with vulnerabilities, wave stats, yield metrics, and signals
    """
    import sys

    detected_tech = detected_tech or []

    results: dict[str, Any] = {
        "scan_type": "staged_nuclei",
        "vulnerabilities": [],
        "info": [],
        "waves_completed": 0,
        "early_stopped": False,
        "early_stop_reason": "",
        "signals": {},
        "wave_stats": [],
        "yield_metrics": [],  # New: track yield per wave
        "tech_detected": detected_tech,
        "total_duration_seconds": 0,
        "templates_executed": 0,
        "templates_matched": 0,
        "scan_completed": False,
    }

    # Initialize wave budgets (will be adjusted based on yield)
    wave_budgets = [
        WaveBudget.wave1(),
        WaveBudget.wave2(),
        WaveBudget.wave3(),
        WaveBudget.wave4(),
    ]

    # Check nuclei availability
    nuclei_cmd = "/opt/tools/nuclei" if os.path.exists("/opt/tools/nuclei") else "nuclei"
    test_out, test_err, test_rc = await run([nuclei_cmd, "-version"], timeout=5)
    if test_rc != 0:
        results["error"] = "Nuclei not installed"
        return results

    all_findings: list[dict] = []
    signals: dict = {
        "sql_errors": False,
        "xss_reflection": False,
        "auth_issues": False,
        "file_inclusion": False,
        "critical_count": 0,
        "high_count": 0,
    }
    total_start = time.time()
    exclude_tags = ["dos", "rate-limit"]
    matched_templates: set[str] = set()
    templates_executed_total = 0

    def _finalize_template_metrics() -> None:
        results["templates_executed"] = templates_executed_total
        results["templates_matched"] = len(matched_templates)

    def _finalize_and_return() -> dict[str, Any]:
        results["scan_completed"] = True
        return results

    # =========================================================================
    # WAVE 1: Critical CVEs + Tech-Specific (fast, targeted)
    # =========================================================================
    wave1_budget = wave_budgets[0]
    print(f"[nuclei] Wave 1: Critical + tech-specific templates (budget: {wave1_budget.max_duration}s)", file=sys.stderr)
    wave1_tags = _build_wave1_tags(detected_tech)
    wave1 = await _run_nuclei_wave(
        url,
        wave1_tags,
        timeout=wave1_budget.max_duration,
        rate_limit=50,
        exclude_tags=exclude_tags,
        targets=targets,
        auth_session=auth_session,
        max_targets=max_targets,
    )

    all_findings.extend(wave1["findings"])
    signals = _update_signals(signals, wave1["findings"])
    templates_executed_total += wave1.get("templates_executed", 0)
    matched_templates.update(wave1.get("matched_template_ids", []))

    # Calculate yield metrics for wave 1
    wave1_yield = calculate_yield_metrics(wave1["findings"], wave1["duration_seconds"])
    results["yield_metrics"].append({
        "wave": 1,
        "findings_count": wave1_yield.findings_count,
        "duration_seconds": wave1_yield.duration_seconds,
        "findings_per_minute": round(wave1_yield.findings_per_minute, 2),
    })

    results["waves_completed"] = 1
    results["wave_stats"].append({
        "wave": 1,
        "tags": wave1_tags[:10],
        "findings": len(wave1["findings"]),
        "duration": wave1["duration_seconds"],
        "budget_max": wave1_budget.max_duration,
        "yield_per_min": round(wave1_yield.findings_per_minute, 2),
    })

    print(f"[nuclei] Wave 1 complete: {len(wave1['findings'])} findings in {wave1['duration_seconds']:.0f}s (yield: {wave1_yield.findings_per_minute:.1f}/min)", file=sys.stderr)

    # Adjust Wave 2 budget based on Wave 1 yield
    if max_waves >= 2:
        wave_budgets[1] = adjust_next_wave_budget(wave1_yield, wave_budgets[1], signals)

    # Early stop check
    if early_stopping and max_waves >= 1:
        should_stop, reason = _should_early_stop(all_findings, signals)
        if should_stop:
            results["early_stopped"] = True
            results["early_stop_reason"] = reason
            print(f"[nuclei] Early stop after Wave 1: {reason}", file=sys.stderr)
            results["vulnerabilities"] = deduplicate_nuclei_findings(all_findings)
            results["signals"] = signals
            results["total_duration_seconds"] = int(time.time() - total_start)
            _finalize_template_metrics()
            return _finalize_and_return()

    if max_waves < 2:
        results["vulnerabilities"] = deduplicate_nuclei_findings(all_findings)
        results["signals"] = signals
        results["total_duration_seconds"] = int(time.time() - total_start)
        _finalize_template_metrics()
        return _finalize_and_return()

    # =========================================================================
    # WAVE 2: Misconfig + Exposure + Signal-Based Expansion
    # =========================================================================
    wave2_budget = wave_budgets[1]
    print(f"[nuclei] Wave 2: Expanding based on signals (budget: {wave2_budget.max_duration}s)", file=sys.stderr)
    wave2_tags = _build_wave2_tags(signals, detected_tech)
    # Exclude tags we already ran
    wave2_tags = [t for t in wave2_tags if t not in wave1_tags]

    wave2_yield = YieldMetrics()  # Default empty metrics if wave skipped
    if wave2_tags:
        wave2 = await _run_nuclei_wave(
            url,
            wave2_tags,
            timeout=wave2_budget.max_duration,
            rate_limit=40,
            exclude_tags=exclude_tags,
            targets=targets,
            auth_session=auth_session,
            max_targets=max_targets,
        )
        all_findings.extend(wave2["findings"])
        signals = _update_signals(signals, wave2["findings"])
        templates_executed_total += wave2.get("templates_executed", 0)
        matched_templates.update(wave2.get("matched_template_ids", []))

        # Calculate yield metrics for wave 2
        wave2_yield = calculate_yield_metrics(wave2["findings"], wave2["duration_seconds"])
        results["yield_metrics"].append({
            "wave": 2,
            "findings_count": wave2_yield.findings_count,
            "duration_seconds": wave2_yield.duration_seconds,
            "findings_per_minute": round(wave2_yield.findings_per_minute, 2),
        })

        results["waves_completed"] = 2
        results["wave_stats"].append({
            "wave": 2,
            "tags": wave2_tags[:10],
            "findings": len(wave2["findings"]),
            "duration": wave2["duration_seconds"],
            "budget_max": wave2_budget.max_duration,
            "yield_per_min": round(wave2_yield.findings_per_minute, 2),
        })
        print(f"[nuclei] Wave 2 complete: {len(wave2['findings'])} findings in {wave2['duration_seconds']:.0f}s (yield: {wave2_yield.findings_per_minute:.1f}/min)", file=sys.stderr)

        # Adjust Wave 3 budget based on Wave 2 yield
        if max_waves >= 3:
            wave_budgets[2] = adjust_next_wave_budget(wave2_yield, wave_budgets[2], signals)

    # Early stop check
    if early_stopping and max_waves >= 2:
        should_stop, reason = _should_early_stop(all_findings, signals)
        if should_stop:
            results["early_stopped"] = True
            results["early_stop_reason"] = reason
            print(f"[nuclei] Early stop after Wave 2: {reason}", file=sys.stderr)
            results["vulnerabilities"] = deduplicate_nuclei_findings(all_findings)
            results["signals"] = signals
            results["total_duration_seconds"] = int(time.time() - total_start)
            _finalize_template_metrics()
            return _finalize_and_return()

    if max_waves < 3:
        results["vulnerabilities"] = deduplicate_nuclei_findings(all_findings)
        results["signals"] = signals
        results["total_duration_seconds"] = int(time.time() - total_start)
        _finalize_template_metrics()
        return _finalize_and_return()

    # =========================================================================
    # WAVE 3: Injection Templates (if signals suggest vulnerabilities)
    # =========================================================================
    wave3_budget = wave_budgets[2]
    wave3_yield = YieldMetrics()  # Default empty metrics if wave skipped

    if signals.get("sql_errors") or signals.get("xss_reflection") or signals.get("file_inclusion"):
        print(f"[nuclei] Wave 3: Injection-focused templates (budget: {wave3_budget.max_duration}s)", file=sys.stderr)
        wave3_tags = ["sqli", "xss", "ssti", "xxe", "ssrf", "lfi", "rce", "injection"]
        # Exclude already-run tags
        already_run = set(wave1_tags + wave2_tags)
        wave3_tags = [t for t in wave3_tags if t not in already_run]

        if wave3_tags:
            wave3 = await _run_nuclei_wave(
                url,
                wave3_tags,
                timeout=wave3_budget.max_duration,
                rate_limit=30,
                exclude_tags=exclude_tags,
                targets=targets,
                auth_session=auth_session,
                max_targets=max_targets,
            )
            all_findings.extend(wave3["findings"])
            signals = _update_signals(signals, wave3["findings"])
            templates_executed_total += wave3.get("templates_executed", 0)
            matched_templates.update(wave3.get("matched_template_ids", []))

            # Calculate yield metrics for wave 3
            wave3_yield = calculate_yield_metrics(wave3["findings"], wave3["duration_seconds"])
            results["yield_metrics"].append({
                "wave": 3,
                "findings_count": wave3_yield.findings_count,
                "duration_seconds": wave3_yield.duration_seconds,
                "findings_per_minute": round(wave3_yield.findings_per_minute, 2),
            })

            results["waves_completed"] = 3
            results["wave_stats"].append({
                "wave": 3,
                "tags": wave3_tags,
                "findings": len(wave3["findings"]),
                "duration": wave3["duration_seconds"],
                "budget_max": wave3_budget.max_duration,
                "yield_per_min": round(wave3_yield.findings_per_minute, 2),
            })
            print(f"[nuclei] Wave 3 complete: {len(wave3['findings'])} findings in {wave3['duration_seconds']:.0f}s (yield: {wave3_yield.findings_per_minute:.1f}/min)", file=sys.stderr)

            # Adjust Wave 4 budget based on Wave 3 yield
            if max_waves >= 4:
                wave_budgets[3] = adjust_next_wave_budget(wave3_yield, wave_budgets[3], signals)
    else:
        print(f"[nuclei] Skipping Wave 3: No injection signals detected", file=sys.stderr)
        results["waves_completed"] = 2

    # Early stop check
    if early_stopping and max_waves >= 3:
        should_stop, reason = _should_early_stop(all_findings, signals)
        if should_stop:
            results["early_stopped"] = True
            results["early_stop_reason"] = reason
            print(f"[nuclei] Early stop after Wave 3: {reason}", file=sys.stderr)
            results["vulnerabilities"] = deduplicate_nuclei_findings(all_findings)
            results["signals"] = signals
            results["total_duration_seconds"] = int(time.time() - total_start)
            _finalize_template_metrics()
            return _finalize_and_return()

    if max_waves < 4:
        results["vulnerabilities"] = deduplicate_nuclei_findings(all_findings)
        results["signals"] = signals
        results["total_duration_seconds"] = int(time.time() - total_start)
        _finalize_template_metrics()
        return _finalize_and_return()

    # =========================================================================
    # WAVE 4: Deep Scan (only if promising signals)
    # =========================================================================
    wave4_budget = wave_budgets[3]

    if not early_stopping or _has_promising_signals(signals, all_findings):
        print(f"[nuclei] Wave 4: Deep comprehensive scan (budget: {wave4_budget.max_duration}s)", file=sys.stderr)
        # Run broader scan with most categories
        wave4_tags = ["network", "iot", "cloud", "panel", "wordpress", "joomla", "drupal",
                      "cms", "cve", "osint", "tech", "token", "api", "backup", "config"]
        already_run = set(wave1_tags + wave2_tags)
        wave4_tags = [t for t in wave4_tags if t not in already_run]

        if wave4_tags:
            wave4 = await _run_nuclei_wave(
                url,
                wave4_tags,
                timeout=wave4_budget.max_duration,
                rate_limit=25,
                exclude_tags=exclude_tags,
                targets=targets,
                auth_session=auth_session,
                max_targets=max_targets,
            )
            all_findings.extend(wave4["findings"])
            signals = _update_signals(signals, wave4["findings"])
            templates_executed_total += wave4.get("templates_executed", 0)
            matched_templates.update(wave4.get("matched_template_ids", []))

            # Calculate yield metrics for wave 4
            wave4_yield = calculate_yield_metrics(wave4["findings"], wave4["duration_seconds"])
            results["yield_metrics"].append({
                "wave": 4,
                "findings_count": wave4_yield.findings_count,
                "duration_seconds": wave4_yield.duration_seconds,
                "findings_per_minute": round(wave4_yield.findings_per_minute, 2),
            })

            results["waves_completed"] = 4
            results["wave_stats"].append({
                "wave": 4,
                "tags": wave4_tags[:10],
                "findings": len(wave4["findings"]),
                "duration": wave4["duration_seconds"],
                "budget_max": wave4_budget.max_duration,
                "yield_per_min": round(wave4_yield.findings_per_minute, 2),
            })
            print(f"[nuclei] Wave 4 complete: {len(wave4['findings'])} findings in {wave4['duration_seconds']:.0f}s (yield: {wave4_yield.findings_per_minute:.1f}/min)", file=sys.stderr)
    else:
        print(f"[nuclei] Skipping Wave 4: No promising signals", file=sys.stderr)

    # Finalize results
    results["vulnerabilities"] = deduplicate_nuclei_findings(all_findings)
    results["signals"] = signals
    results["total_duration_seconds"] = int(time.time() - total_start)
    _finalize_template_metrics()
    results["scan_completed"] = True

    # Separate info findings
    vuln_findings = []
    info_findings = []
    for f in results["vulnerabilities"]:
        if f.get("severity", "").lower() in ["critical", "high", "medium", "low"]:
            vuln_findings.append(f)
        else:
            info_findings.append(f)
    results["vulnerabilities"] = vuln_findings
    results["info"] = info_findings

    print(f"[nuclei] Staged scan complete: {len(vuln_findings)} vulns, {len(info_findings)} info in {results['total_duration_seconds']}s", file=sys.stderr)

    return results
