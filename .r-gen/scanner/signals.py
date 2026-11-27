"""
Signal extraction from security tool outputs.

This module handles extracting vulnerability signals from nuclei and other
security tools to guide subsequent scan phases. Signals inform:
- Discovery: Which paths to prioritize
- Active testing: Which attack types to focus on

Extracted from scanner.py for better maintainability.
"""
from __future__ import annotations

from typing import Any

# Support both package import and script import
try:
    from .scanner_tools.signal_types import Signal, SignalSet
except ImportError:
    from scanner_tools.signal_types import Signal, SignalSet


def extract_signals_from_nuclei(nuclei_results: dict) -> SignalSet:
    """
    Extract vulnerability signals from nuclei findings for guiding later phases.

    This function goes beyond simple keyword matching to:
    1. Analyze template IDs, tags, and titles
    2. Parse response patterns and evidence
    3. Consider CVSS scores and severity
    4. Detect technology-specific vulnerabilities
    5. Track confidence levels for each signal

    These signals inform:
    - Discovery: Which paths to prioritize
    - Active testing: Which attack types to focus on

    Returns:
        SignalSet with scored signals. Backward compatible with dict-like access
        (supports .get(), [] access, and boolean checks).
    """
    signals = SignalSet()

    findings = nuclei_results.get("findings", [])
    if not findings:
        findings = nuclei_results.get("vulnerabilities", [])

    # Enhanced patterns for signal detection
    sql_patterns = ["sql", "database", "query", "mysql", "postgres", "sqlite", "mssql",
                    "oracle", "mariadb", "nosql", "mongodb", "injection"]
    xss_patterns = ["xss", "reflect", "cross-site", "script", "dom-based", "stored-xss"]
    auth_patterns = ["auth", "login", "jwt", "session", "token", "oauth", "saml", "credential",
                     "password", "apikey", "api-key", "bearer", "cookie"]
    lfi_patterns = ["lfi", "rfi", "path-traversal", "file-inclusion", "directory-traversal",
                    "file-read", "arbitrary-file"]
    ssrf_patterns = ["ssrf", "server-side-request", "url-fetch", "redirect", "open-redirect"]
    rce_patterns = ["rce", "command-injection", "code-execution", "remote-code", "exec", "shell",
                    "deserialization", "template-injection", "ssti"]
    api_patterns = ["api", "graphql", "rest", "swagger", "openapi", "endpoint", "webhook"]
    info_patterns = ["disclosure", "exposure", "leak", "sensitive", "debug", "stack-trace",
                     "error-message", "verbose"]
    misconfig_patterns = ["misconfig", "misconfiguration", "insecure", "default", "weak",
                          "cors", "headers", "security-header"]
    default_cred_patterns = ["default-login", "default-credential", "admin-panel",
                             "hardcoded", "weak-password"]

    for finding in findings:
        template_id = str(finding.get("template_id", "") or finding.get("template-id", "")).lower()
        tags = [t.lower() for t in (finding.get("tags", []) or [])]
        title = str(finding.get("title", "") or finding.get("info", {}).get("name", "")).lower()
        matcher_name = str(finding.get("matcher-name", "") or finding.get("matcher_name", "")).lower()
        severity = str(finding.get("severity", "") or finding.get("info", {}).get("severity", "")).lower()
        evidence = finding.get("evidence", {}) or {}
        matched_at = finding.get("matched-at", "") or finding.get("matched_at", "") or ""
        extracted_results = finding.get("extracted-results", []) or []

        # Combine all text for pattern matching
        all_text = f"{template_id} {title} {matcher_name} {' '.join(tags)}"

        # Extract CVSS if available
        cvss = 0.0
        info = finding.get("info", {})
        if info:
            classification = info.get("classification", {})
            if classification:
                cvss = float(classification.get("cvss-score", 0) or classification.get("cvss_score", 0) or 0)

        # Track severity counts
        if severity == "critical" or cvss >= 9.0:
            signals.critical_count += 1
        elif severity == "high" or cvss >= 7.0:
            signals.high_count += 1

        # SQL/Database signals (enhanced with evidence analysis)
        if any(p in all_text for p in sql_patterns):
            confidence = 0.9 if cvss >= 7.0 else 0.7
            if not signals.sql_errors.active or confidence > signals.sql_errors.confidence:
                signals.sql_errors = Signal(
                    active=True,
                    confidence=confidence,
                    evidence=[f"template:{template_id}"],
                    source="nuclei"
                )
            else:
                signals.sql_errors.add_evidence(f"template:{template_id}")

        # Also check evidence for SQL error patterns
        evidence_str = str(evidence).lower() if evidence else ""
        extracted_str = " ".join(str(e) for e in extracted_results).lower()
        sql_error_keywords = ["sql syntax", "mysql", "ora-", "pg_", "sqlite", "mssql", "syntax error"]
        if any(err in evidence_str or err in extracted_str for err in sql_error_keywords):
            signals.sql_errors = Signal(
                active=True,
                confidence=0.95,
                evidence=signals.sql_errors.evidence + ["error_pattern_in_response"],
                source="nuclei"
            )

        # XSS/Reflection signals
        if any(p in all_text for p in xss_patterns):
            confidence = 0.85 if cvss >= 6.0 else 0.6
            if not signals.xss_reflection.active or confidence > signals.xss_reflection.confidence:
                signals.xss_reflection = Signal(
                    active=True,
                    confidence=confidence,
                    evidence=[f"template:{template_id}"],
                    source="nuclei"
                )
            else:
                signals.xss_reflection.add_evidence(f"template:{template_id}")

        # Auth signals
        if any(p in all_text for p in auth_patterns):
            confidence = 0.9 if severity in ["critical", "high"] else 0.7
            if not signals.auth_issues.active or confidence > signals.auth_issues.confidence:
                signals.auth_issues = Signal(
                    active=True,
                    confidence=confidence,
                    evidence=[f"template:{template_id}"],
                    source="nuclei"
                )
            else:
                signals.auth_issues.add_evidence(f"template:{template_id}")

        # LFI/RFI signals
        if any(p in all_text for p in lfi_patterns):
            if not signals.file_inclusion.active:
                signals.file_inclusion = Signal(
                    active=True,
                    confidence=0.9,
                    evidence=[f"template:{template_id}"],
                    source="nuclei"
                )
            else:
                signals.file_inclusion.add_evidence(f"template:{template_id}")

        # SSRF signals
        if any(p in all_text for p in ssrf_patterns):
            if not signals.ssrf_potential.active:
                signals.ssrf_potential = Signal(
                    active=True,
                    confidence=0.8,
                    evidence=[f"template:{template_id}"],
                    source="nuclei"
                )
            else:
                signals.ssrf_potential.add_evidence(f"template:{template_id}")

        # RCE signals
        if any(p in all_text for p in rce_patterns):
            if not signals.rce_potential.active:
                signals.rce_potential = Signal(
                    active=True,
                    confidence=0.95,
                    evidence=[f"template:{template_id}"],
                    source="nuclei"
                )
            else:
                signals.rce_potential.add_evidence(f"template:{template_id}")

        # API exposure signals
        if any(p in all_text for p in api_patterns):
            if not signals.api_exposure.active:
                signals.api_exposure = Signal(
                    active=True,
                    confidence=0.7,
                    evidence=[f"template:{template_id}"],
                    source="nuclei"
                )
            else:
                signals.api_exposure.add_evidence(f"template:{template_id}")

        # Information disclosure signals
        if any(p in all_text for p in info_patterns):
            if not signals.information_disclosure.active:
                signals.information_disclosure = Signal(
                    active=True,
                    confidence=0.7,
                    evidence=[f"template:{template_id}"],
                    source="nuclei"
                )
            else:
                signals.information_disclosure.add_evidence(f"template:{template_id}")

        # Misconfiguration signals
        if any(p in all_text for p in misconfig_patterns):
            if not signals.misconfig.active:
                signals.misconfig = Signal(
                    active=True,
                    confidence=0.7,
                    evidence=[f"template:{template_id}"],
                    source="nuclei"
                )
            else:
                signals.misconfig.add_evidence(f"template:{template_id}")

        # Default credentials signals
        if any(p in all_text for p in default_cred_patterns):
            if not signals.default_creds.active:
                signals.default_creds = Signal(
                    active=True,
                    confidence=0.85,
                    evidence=[f"template:{template_id}"],
                    source="nuclei"
                )
            else:
                signals.default_creds.add_evidence(f"template:{template_id}")

        # Track high-value targets (URLs where critical/high findings were found)
        if (severity in ["critical", "high"] or cvss >= 7.0) and matched_at:
            signals.high_value_targets.append(matched_at)

        # Technology-specific signals from tags
        tech_tags = ["wordpress", "drupal", "joomla", "spring", "struts", "rails",
                     "django", "laravel", "express", "react", "angular", "vue",
                     "tomcat", "nginx", "apache", "iis", "jenkins", "gitlab",
                     "kubernetes", "docker", "aws", "azure", "gcp"]
        for tech in tech_tags:
            if tech in tags or tech in template_id:
                if tech not in signals.tech_specific:
                    signals.tech_specific[tech] = []
                signals.tech_specific[tech].append(template_id)

    # Deduplicate high-value targets
    signals.high_value_targets = list(set(signals.high_value_targets))[:20]

    return signals


def merge_signals(signal_sets: list[SignalSet]) -> SignalSet:
    """Merge multiple signal sets into one, keeping highest confidence values."""
    if not signal_sets:
        return SignalSet()

    merged = SignalSet()

    for signals in signal_sets:
        # Merge counts
        merged.critical_count += signals.critical_count
        merged.high_count += signals.high_count

        # Merge signal attributes (keep highest confidence)
        signal_attrs = [
            'sql_errors', 'xss_reflection', 'auth_issues', 'file_inclusion',
            'ssrf_potential', 'rce_potential', 'api_exposure',
            'information_disclosure', 'misconfig', 'default_creds'
        ]

        for attr in signal_attrs:
            current = getattr(merged, attr)
            new = getattr(signals, attr)
            if new.active:
                if not current.active or new.confidence > current.confidence:
                    setattr(merged, attr, Signal(
                        active=True,
                        confidence=new.confidence,
                        evidence=list(set(current.evidence + new.evidence)),
                        source=new.source
                    ))
                else:
                    current.evidence = list(set(current.evidence + new.evidence))

        # Merge high-value targets
        merged.high_value_targets.extend(signals.high_value_targets)

        # Merge tech-specific
        for tech, templates in signals.tech_specific.items():
            if tech not in merged.tech_specific:
                merged.tech_specific[tech] = []
            merged.tech_specific[tech].extend(templates)

    # Deduplicate
    merged.high_value_targets = list(set(merged.high_value_targets))[:50]
    for tech in merged.tech_specific:
        merged.tech_specific[tech] = list(set(merged.tech_specific[tech]))

    return merged


def signals_to_dict(signals: SignalSet) -> dict[str, Any]:
    """Convert SignalSet to dictionary for serialization."""
    return {
        "critical_count": signals.critical_count,
        "high_count": signals.high_count,
        "sql_errors": signals.sql_errors.active,
        "xss_reflection": signals.xss_reflection.active,
        "auth_issues": signals.auth_issues.active,
        "file_inclusion": signals.file_inclusion.active,
        "ssrf_potential": signals.ssrf_potential.active,
        "rce_potential": signals.rce_potential.active,
        "api_exposure": signals.api_exposure.active,
        "information_disclosure": signals.information_disclosure.active,
        "misconfig": signals.misconfig.active,
        "default_creds": signals.default_creds.active,
        "high_value_targets": signals.high_value_targets,
        "tech_specific": signals.tech_specific,
    }
