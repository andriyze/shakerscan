"""
Finding Validator - Verify that findings are real, not false positives.

This module provides validation logic to verify that detected vulnerabilities
are actually exploitable, reducing false positives and noise.

Philosophy: "Find less, but only real vulnerabilities."
"""

import logging
import re
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


# =============================================================================
# CONFIDENCE TIERS - Standardized confidence levels with documentation
# =============================================================================
# These tiers replace scattered magic numbers throughout the codebase.
# Each tier has a specific meaning and should be used consistently.

class ConfidenceTier:
    """
    Standardized confidence levels for finding validation.

    Usage: Use these constants instead of hardcoded float values.

    Decision tree for choosing a tier:
    1. Did we successfully exploit and extract data? → CONFIRMED (0.95)
    2. Did a trusted tool verify the vulnerability? → VERIFIED (0.90)
    3. Strong evidence but no direct proof? → HIGH (0.85)
    4. Multiple indicators suggest vulnerability? → MEDIUM_HIGH (0.75)
    5. Pattern match with some corroboration? → MEDIUM (0.65)
    6. Single indicator, needs more verification? → LOW (0.50)
    7. Possible but no strong evidence? → UNCERTAIN (0.35)
    8. Evidence suggests false positive? → LIKELY_FP (0.20)
    9. Clearly not a vulnerability? → NOT_VULN (0.10)
    """

    # Tier 1: Confirmed vulnerabilities (exploit succeeded)
    CONFIRMED = 0.95     # Proof-of-exploit succeeded, data extracted

    # Tier 2: Verified by trusted tool
    VERIFIED = 0.90      # Trusted tool (dalfox, sqlmap) confirmed vuln

    # Tier 3: High confidence based on strong evidence
    HIGH = 0.85          # Multiple strong indicators, tool-verified

    # Tier 4: Medium-high confidence
    MEDIUM_HIGH = 0.75   # Good evidence, minor uncertainty

    # Tier 5: Medium confidence
    MEDIUM = 0.65        # Pattern match + corroborating evidence

    # Tier 6: Low confidence - needs manual verification
    LOW = 0.50           # Single indicator, unconfirmed

    # Tier 7: Uncertain - likely needs more testing
    UNCERTAIN = 0.35     # Possible vuln, weak evidence

    # Tier 8: Likely false positive
    LIKELY_FP = 0.20     # Evidence suggests not a real vuln

    # Tier 9: Not a vulnerability
    NOT_VULN = 0.10      # Clearly false positive

    @classmethod
    def from_evidence_strength(cls,
                               tool_confirmed: bool = False,
                               data_extracted: bool = False,
                               pattern_matched: bool = False,
                               context_verified: bool = False,
                               error_based: bool = False) -> float:
        """
        Calculate confidence based on evidence types.

        Args:
            tool_confirmed: Trusted tool (dalfox, sqlmap) confirmed
            data_extracted: Actual data was extracted (PoE succeeded)
            pattern_matched: Payload/pattern found in response
            context_verified: Payload is in executable context
            error_based: Vulnerability inferred from error messages

        Returns:
            Confidence score 0.0-1.0
        """
        if data_extracted:
            return cls.CONFIRMED
        if tool_confirmed and context_verified:
            return cls.VERIFIED
        if tool_confirmed:
            return cls.HIGH
        if pattern_matched and context_verified:
            return cls.MEDIUM_HIGH
        if pattern_matched:
            return cls.MEDIUM
        if error_based:
            return cls.LOW
        return cls.UNCERTAIN


# Minimum confidence required to report at each severity level
# These thresholds prevent noisy low-confidence findings from being reported
# at high severity levels.
CONFIDENCE_THRESHOLDS = {
    "critical": ConfidenceTier.HIGH,      # 0.85 - only high confidence criticals
    "high": ConfidenceTier.MEDIUM_HIGH,   # 0.75 - need decent evidence for high
    "medium": ConfidenceTier.MEDIUM,      # 0.65 - medium allows some uncertainty
    "low": ConfidenceTier.UNCERTAIN,      # 0.35 - low severity can be uncertain
    "info": 0.0                           # Always report info findings
}


# =============================================================================
# VALIDATION RESULT
# =============================================================================

class ValidationResult:
    """Result of finding validation."""

    def __init__(
        self,
        verified: bool = False,
        confidence: float = 0.5,
        evidence: str | None = None,
        reason: str | None = None,
        downgrade_to: str | None = None,
        evidence_level: str | None = None,
    ):
        self.verified = verified
        self.confidence = confidence
        self.evidence = evidence
        self.reason = reason
        self.downgrade_to = downgrade_to  # Severity to downgrade to, if any
        if evidence_level:
            self.evidence_level = evidence_level
        elif verified:
            self.evidence_level = "confirmed_exploit"
        elif confidence >= ConfidenceTier.MEDIUM:
            self.evidence_level = "strong_indicator"
        else:
            self.evidence_level = "weak_indicator"

    def to_dict(self) -> dict[str, Any]:
        return {
            "verified": self.verified,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "reason": self.reason,
            "downgrade_to": self.downgrade_to,
            "evidence_level": self.evidence_level,
        }


# =============================================================================
# XSS VALIDATION
# =============================================================================

# Contexts where XSS payloads are NOT executable
SAFE_CONTEXTS = [
    r'&lt;',  # HTML entity encoded
    r'&gt;',
    r'&#',    # Numeric entity
    r'%3C',   # URL encoded
    r'%3E',
    r'\\x3c', # JS escaped
    r'\\x3e',
    r'\\u003c',
    r'\\u003e',
]

# Patterns indicating payload is in executable context
EXECUTABLE_CONTEXTS = [
    r'<script[^>]*>[^<]*{payload}',  # Inside script tag
    r'on\w+\s*=\s*["\'][^"\']*{payload}',  # In event handler
    r'javascript:[^"\']*{payload}',  # In javascript: URL
    r'<[^>]+\s+src\s*=\s*["\'][^"\']*{payload}',  # In src attribute
    r'<[^>]+\s+href\s*=\s*["\'][^"\']*{payload}',  # In href attribute
]


def _finding_has_execution_proof(finding: dict[str, Any]) -> bool:
    """Return True when XSS evidence includes execution proof, not just reflection."""
    if finding.get("poe_result", {}).get("proven") is True:
        return True
    if finding.get("browser_proof"):
        return True
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    evidence_text = str(evidence).lower()
    proof_markers = (
        "browser proof",
        "payload executed",
        "dialog",
        "console proof",
        "dom proof",
        "execution proof",
    )
    return any(marker in evidence_text for marker in proof_markers)


def validate_xss(
    finding: dict[str, Any],
    response_body: str | None = None
) -> ValidationResult:
    """
    Validate XSS finding by checking if payload is in executable context.

    Args:
        finding: The XSS finding to validate
        response_body: Optional response body to analyze

    Returns:
        ValidationResult with confidence score
    """
    evidence = finding.get("evidence", {})
    tool = finding.get("tool", "").lower()
    payload = evidence.get("payload", "") or evidence.get("detail", {}).get("payload", "")

    # Trust dalfox findings - it does its own verification
    # Dalfox only reports confirmed XSS, not potential
    if tool == "dalfox":
        detail = evidence.get("detail", {})
        # Dalfox "Verified" type is highest confidence
        if detail.get("type") == "Verified" or "verified" in str(detail).lower():
            return ValidationResult(
                verified=True,
                confidence=0.95,
                evidence=payload[:100] if payload else "dalfox verified",
                reason="Dalfox confirmed verified XSS"
            )
        # Even non-verified dalfox findings are reliable (it has built-in verification)
        return ValidationResult(
            verified=True,
            confidence=0.85,
            evidence=payload[:100] if payload else "dalfox finding",
            reason="Dalfox reported XSS (tool has built-in verification)"
        )

    # DOM-based XSS is static analysis (source-to-sink) and may not have a payload
    if tool == "dom_xss":
        source_nearby = bool(evidence.get("source_nearby") or evidence.get("source_pattern"))
        # Higher confidence to ensure DOM XSS findings pass validation filters
        # Static analysis with source_nearby is reliable enough to report
        confidence = 0.70 if source_nearby else 0.50
        return ValidationResult(
            verified=False,
            confidence=confidence,
            evidence=evidence.get("sink_type") or evidence.get("file") or "dom-xss",
            reason="DOM XSS static analysis (source-to-sink)"
        )

    # If no payload from non-dalfox tools, can't validate
    if not payload:
        return ValidationResult(
            verified=False,
            confidence=0.3,
            reason="No payload to verify"
        )

    # If no response to check, trust the tool but with reduced confidence
    if not response_body:
        # Check if tool reported as verified
        detail = evidence.get("detail", {})
        if (
            detail.get("type") == "Verified"
            or "verified" in str(detail).lower()
            or (finding.get("verified") is True and _finding_has_execution_proof(finding))
        ):
            return ValidationResult(
                verified=True,
                confidence=0.85,
                evidence=payload[:100] if payload else "xss execution proof",
                reason="Tool reported execution-verified XSS",
                evidence_level="confirmed_exploit",
            )
        # Has payload but no response/context proof. This is a lead, not verified XSS.
        return ValidationResult(
            verified=False,
            confidence=0.55,
            evidence=payload[:100],
            reason="XSS payload detected, response not available for context verification",
            downgrade_to="medium",
            evidence_level="weak_indicator",
        )

    # Check if payload is present in response
    if payload not in response_body:
        return ValidationResult(
            verified=False,
            confidence=0.1,
            reason="Payload not reflected in response"
        )

    # Check if payload is in safe (escaped) context
    for safe_pattern in SAFE_CONTEXTS:
        if re.search(safe_pattern + re.escape(payload), response_body, re.I):
            return ValidationResult(
                verified=False,
                confidence=0.2,
                reason=f"Payload is escaped/encoded ({safe_pattern})",
                downgrade_to="info"
            )

    # Check if in executable context
    for context_pattern in EXECUTABLE_CONTEXTS:
        pattern = context_pattern.replace("{payload}", re.escape(payload))
        if re.search(pattern, response_body, re.I | re.S):
            return ValidationResult(
                verified=True,
                confidence=0.95,
                evidence=f"Payload in executable context: {context_pattern.split('{')[0]}",
                reason="XSS payload is in executable context"
            )

    # Payload reflected but context unclear
    return ValidationResult(
        verified=False,
        confidence=0.65,
        reason="Payload reflected, context unclear - manual verification recommended",
        downgrade_to="medium",
        evidence_level="strong_indicator",
    )


# =============================================================================
# SQL INJECTION VALIDATION
# =============================================================================

# Patterns indicating actual SQL data extraction
SQL_DATA_PATTERNS = [
    r'@[a-z_]+\s*=',  # SQL variables
    r'\d+\s*rows?\s+affected',  # Rows affected
    r'select\s+.*\s+from\s+',  # SELECT statement echo
    r'syntax\s+error.*sql',  # SQL syntax error (useful but not confirmed)
    r'unclosed\s+quotation',  # SQL error
    r'quoted\s+string\s+not\s+properly\s+terminated',
    r'mysql_fetch',  # PHP MySQL error
    r'pg_query',  # PostgreSQL error
    r'sqlite3\.OperationalError',  # SQLite error
    r'ORA-\d{5}',  # Oracle error
    r'Microsoft\s+SQL\s+Server',  # MSSQL error
]

# Patterns indicating CONFIRMED data extraction (high confidence)
SQL_CONFIRMED_PATTERNS = [
    r'information_schema',  # Schema access
    r'table_name\s*[=:]\s*[\'"]?\w+',  # Table name extracted
    r'column_name\s*[=:]\s*[\'"]?\w+',  # Column name extracted
    r'@@version',  # Version extraction
    r'user\(\)\s*[=:]\s*[\'"]?\w+',  # User extraction
    r'database\(\)\s*[=:]\s*[\'"]?\w+',  # Database extraction
]


def validate_sqli(
    finding: dict[str, Any],
    response_body: str | None = None
) -> ValidationResult:
    """
    Validate SQL injection finding.

    Args:
        finding: The SQLi finding to validate
        response_body: Optional response body to analyze

    Returns:
        ValidationResult with confidence score
    """
    evidence = finding.get("evidence", {})
    summary = evidence.get("summary", "")

    # SQLMap says "possible SQLi" vs confirmed
    if "possible" in summary.lower():
        # Just possible, not confirmed
        return ValidationResult(
            verified=False,
            confidence=0.6,
            reason="SQLMap reported as possible, not confirmed"
        )

    if "is vulnerable" in summary.lower() or "confirmed" in summary.lower():
        return ValidationResult(
            verified=True,
            confidence=0.9,
            reason="SQLMap confirmed vulnerability"
        )

    # If we have response body, check for SQL indicators
    if response_body:
        # Check for confirmed extraction patterns (high confidence)
        for pattern in SQL_CONFIRMED_PATTERNS:
            if re.search(pattern, response_body, re.I):
                return ValidationResult(
                    verified=True,
                    confidence=0.95,
                    evidence=f"SQL data extracted: {pattern}",
                    reason="Confirmed SQL injection with data extraction"
                )

        # Check for SQL error patterns (medium confidence)
        for pattern in SQL_DATA_PATTERNS:
            if re.search(pattern, response_body, re.I):
                return ValidationResult(
                    verified=False,
                    confidence=0.75,
                    evidence=f"SQL error/indicator: {pattern}",
                    reason="SQL error indicates potential injection but does not prove exploitability",
                    evidence_level="strong_indicator",
                )

    # Default: can't verify
    return ValidationResult(
        verified=False,
        confidence=0.5,
        reason="Cannot verify SQL injection"
    )


# =============================================================================
# EXPOSED FILE VALIDATION
# =============================================================================

# Expected content markers for common exposed files
EXPOSED_FILE_MARKERS = {
    ".git/config": {
        "markers": ["[core]", "[remote", "repositoryformatversion", "filemode"],
        "min_length": 20,
        "not_html": True
    },
    ".git/HEAD": {
        "markers": ["ref: refs/heads/", "ref: refs/tags/"],
        "min_length": 10,
        "max_length": 200,
        "not_html": True
    },
    ".env": {
        "markers": ["="],  # Must have at least one KEY=VALUE
        "pattern": r"^[A-Z][A-Z0-9_]*=",  # Standard env var format
        "min_length": 5,
        "not_html": True
    },
    "wp-config.php": {
        "markers": ["DB_NAME", "DB_PASSWORD", "DB_USER", "<?php"],
        "not_markers": ["<html", "<!DOCTYPE"],  # Should NOT be served as HTML
        "min_length": 100
    },
    ".htpasswd": {
        "markers": [":"],
        "pattern": r"^[a-zA-Z0-9_-]+:\$",  # user:$hash format
        "min_length": 10,
        "not_html": True
    },
    "id_rsa": {
        "markers": ["-----BEGIN", "PRIVATE KEY-----"],
        "min_length": 200,
        "not_html": True
    },
    ".aws/credentials": {
        "markers": ["aws_access_key_id", "aws_secret_access_key"],
        "min_length": 50,
        "not_html": True
    }
}


def validate_exposed_file(
    finding: dict[str, Any],
    response_body: str | None = None,
    response_headers: dict[str, str] | None = None
) -> ValidationResult:
    """
    Validate exposed file finding by checking content.

    Args:
        finding: The exposed file finding to validate
        response_body: Response body content
        response_headers: Response headers

    Returns:
        ValidationResult with confidence score
    """
    evidence = finding.get("evidence", {})
    path = evidence.get("path", "").lower()

    if not response_body:
        # Some scanners intentionally avoid storing raw secret contents in evidence.
        # Fall back to detector metadata when confidence is already high.
        confidence_label = str(evidence.get("confidence", "")).strip().lower()
        has_html = bool(evidence.get("has_html"))
        markers = evidence.get("markers")
        markers = markers if isinstance(markers, list) else []
        sensitive_hints = {
            ".env",
            ".git/config",
            ".git/head",
            ".htpasswd",
            "id_rsa",
            ".aws/credentials",
            "wp-config.php",
        }
        looks_sensitive = any(hint in path for hint in sensitive_hints)
        marker_signals = {"credential_like", "dotenv_format", "secret_like", "key_like"}
        has_sensitive_marker = any(str(m).strip().lower() in marker_signals for m in markers)

        if confidence_label == "high" and not has_html and (looks_sensitive or has_sensitive_marker):
            return ValidationResult(
                verified=True,
                confidence=0.85,
                evidence="Validated from detector metadata (body redacted)",
                reason="High-confidence exposed file with sensitive markers",
            )

        if confidence_label == "medium" and not has_html and looks_sensitive and has_sensitive_marker:
            return ValidationResult(
                verified=True,
                confidence=0.75,
                evidence="Validated from detector metadata (body redacted)",
                reason="Medium-confidence exposed file with sensitive path and markers",
            )

        return ValidationResult(
            verified=False,
            confidence=0.4,
            reason="No response body to verify"
        )

    # Check if response is HTML (likely custom 404)
    is_html = any(marker in response_body.lower()[:500] for marker in [
        "<!doctype html", "<html", "<head>", "<body>", "text/html"
    ])

    # Find matching file type
    file_validator = None
    for file_pattern, validator in EXPOSED_FILE_MARKERS.items():
        if file_pattern in path:
            file_validator = validator
            break

    if not file_validator:
        # Generic validation for unknown file types
        if is_html:
            return ValidationResult(
                verified=False,
                confidence=0.2,
                reason="Response is HTML - likely custom 404 page",
                downgrade_to="info"
            )
        return ValidationResult(
            verified=True,
            confidence=0.6,
            reason="File exists but content not validated"
        )

    # Apply file-specific validation

    # Check not_html constraint
    if file_validator.get("not_html") and is_html:
        return ValidationResult(
            verified=False,
            confidence=0.1,
            reason="Response is HTML but file should be plaintext",
            downgrade_to="info"
        )

    # Check min_length
    if len(response_body) < file_validator.get("min_length", 0):
        return ValidationResult(
            verified=False,
            confidence=0.3,
            reason=f"Response too short (expected min {file_validator['min_length']} chars)",
            downgrade_to="info"
        )

    # Check max_length
    if file_validator.get("max_length") and len(response_body) > file_validator["max_length"]:
        return ValidationResult(
            verified=False,
            confidence=0.3,
            reason=f"Response too long (expected max {file_validator['max_length']} chars)",
            downgrade_to="info"
        )

    # Check required markers
    markers = file_validator.get("markers", [])
    markers_found = sum(1 for m in markers if m.lower() in response_body.lower())

    if markers and markers_found == 0:
        return ValidationResult(
            verified=False,
            confidence=0.2,
            reason=f"No expected content markers found ({markers[:3]}...)",
            downgrade_to="info"
        )

    # Check not_markers (things that should NOT be present)
    not_markers = file_validator.get("not_markers", [])
    for nm in not_markers:
        if nm.lower() in response_body.lower():
            return ValidationResult(
                verified=False,
                confidence=0.2,
                reason=f"Found unexpected content: {nm}",
                downgrade_to="info"
            )

    # Check regex pattern
    pattern = file_validator.get("pattern")
    if pattern:
        if not re.search(pattern, response_body, re.M):
            return ValidationResult(
                verified=False,
                confidence=0.4,
                reason="Content doesn't match expected format",
                downgrade_to="low"
            )

    # All checks passed
    marker_confidence = min(0.95, 0.7 + (markers_found / max(len(markers), 1)) * 0.25)

    return ValidationResult(
        verified=True,
        confidence=marker_confidence,
        evidence=f"Found {markers_found}/{len(markers)} content markers",
        reason="File content validated"
    )


# =============================================================================
# SSRF VALIDATION
# =============================================================================

# Patterns indicating successful SSRF (actual internal access)
SSRF_CONFIRMED_PATTERNS = [
    r'ami-[a-f0-9]+',  # AWS instance metadata
    r'instance-id',
    r'iam/security-credentials',
    r'169\.254\.169\.254',
    r'metadata\.google\.internal',
    r'root:.*:0:0:',  # /etc/passwd content
    r'localhost.*refused',  # Internal port scan indicator
    r'\["127\.0\.0\.1"\]',  # Internal IP in response
]

# Patterns that suggest SSRF but need more verification
SSRF_POSSIBLE_PATTERNS = [
    r'connection\s+refused',
    r'no\s+route\s+to\s+host',
    r'network\s+is\s+unreachable',
    r'timeout',
    r'internal\s+server\s+error',
]


def validate_ssrf(
    finding: dict[str, Any],
    response_body: str | None = None
) -> ValidationResult:
    """
    Validate SSRF finding by checking for internal data access.
    """
    evidence = finding.get("evidence", {})

    if not response_body:
        # Check if evidence shows confirmed access
        evidence_str = str(evidence).lower()
        if any(pattern in evidence_str for pattern in ['metadata', '169.254', 'internal']):
            return ValidationResult(
                verified=True,
                confidence=0.75,
                reason="SSRF evidence suggests internal access"
            )
        return ValidationResult(
            verified=False,
            confidence=0.5,
            reason="Cannot verify SSRF without response"
        )

    # Check for confirmed SSRF patterns
    for pattern in SSRF_CONFIRMED_PATTERNS:
        if re.search(pattern, response_body, re.I):
            return ValidationResult(
                verified=True,
                confidence=0.95,
                evidence=f"Internal data accessed: {pattern}",
                reason="Confirmed SSRF - internal data retrieved"
            )

    # Check for possible SSRF patterns (lower confidence)
    for pattern in SSRF_POSSIBLE_PATTERNS:
        if re.search(pattern, response_body, re.I):
            return ValidationResult(
                verified=True,
                confidence=0.65,
                evidence=f"Network behavior indicates SSRF: {pattern}",
                reason="Possible SSRF - internal network interaction"
            )

    return ValidationResult(
        verified=False,
        confidence=0.4,
        reason="No SSRF indicators found in response"
    )


# =============================================================================
# XXE VALIDATION
# =============================================================================

# Patterns indicating successful XXE
XXE_CONFIRMED_PATTERNS = [
    r'root:.*:0:0:',  # /etc/passwd
    r'/bin/bash',
    r'/bin/sh',
    r'daemon:',
    r'nobody:',
    r'ami-[a-f0-9]+',  # AWS metadata via XXE
    r'<\?xml.*ENTITY',  # Entity processed
]

# Patterns indicating XXE was attempted but blocked
XXE_BLOCKED_PATTERNS = [
    r'external\s+entity.*not\s+allowed',
    r'entity\s+reference.*loop',
    r'DOCTYPE.*forbidden',
    r'DTD.*not\s+allowed',
    r'parser\s+error.*entity',
]


def validate_xxe(
    finding: dict[str, Any],
    response_body: str | None = None
) -> ValidationResult:
    """
    Validate XXE finding by checking for file/data extraction.
    """
    evidence = finding.get("evidence", {})

    if not response_body:
        # Check evidence for indicators
        evidence_str = str(evidence).lower()
        if 'root:' in evidence_str or '/etc/passwd' in evidence_str:
            return ValidationResult(
                verified=True,
                confidence=0.85,
                reason="XXE evidence shows file extraction"
            )
        return ValidationResult(
            verified=False,
            confidence=0.5,
            reason="Cannot verify XXE without response"
        )

    # Skip if response is clearly HTML documentation/error page
    if re.search(r'<title>.*error.*</title>', response_body, re.I):
        return ValidationResult(
            verified=False,
            confidence=0.2,
            reason="Response appears to be error page",
            downgrade_to="info"
        )

    # Check for confirmed XXE patterns
    for pattern in XXE_CONFIRMED_PATTERNS:
        if re.search(pattern, response_body, re.I):
            return ValidationResult(
                verified=True,
                confidence=0.95,
                evidence=f"XXE extracted data: {pattern}",
                reason="Confirmed XXE - data extracted"
            )

    # Check for blocked XXE (still informational)
    for pattern in XXE_BLOCKED_PATTERNS:
        if re.search(pattern, response_body, re.I):
            return ValidationResult(
                verified=True,
                confidence=0.6,
                evidence="XXE payload processed but blocked",
                reason="XXE attempted - parser vulnerable but blocked"
            )

    return ValidationResult(
        verified=False,
        confidence=0.4,
        reason="No XXE indicators found"
    )


# =============================================================================
# PATH TRAVERSAL / LFI VALIDATION
# =============================================================================

# Patterns indicating successful path traversal
LFI_CONFIRMED_PATTERNS = [
    r'root:.*:0:0:',  # /etc/passwd
    r'\[boot\s*loader\]',  # Windows boot.ini
    r'\[operating\s*systems\]',
    r'<\?php',  # PHP source
    r'#!/bin/(bash|sh)',  # Script shebang
    r'DB_PASSWORD\s*=',  # Config file content
    r'mysql:.*localhost',
    r'\[mysqld\]',  # MySQL config
    r'DocumentRoot',  # Apache config
    r'server\s*{',  # Nginx config
]


def validate_path_traversal(
    finding: dict[str, Any],
    response_body: str | None = None
) -> ValidationResult:
    """
    Validate path traversal/LFI by checking for file content.
    """
    evidence = finding.get("evidence", {})

    if not response_body:
        return ValidationResult(
            verified=False,
            confidence=0.5,
            reason="Cannot verify path traversal without response"
        )

    # Check if response is HTML (likely not file content)
    is_html = any(marker in response_body.lower()[:200] for marker in [
        '<!doctype html', '<html', '<head>'
    ])

    if is_html:
        # Could still be path traversal if viewing HTML file
        if not any(p in response_body.lower() for p in ['root:', 'db_password', '<?php']):
            return ValidationResult(
                verified=False,
                confidence=0.2,
                reason="Response is HTML - likely not file content",
                downgrade_to="info"
            )

    # Check for confirmed patterns
    for pattern in LFI_CONFIRMED_PATTERNS:
        if re.search(pattern, response_body, re.I):
            return ValidationResult(
                verified=True,
                confidence=0.95,
                evidence=f"File content extracted: {pattern}",
                reason="Confirmed path traversal - file accessed"
            )

    # Check for partial evidence (file exists but content unclear)
    if len(response_body) > 50 and not is_html:
        return ValidationResult(
            verified=True,
            confidence=0.65,
            reason="Non-HTML response suggests file access"
        )

    return ValidationResult(
        verified=False,
        confidence=0.3,
        reason="No path traversal indicators found",
        downgrade_to="low"
    )


# =============================================================================
# OPEN REDIRECT VALIDATION
# =============================================================================

def validate_open_redirect(
    finding: dict[str, Any],
    response_body: str | None = None,
    response_headers: dict[str, str] | None = None
) -> ValidationResult:
    """
    Validate open redirect by checking if redirect actually occurs.
    """
    evidence = finding.get("evidence", {})

    # Check if we have location header evidence
    redirect_url = evidence.get("redirect_url", "") or evidence.get("location", "")
    payload = evidence.get("payload", "")

    # Check if redirect goes to external domain
    if redirect_url:
        external_indicators = ['evil.com', 'attacker.com', 'external', 'http://', '//']
        if any(ind in redirect_url.lower() for ind in external_indicators):
            # Verify it's not just a same-site redirect with path
            if not redirect_url.startswith('/') or '//' in redirect_url[:10]:
                return ValidationResult(
                    verified=True,
                    confidence=0.9,
                    evidence=f"Redirects to: {redirect_url[:100]}",
                    reason="Confirmed open redirect to external domain"
                )

    # Check response headers if available
    if response_headers:
        location = response_headers.get('location', '') or response_headers.get('Location', '')
        if location and ('://' in location or location.startswith('//')):
            return ValidationResult(
                verified=True,
                confidence=0.85,
                evidence=f"Location header: {location[:100]}",
                reason="Redirect header contains external URL"
            )

    # Check for JavaScript-based redirects in response
    if response_body:
        js_redirect_patterns = [
            r'window\.location\s*=\s*["\']https?://',
            r'location\.href\s*=\s*["\']https?://',
            r'location\.replace\s*\(\s*["\']https?://',
            r'<meta\s+http-equiv=["\']refresh["\'].*url=https?://',
        ]
        for pattern in js_redirect_patterns:
            if re.search(pattern, response_body, re.I):
                return ValidationResult(
                    verified=True,
                    confidence=0.75,
                    evidence="JavaScript/meta redirect found",
                    reason="Client-side redirect to external URL"
                )

    return ValidationResult(
        verified=False,
        confidence=0.4,
        reason="Redirect not confirmed"
    )


# =============================================================================
# COMMAND INJECTION / RCE VALIDATION
# =============================================================================

# Patterns indicating successful command execution
RCE_CONFIRMED_PATTERNS = [
    r'uid=\d+.*gid=\d+',  # id command output
    r'root:.*:0:0:',  # /etc/passwd via cat
    r'total\s+\d+\s+drwx',  # ls -la output
    r'Linux\s+\w+\s+\d+\.\d+',  # uname output
    r'Windows\s+(NT|IP)',  # Windows systeminfo
    r'Directory\s+of\s+C:',  # Windows dir
    r'\d+\.\d+\.\d+\.\d+.*TTL',  # ping output
    r'nameserver\s+\d+\.\d+',  # /etc/resolv.conf
    r'PING\s+.*\d+\s+bytes',  # ping command
]

# Time-based detection thresholds
RCE_TIME_THRESHOLD = 4.0  # seconds delay indicates sleep command worked


def validate_command_injection(
    finding: dict[str, Any],
    response_body: str | None = None
) -> ValidationResult:
    """
    Validate command injection/RCE by checking for command output.
    """
    evidence = finding.get("evidence", {})

    # Check for time-based detection
    delay = evidence.get("delay", 0) or evidence.get("response_time", 0)
    if isinstance(delay, (int, float)) and delay > RCE_TIME_THRESHOLD:
        return ValidationResult(
            verified=True,
            confidence=0.85,
            evidence=f"Response delayed by {delay:.1f}s (sleep command executed)",
            reason="Time-based command injection confirmed"
        )

    if not response_body:
        return ValidationResult(
            verified=False,
            confidence=0.5,
            reason="Cannot verify RCE without response"
        )

    # Check for command output patterns
    for pattern in RCE_CONFIRMED_PATTERNS:
        if re.search(pattern, response_body, re.I):
            return ValidationResult(
                verified=True,
                confidence=0.95,
                evidence=f"Command output detected: {pattern}",
                reason="Confirmed RCE - command executed"
            )

    # Check for error-based detection
    error_patterns = [
        r'sh:\s+\w+:\s+not\s+found',
        r'command\s+not\s+found',
        r'/bin/sh:',
        r'syntax\s+error.*unexpected',
    ]
    for pattern in error_patterns:
        if re.search(pattern, response_body, re.I):
            return ValidationResult(
                verified=True,
                confidence=0.7,
                evidence="Shell error in response",
                reason="Command injection - shell errors visible"
            )

    return ValidationResult(
        verified=False,
        confidence=0.4,
        reason="No command execution indicators found"
    )


# =============================================================================
# SUBDOMAIN TAKEOVER VALIDATION
# =============================================================================

# Known takeover fingerprints per service
# Last updated: 2025-12 - based on can-i-take-over-xyz and active testing
# Reference: https://github.com/EdOverflow/can-i-take-over-xyz
TAKEOVER_FINGERPRINTS = {
    # ===== HIGH CONFIDENCE (actively maintained services) =====
    "github.io": [
        "There isn't a GitHub Pages site here",
        "For root URLs (like http://example.com/) you must provide an index.html file",
    ],
    "amazonaws.com": [  # S3 buckets
        "NoSuchBucket",
        "The specified bucket does not exist",
        "AccessDenied",  # Sometimes indicates takeover possible
    ],
    "s3.amazonaws.com": [
        "NoSuchBucket",
        "The specified bucket does not exist",
    ],
    "azurewebsites.net": [
        "404 Web Site not found",
        "Error 404 - Web app not found",
    ],
    "blob.core.windows.net": [  # Azure Blob Storage
        "The specified resource does not exist",
        "BlobNotFound",
    ],
    "cloudapp.azure.com": [
        "404 - Page not found",
    ],

    # ===== MEDIUM CONFIDENCE (may require specific conditions) =====
    "cloudfront.net": [
        "Bad Request",
        "ERROR: The request could not be satisfied",
        "The distribution does not exist",
    ],
    "fastly.net": [
        "Fastly error: unknown domain",
    ],
    "netlify.app": [
        "Not Found - Request ID:",
    ],
    "vercel.app": [
        "The deployment could not be found",
        "DEPLOYMENT_NOT_FOUND",
    ],
    # NOTE: fly.dev and render.com removed due to overly generic fingerprints
    # that match legitimate 404 pages. These require manual verification.

    # ===== LOWER CONFIDENCE (fingerprints may have changed) =====
    "herokuapp.com": [
        "No such app",
        "no-such-app",
        "There is no app configured at that hostname",
    ],
    "shopify.com": [
        "Sorry, this shop is currently unavailable",
        "Only one step left!",
    ],
    "tumblr.com": [
        "There's nothing here",
        "Whatever you were looking for doesn't currently exist",
    ],
    "wordpress.com": [
        "Do you want to register",
    ],
    "zendesk.com": [
        "Help Center Closed",
        "This help center no longer exists",
    ],
    "pantheon.io": [
        "The gods are wise",
        "404 error unknown site",
    ],
    "ghost.io": [
        "The thing you were looking for is no longer here",
        "This site is no longer available",
    ],
    "surge.sh": [
        "project not found",
    ],
    "bitbucket.io": [
        "Repository not found",
    ],
    "readme.io": [
        "Project doesnt exist",
    ],
    "cargo.site": [
        "If this is your website and you've just created it",
    ],
}


# Fingerprints that are too generic and require additional verification
# These could match legitimate 404 pages and cause false positives
GENERIC_FINGERPRINTS = frozenset([
    "not found",
    "404",
    "page not found",
    "site not found",
])

# High-confidence services with unique, specific fingerprints
HIGH_CONFIDENCE_SERVICES = frozenset([
    "github.io",
    "amazonaws.com",
    "s3.amazonaws.com",
    "azurewebsites.net",
    "blob.core.windows.net",
])


def validate_subdomain_takeover(
    finding: dict[str, Any],
    response_body: str | None = None,
    response_headers: dict[str, str] | None = None
) -> ValidationResult:
    """
    Validate subdomain takeover by checking for service fingerprints.

    Uses a tiered confidence approach:
    - High confidence (0.95): Specific fingerprint matched for known vulnerable service
    - Medium confidence (0.70): Service identified but fingerprint is generic
    - Low confidence (0.50): CNAME points to vulnerable service but no fingerprint
    """
    evidence = finding.get("evidence", {})
    cname = evidence.get("cname", "") or evidence.get("dangling_cname", "")

    if not cname:
        return ValidationResult(
            verified=False,
            confidence=0.3,
            reason="No CNAME record found"
        )

    cname_lower = cname.lower()

    # Find matching service
    matching_service = None
    for service in TAKEOVER_FINGERPRINTS:
        if service in cname_lower:
            matching_service = service
            break

    if not matching_service:
        return ValidationResult(
            verified=False,
            confidence=0.4,
            reason=f"CNAME {cname} not a known vulnerable service"
        )

    # If we have response body, check for fingerprint
    if response_body:
        fingerprints = TAKEOVER_FINGERPRINTS[matching_service]
        body_lower = response_body.lower()

        for fingerprint in fingerprints:
            fingerprint_lower = fingerprint.lower()
            if fingerprint_lower in body_lower:
                # Check if this is a generic fingerprint that could cause false positives
                is_generic = any(
                    generic in fingerprint_lower
                    for generic in GENERIC_FINGERPRINTS
                )

                if is_generic:
                    # Generic fingerprint - require additional verification
                    # Check for absence of application content (body < 2KB and no JS/CSS)
                    is_minimal_page = (
                        len(response_body) < 2000 and
                        "<script" not in body_lower and
                        "function(" not in body_lower
                    )
                    if is_minimal_page:
                        return ValidationResult(
                            verified=True,
                            confidence=0.75,
                            evidence=f"Generic fingerprint matched: {fingerprint}",
                            reason=f"Likely takeover - {matching_service} shows minimal error page"
                        )
                    else:
                        # Has application content, likely a real 404 page
                        return ValidationResult(
                            verified=False,
                            confidence=0.45,
                            evidence="Generic fingerprint matched but page has content",
                            reason=f"Likely false positive - {matching_service} shows custom 404"
                        )
                else:
                    # Specific fingerprint - high confidence
                    confidence = 0.95 if matching_service in HIGH_CONFIDENCE_SERVICES else 0.88
                    return ValidationResult(
                        verified=True,
                        confidence=confidence,
                        evidence=f"Fingerprint matched: {fingerprint}",
                        reason=f"Confirmed takeover - {matching_service} shows unclaimed page"
                    )

    # CNAME points to vulnerable service but fingerprint not confirmed
    return ValidationResult(
        verified=False,
        confidence=0.50,
        evidence=f"CNAME points to {matching_service}",
        reason="Potential takeover - fingerprint not confirmed, verify manually"
    )


# =============================================================================
# CORS MISCONFIGURATION VALIDATION
# =============================================================================

def validate_cors(
    finding: dict[str, Any],
    response_body: str | None = None,
    response_headers: dict[str, str] | None = None
) -> ValidationResult:
    """
    Validate CORS misconfiguration by checking if it's actually exploitable.
    """
    evidence = finding.get("evidence", {})

    # Get CORS headers from evidence or response
    acao = evidence.get("access-control-allow-origin", "")
    acac = evidence.get("access-control-allow-credentials", "")

    if response_headers:
        acao = acao or response_headers.get("access-control-allow-origin", "")
        acac = acac or response_headers.get("access-control-allow-credentials", "")

    # Check for dangerous CORS configurations

    # 1. Wildcard with credentials (most dangerous but rare)
    if acao == "*" and acac.lower() == "true":
        return ValidationResult(
            verified=True,
            confidence=0.95,
            evidence="ACAO: * with credentials",
            reason="Critical CORS - wildcard with credentials (browsers block this)"
        )

    # 2. Reflecting arbitrary origin with credentials
    if "null" in acao.lower() and acac.lower() == "true":
        return ValidationResult(
            verified=True,
            confidence=0.9,
            evidence="ACAO reflects 'null' with credentials",
            reason="CORS allows null origin with credentials - exploitable via sandboxed iframe"
        )

    # 3. Reflecting origin with credentials
    if acac.lower() == "true" and acao and acao != "*":
        return ValidationResult(
            verified=True,
            confidence=0.85,
            evidence=f"ACAO: {acao} with credentials",
            reason="CORS reflects origin with credentials - check if origin validation is weak"
        )

    # 4. Wildcard without credentials (low risk)
    if acao == "*":
        return ValidationResult(
            verified=True,
            confidence=0.5,
            evidence="ACAO: * (no credentials)",
            reason="CORS wildcard - low risk without credentials",
            downgrade_to="low"
        )

    # 5. No ACAO header
    if not acao:
        return ValidationResult(
            verified=False,
            confidence=0.2,
            reason="No CORS headers found",
            downgrade_to="info"
        )

    return ValidationResult(
        verified=True,
        confidence=0.6,
        reason="CORS configuration present - verify exploitability"
    )


# =============================================================================
# JWT VALIDATION
# =============================================================================

def validate_jwt(
    finding: dict[str, Any],
    response_body: str | None = None
) -> ValidationResult:
    """
    Validate JWT vulnerability findings.
    """
    evidence = finding.get("evidence", {})
    title_lower = finding.get("title", "").lower()
    issues = evidence.get("issues", [])

    # None algorithm attack
    if "none" in title_lower or "none_algorithm" in str(issues):
        # Check if we have evidence of acceptance
        if evidence.get("accepted") or "accepted" in str(evidence).lower():
            return ValidationResult(
                verified=True,
                confidence=0.95,
                evidence="Server accepted 'none' algorithm JWT",
                reason="Critical JWT vulnerability - none algorithm accepted"
            )
        return ValidationResult(
            verified=True,
            confidence=0.7,
            reason="JWT none algorithm vulnerability - verify manually"
        )

    # Weak secret
    if "weak" in title_lower or "weak_secret" in str(issues):
        secret = evidence.get("secret", "")
        if secret:
            return ValidationResult(
                verified=True,
                confidence=0.9,
                evidence=f"JWT signed with weak secret: {secret}",
                reason="JWT uses weak/guessable secret"
            )
        return ValidationResult(
            verified=False,
            confidence=0.5,
            reason="Weak secret claimed but not demonstrated"
        )

    # Algorithm confusion (RS256 -> HS256)
    if "algorithm" in title_lower or "confusion" in title_lower:
        return ValidationResult(
            verified=True,
            confidence=0.8,
            reason="JWT algorithm confusion vulnerability"
        )

    # Missing signature validation
    if "signature" in title_lower:
        return ValidationResult(
            verified=True,
            confidence=0.75,
            reason="JWT signature validation issue"
        )

    return ValidationResult(
        verified=True,
        confidence=0.6,
        reason="JWT vulnerability - type not specifically validated"
    )


# =============================================================================
# HOST HEADER INJECTION VALIDATION
# =============================================================================

def validate_host_header_injection(
    finding: dict[str, Any],
    response_body: str | None = None,
    response_headers: dict[str, str] | None = None
) -> ValidationResult:
    """
    Validate host header injection by checking for reflection.
    """
    evidence = finding.get("evidence", {})

    injected_value = evidence.get("injected_value", "") or evidence.get("header", "")
    is_cacheable = evidence.get("cacheable", False)

    if not response_body and not response_headers:
        return ValidationResult(
            verified=False,
            confidence=0.5,
            reason="Cannot verify without response"
        )

    # Check for reflection in response body
    if response_body and injected_value:
        # Check in sensitive contexts
        patterns = [
            (rf'href=["\'][^"\']*{re.escape(injected_value)}', "href attribute"),
            (rf'src=["\'][^"\']*{re.escape(injected_value)}', "src attribute"),
            (rf'action=["\'][^"\']*{re.escape(injected_value)}', "form action"),
            (rf'<a[^>]+{re.escape(injected_value)}', "link"),
        ]

        for pattern, context in patterns:
            if re.search(pattern, response_body, re.I):
                confidence = 0.9 if is_cacheable else 0.75
                severity_note = "cacheable - cache poisoning possible" if is_cacheable else "not cacheable"
                return ValidationResult(
                    verified=True,
                    confidence=confidence,
                    evidence=f"Injected value reflected in {context}",
                    reason=f"Host header injection in {context} ({severity_note})"
                )

    # Check response headers for reflection
    if response_headers and injected_value:
        for header, value in response_headers.items():
            if injected_value.lower() in value.lower():
                return ValidationResult(
                    verified=True,
                    confidence=0.85,
                    evidence=f"Reflected in {header} header",
                    reason="Host header reflected in response headers"
                )

    return ValidationResult(
        verified=False,
        confidence=0.4,
        reason="Host header injection not confirmed",
        downgrade_to="low"
    )


# =============================================================================
# CSRF VALIDATION
# =============================================================================

def validate_csrf(
    finding: dict[str, Any],
    response_body: str | None = None
) -> ValidationResult:
    """
    Validate CSRF by checking if protection is actually missing.
    """
    evidence = finding.get("evidence", {})
    title_lower = finding.get("title", "").lower()

    # Check for forms without tokens
    has_form = evidence.get("has_form", False)
    has_token = evidence.get("has_csrf_token", False)
    has_samesite = evidence.get("has_samesite_cookie", False)

    if response_body:
        # Look for CSRF tokens in the page
        csrf_patterns = [
            r'name=["\']_?csrf',
            r'name=["\']authenticity_token',
            r'name=["\']__RequestVerificationToken',
            r'csrf[-_]?token',
            r'x-csrf-token',
        ]
        has_token = any(re.search(p, response_body, re.I) for p in csrf_patterns)

    # State-changing form without protection
    if has_form and not has_token and not has_samesite:
        return ValidationResult(
            verified=True,
            confidence=0.8,
            evidence="Form without CSRF token or SameSite cookie",
            reason="CSRF protection missing on state-changing form"
        )

    # Has SameSite cookie - reduces risk
    if has_samesite:
        return ValidationResult(
            verified=True,
            confidence=0.5,
            reason="Form lacks token but SameSite cookie provides protection",
            downgrade_to="low"
        )

    # No form found
    if not has_form:
        return ValidationResult(
            verified=False,
            confidence=0.3,
            reason="No state-changing forms found",
            downgrade_to="info"
        )

    return ValidationResult(
        verified=True,
        confidence=0.6,
        reason="CSRF protection unclear - verify manually"
    )


# =============================================================================
# IDOR VALIDATION
# =============================================================================

def validate_idor(
    finding: dict[str, Any],
    response_body: str | None = None
) -> ValidationResult:
    """
    Validate IDOR by checking if different data was accessed.
    """
    evidence = finding.get("evidence", {})

    # Check if we have evidence of unauthorized access
    accessed_other_user = evidence.get("accessed_other_user", False)
    data_difference = evidence.get("data_difference", False)
    sequential_ids = evidence.get("sequential_ids", False)

    if accessed_other_user or data_difference:
        return ValidationResult(
            verified=True,
            confidence=0.9,
            evidence="Accessed data belonging to different user/entity",
            reason="Confirmed IDOR - unauthorized data access"
        )

    if sequential_ids:
        return ValidationResult(
            verified=True,
            confidence=0.7,
            evidence="Sequential IDs detected",
            reason="Potential IDOR - sequential IDs without access control"
        )

    # Just pattern-based detection
    if "id=" in str(evidence).lower() or "user" in str(evidence).lower():
        return ValidationResult(
            verified=False,
            confidence=0.5,
            reason="IDOR pattern detected but not confirmed"
        )

    return ValidationResult(
        verified=False,
        confidence=0.4,
        reason="IDOR not verified"
    )


# =============================================================================
# FILE UPLOAD VALIDATION
# =============================================================================

# Dangerous file extensions that indicate high-risk uploads
DANGEROUS_EXTENSIONS = frozenset([
    ".php", ".php3", ".php4", ".php5", ".phtml", ".phar",
    ".asp", ".aspx", ".ashx", ".asmx", ".cer",
    ".jsp", ".jspx", ".jsw", ".jsv",
    ".exe", ".dll", ".bat", ".cmd", ".com", ".msi",
    ".sh", ".bash", ".zsh", ".csh",
    ".py", ".pl", ".rb", ".cgi",
    ".htaccess", ".htpasswd",
    ".svg",  # Can contain JavaScript
    ".html", ".htm", ".xhtml",  # XSS via upload
])

# Extensions that bypass common filters
BYPASS_EXTENSIONS = [
    ".php.jpg", ".php.png", ".php.gif",  # Double extension
    ".pHp", ".PhP", ".PHP",  # Case variation
    ".php%00.jpg", ".php\x00.jpg",  # Null byte injection
    ".php;.jpg",  # Semicolon bypass
    ".php::$DATA",  # Windows ADS bypass
]


def validate_file_upload(
    finding: dict[str, Any],
    response_body: str | None = None,
    response_headers: dict[str, str] | None = None
) -> ValidationResult:
    """
    Validate file upload vulnerability by checking if dangerous uploads are possible.
    """
    evidence = finding.get("evidence", {})
    title_lower = finding.get("title", "").lower()

    # Check what we know about the upload
    accepted_types = evidence.get("accepted_types", [])
    uploaded_file = evidence.get("uploaded_file", "")
    upload_successful = evidence.get("upload_successful", False)
    file_accessible = evidence.get("file_accessible", False)
    content_type_validated = evidence.get("content_type_validated", True)

    # High confidence: Successfully uploaded and accessed dangerous file
    if upload_successful and file_accessible and any(
        uploaded_file.lower().endswith(ext) for ext in DANGEROUS_EXTENSIONS
    ):
        return ValidationResult(
            verified=True,
            confidence=0.95,
            evidence=f"Dangerous file uploaded and accessible: {uploaded_file}",
            reason="Confirmed file upload RCE - dangerous file type accessible"
        )

    # Medium-high confidence: Upload succeeded but access not confirmed
    if upload_successful and any(
        uploaded_file.lower().endswith(ext) for ext in DANGEROUS_EXTENSIONS
    ):
        return ValidationResult(
            verified=True,
            confidence=0.8,
            evidence=f"Dangerous file type accepted: {uploaded_file}",
            reason="File upload accepts dangerous extensions"
        )

    # Content-type validation bypass
    if not content_type_validated:
        return ValidationResult(
            verified=True,
            confidence=0.75,
            evidence="Server does not validate Content-Type",
            reason="Content-Type validation missing - potential for type confusion attacks"
        )

    # Form detected that accepts files with no clear restrictions
    if "upload" in title_lower and evidence.get("has_upload_form"):
        # Check if we found unrestricted accept attribute
        accept_attr = evidence.get("accept_attribute", "")
        if not accept_attr or accept_attr == "*/*" or accept_attr == "*":
            return ValidationResult(
                verified=True,
                confidence=0.6,
                evidence="Upload form without file type restrictions",
                reason="Unrestricted file upload form - verify allowed types"
            )

    # No evidence of actual upload vulnerability
    if "potential" in title_lower or "possible" in title_lower:
        return ValidationResult(
            verified=False,
            confidence=0.4,
            reason="Upload form exists but no vulnerability confirmed",
            downgrade_to="low"
        )

    return ValidationResult(
        verified=True,
        confidence=0.5,
        reason="File upload functionality detected - manual verification needed"
    )


# =============================================================================
# DESERIALIZATION VALIDATION
# =============================================================================

# Known deserialization attack patterns
DESERIALIZATION_SIGNATURES = {
    "java": [
        (r'rO0AB', "Base64-encoded Java serialized object"),
        (r'\xac\xed\x00\x05', "Raw Java serialized object header"),
        (r'org\.apache\.commons\.collections', "Commons Collections gadget"),
        (r'ysoserial', "ysoserial payload detected"),
        (r'ObjectInputStream', "Java ObjectInputStream usage"),
        (r'readObject\(\)', "readObject method call"),
    ],
    "php": [
        (r'O:\d+:"[^"]+":{\d+:', "PHP serialized object"),
        (r'a:\d+:{', "PHP serialized array"),
        (r'unserialize\s*\(', "PHP unserialize call"),
        (r'__wakeup|__destruct', "PHP magic methods"),
    ],
    "python": [
        (r'pickle\.loads?', "Python pickle usage"),
        (r'cPickle', "Python cPickle usage"),
        (r'yaml\.load\s*\(', "YAML unsafe load"),
        (r'marshal\.loads?', "Python marshal usage"),
        (r'shelve', "Python shelve usage"),
    ],
    "dotnet": [
        (r'BinaryFormatter', ".NET BinaryFormatter"),
        (r'ObjectStateFormatter', ".NET ObjectStateFormatter"),
        (r'LosFormatter', ".NET LosFormatter"),
        (r'SoapFormatter', ".NET SoapFormatter"),
        (r'NetDataContractSerializer', ".NET insecure deserializer"),
        (r'__VIEWSTATE', "ASP.NET ViewState"),
    ],
    "ruby": [
        (r'Marshal\.load', "Ruby Marshal.load"),
        (r'YAML\.load', "Ruby YAML.load"),
    ]
}

# Error messages indicating deserialization issues
DESERIALIZATION_ERRORS = [
    r'ClassNotFoundException',
    r'InvalidClassException',
    r'StreamCorruptedException',
    r'java\.io\.ObjectInputStream',
    r'unserialize\(\).*failed',
    r'pickle\.UnpicklingError',
    r'yaml\.constructor\.ConstructorError',
    r'SerializationException',
]


def validate_deserialization(
    finding: dict[str, Any],
    response_body: str | None = None
) -> ValidationResult:
    """
    Validate deserialization vulnerability by checking for exploit patterns.
    """
    evidence = finding.get("evidence", {})
    title_lower = finding.get("title", "").lower()

    # Check for language-specific patterns in evidence
    payload = str(evidence.get("payload", ""))
    request_body = str(evidence.get("request", ""))
    combined_input = payload + request_body

    # Determine language context
    language = evidence.get("language", "").lower()
    if not language:
        # Try to detect from title or evidence
        for lang in DESERIALIZATION_SIGNATURES:
            if lang in title_lower:
                language = lang
                break

    # Check for confirmed exploitation
    if evidence.get("exploited", False) or evidence.get("code_executed", False):
        return ValidationResult(
            verified=True,
            confidence=0.95,
            evidence="Deserialization exploit successful",
            reason="Confirmed insecure deserialization with code execution"
        )

    # Check for error-based detection
    if response_body:
        for error_pattern in DESERIALIZATION_ERRORS:
            if re.search(error_pattern, response_body, re.I):
                return ValidationResult(
                    verified=True,
                    confidence=0.8,
                    evidence="Deserialization error in response",
                    reason="Error message indicates deserialization processing"
                )

    # Check for known payload signatures in requests
    if language and language in DESERIALIZATION_SIGNATURES:
        for pattern, description in DESERIALIZATION_SIGNATURES[language]:
            if re.search(pattern, combined_input, re.I):
                return ValidationResult(
                    verified=True,
                    confidence=0.7,
                    evidence=description,
                    reason=f"Known {language} deserialization pattern detected"
                )
    else:
        # Check all languages
        for lang, patterns in DESERIALIZATION_SIGNATURES.items():
            for pattern, description in patterns:
                if re.search(pattern, combined_input, re.I):
                    return ValidationResult(
                        verified=True,
                        confidence=0.65,
                        evidence=f"{description} ({lang})",
                        reason=f"Deserialization pattern detected - {lang}"
                    )

    # Tool reported but no confirmation
    if any(x in title_lower for x in ["possible", "potential", "suspected"]):
        return ValidationResult(
            verified=False,
            confidence=0.4,
            reason="Possible deserialization issue - not confirmed",
            downgrade_to="medium"
        )

    # Found endpoint that handles serialized data
    if evidence.get("handles_serialized_data"):
        return ValidationResult(
            verified=True,
            confidence=0.6,
            reason="Endpoint processes serialized data - verify safe handling"
        )

    return ValidationResult(
        verified=False,
        confidence=0.5,
        reason="Deserialization functionality detected - manual verification needed"
    )


# =============================================================================
# INFORMATION DISCLOSURE VALIDATION
# =============================================================================

# Patterns that confirm sensitive information exposure
SENSITIVE_INFO_PATTERNS = {
    "high": [
        (r'password\s*[=:]\s*["\']?[^\s"\']{8,}', "Password exposed"),
        (r'api[_-]?key\s*[=:]\s*["\']?[A-Za-z0-9]{20,}', "API key exposed"),
        (r'secret[_-]?key\s*[=:]\s*["\']?[A-Za-z0-9]{20,}', "Secret key exposed"),
        (r'aws[_-]?access[_-]?key[_-]?id\s*[=:]\s*["\']?AK[A-Z0-9]{18}', "AWS key exposed"),
        (r'private[_-]?key|BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY', "Private key exposed"),
        (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}.*password', "Email with password"),
    ],
    "medium": [
        (r'database\s*[=:]\s*["\']?\w+', "Database name exposed"),
        (r'server\s*[=:]\s*["\']?[\d.]+', "Server IP exposed"),
        (r'internal[_-]?ip|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+', "Internal IP"),
        (r'stack\s*trace|traceback|exception', "Stack trace exposed"),
        (r'debug\s*[=:]\s*true', "Debug mode enabled"),
    ],
    "low": [
        (r'version\s*[=:]\s*[\d.]+', "Version information"),
        (r'server:\s*\w+/[\d.]+', "Server version header"),
        (r'x-powered-by:', "Technology disclosure"),
    ]
}


def validate_information_disclosure(
    finding: dict[str, Any],
    response_body: str | None = None
) -> ValidationResult:
    """
    Validate information disclosure by checking severity of exposed data.
    """
    if not response_body:
        return ValidationResult(
            verified=False,
            confidence=0.5,
            reason="Cannot verify without response"
        )

    # Check for high-severity disclosures
    for pattern, description in SENSITIVE_INFO_PATTERNS["high"]:
        if re.search(pattern, response_body, re.I):
            return ValidationResult(
                verified=True,
                confidence=0.95,
                evidence=description,
                reason=f"High-severity disclosure: {description}"
            )

    # Check for medium-severity disclosures
    for pattern, description in SENSITIVE_INFO_PATTERNS["medium"]:
        if re.search(pattern, response_body, re.I):
            return ValidationResult(
                verified=True,
                confidence=0.75,
                evidence=description,
                reason=f"Medium-severity disclosure: {description}"
            )

    # Check for low-severity disclosures
    for pattern, description in SENSITIVE_INFO_PATTERNS["low"]:
        if re.search(pattern, response_body, re.I):
            return ValidationResult(
                verified=True,
                confidence=0.5,
                evidence=description,
                reason=f"Low-severity disclosure: {description}",
                downgrade_to="low"
            )

    return ValidationResult(
        verified=False,
        confidence=0.3,
        reason="No sensitive information patterns found",
        downgrade_to="info"
    )


# =============================================================================
# MAIN VALIDATION DISPATCHER
# =============================================================================

HYGIENE_TOOLS = frozenset({
    "csp_evaluator",
    "dns_policy",
    "http_headers",
    "input_validation",
    "security_txt",
    "tls_config",
})


def validate_hygiene_finding(finding: dict[str, Any]) -> ValidationResult:
    """Classify deterministic hardening/configuration findings as hygiene evidence."""
    tool = str(finding.get("tool") or "").lower()
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}

    if tool == "input_validation":
        confidence = 0.75
        reason = "Informational input-validation signal from deterministic probe response"
    elif evidence.get("reproduction") or evidence.get("missing") is True or "record" in evidence:
        confidence = 0.85
        reason = "Deterministic configuration/header/DNS evidence"
    else:
        confidence = 0.75
        reason = "Deterministic hygiene finding"

    return ValidationResult(
        verified=False,
        confidence=confidence,
        evidence=str(evidence.get("reproduction") or evidence.get("header") or evidence.get("record") or tool)[:200],
        reason=reason,
        evidence_level="hygiene",
    )


def validate_finding(
    finding: dict[str, Any],
    response_body: str | None = None,
    response_headers: dict[str, str] | None = None
) -> ValidationResult:
    """
    Validate a finding based on its type.

    Args:
        finding: The finding to validate
        response_body: Optional response body for verification
        response_headers: Optional response headers

    Returns:
        ValidationResult with validation details
    """
    title_lower = finding.get("title", "").lower()
    tool = finding.get("tool", "").lower()

    if tool in HYGIENE_TOOLS:
        return validate_hygiene_finding(finding)

    # ==========================================================================
    # INJECTION VULNERABILITIES
    # ==========================================================================

    # XSS validation
    if "xss" in title_lower or "cross-site scripting" in title_lower or tool in ("dalfox", "dom_xss"):
        return validate_xss(finding, response_body)

    # SQLi validation
    if ("sql" in title_lower and "inject" in title_lower) or tool == "sqlmap":
        return validate_sqli(finding, response_body)

    # Command Injection / RCE
    if any(x in title_lower for x in ["command injection", "rce", "remote code", "os command"]):
        return validate_command_injection(finding, response_body)

    # XXE validation
    if "xxe" in title_lower or "xml external" in title_lower:
        return validate_xxe(finding, response_body)

    # ==========================================================================
    # ACCESS CONTROL VULNERABILITIES
    # ==========================================================================

    # SSRF validation
    if "ssrf" in title_lower or "server-side request" in title_lower:
        return validate_ssrf(finding, response_body)

    # Path Traversal / LFI
    if any(x in title_lower for x in ["path traversal", "lfi", "local file", "directory traversal", "../"]):
        return validate_path_traversal(finding, response_body)

    # IDOR validation
    if "idor" in title_lower or "insecure direct object" in title_lower or "bola" in title_lower:
        return validate_idor(finding, response_body)

    # CSRF validation
    if "csrf" in title_lower or "cross-site request forgery" in title_lower:
        return validate_csrf(finding, response_body)

    # ==========================================================================
    # CONFIGURATION VULNERABILITIES
    # ==========================================================================

    # Exposed file validation
    if "exposed" in title_lower or tool == "exposed_files":
        return validate_exposed_file(finding, response_body, response_headers)

    # Open Redirect
    if "open redirect" in title_lower or "url redirect" in title_lower:
        return validate_open_redirect(finding, response_body, response_headers)

    # CORS misconfiguration
    if "cors" in title_lower:
        return validate_cors(finding, response_body, response_headers)

    # Host Header Injection
    if "host header" in title_lower or "host injection" in title_lower:
        return validate_host_header_injection(finding, response_body, response_headers)

    # Subdomain Takeover
    if "subdomain takeover" in title_lower or "takeover" in title_lower:
        return validate_subdomain_takeover(finding, response_body)

    # File Upload vulnerabilities
    if any(x in title_lower for x in ["file upload", "upload vuln", "unrestricted upload", "arbitrary file"]):
        return validate_file_upload(finding, response_body, response_headers)

    # Deserialization vulnerabilities
    if any(x in title_lower for x in ["deserialization", "deserialize", "pickle", "unserialize", "marshal"]):
        return validate_deserialization(finding, response_body)

    # ==========================================================================
    # AUTHENTICATION VULNERABILITIES
    # ==========================================================================

    # JWT vulnerabilities
    if "jwt" in title_lower or "json web token" in title_lower:
        return validate_jwt(finding, response_body)

    # ==========================================================================
    # INFORMATION DISCLOSURE
    # ==========================================================================

    if any(x in title_lower for x in ["information disclosure", "info leak", "sensitive data"]):
        return validate_information_disclosure(finding, response_body)

    # ==========================================================================
    # DEFAULT
    # ==========================================================================

    # Default: do not mark unsupported finding types as verified. The caller can
    # still report them as leads, but they should not count as confirmed bugs.
    return ValidationResult(
        verified=False,
        confidence=0.55,
        reason="No specific validation available for this finding type",
        downgrade_to=None,
    )


def apply_validation_to_finding(
    finding: dict[str, Any],
    validation: ValidationResult
) -> dict[str, Any]:
    """
    Apply validation result to a finding, potentially downgrading severity.

    Args:
        finding: The finding to update
        validation: Validation result

    Returns:
        Updated finding with validation metadata
    """
    finding["validation"] = validation.to_dict()
    finding["confidence"] = validation.confidence
    finding["confidence_tier"] = _confidence_tier(validation.confidence)

    if validation.verified:
        finding["verified"] = True
        finding["needs_verification"] = False
        finding["suspected"] = False
    else:
        finding["verified"] = False
        if validation.evidence_level in {"weak_indicator", "strong_indicator"}:
            finding["needs_verification"] = True
        if validation.evidence_level == "weak_indicator":
            finding["suspected"] = True
        if validation.reason:
            finding["verification_reason"] = validation.reason

    # Downgrade severity if validation failed
    if validation.downgrade_to and not validation.verified:
        original_severity = finding.get("severity")
        finding["severity"] = validation.downgrade_to
        finding["validation"]["original_severity"] = original_severity
        finding["validation"]["severity_downgraded"] = True

        # Adjust CVSS score for downgrade
        severity_cvss = {
            "info": 0.0,
            "low": 2.0,
            "medium": 5.0,
            "high": 7.5,
            "critical": 9.0
        }
        if validation.downgrade_to in severity_cvss:
            finding["cvss_score"] = min(
                finding.get("cvss_score", 5.0),
                severity_cvss[validation.downgrade_to]
            )

    return finding


def _confidence_tier(confidence: float) -> str:
    if confidence >= 0.90:
        return "verified"
    if confidence >= 0.80:
        return "high"
    if confidence >= 0.65:
        return "medium"
    if confidence >= 0.50:
        return "low"
    return "uncertain"


def should_report_finding(finding: dict[str, Any]) -> tuple[bool, str]:
    """
    Determine if a finding should be reported based on confidence.

    Args:
        finding: The finding to check

    Returns:
        Tuple of (should_report, reason)
    """
    confidence = finding.get("confidence", 0.5)
    severity = finding.get("severity", "medium").lower()

    threshold = CONFIDENCE_THRESHOLDS.get(severity, 0.5)

    if confidence >= threshold:
        return True, f"Confidence {confidence:.0%} meets threshold {threshold:.0%}"
    else:
        return False, f"Confidence {confidence:.0%} below threshold {threshold:.0%} for {severity}"


# =============================================================================
# PROOF-OF-EXPLOIT INTEGRATION
# =============================================================================
# Automatically trigger proof-of-exploit for high-severity findings that
# haven't been verified. This helps reduce false positives for critical/high
# findings by requiring actual exploitation evidence.

# Vulnerability types that support proof-of-exploit
POE_SUPPORTED_TYPES = frozenset([
    "xss", "sqli", "path_traversal", "ssrf", "command_injection"
])


async def validate_with_poe(
    finding: dict[str, Any],
    safe_mode: bool = True,
    timeout: int = 15
) -> dict[str, Any]:
    """
    Validate a finding using proof-of-exploit if applicable.

    For high-severity findings with low confidence, attempts to prove
    the vulnerability is real by actually exploiting it safely.

    Args:
        finding: The finding to validate
        safe_mode: If True, skip aggressive PoE techniques (default: True)
        timeout: Request timeout in seconds

    Returns:
        Updated finding with PoE results
    """
    try:
        from .proof_of_exploit import prove_vulnerability
    except ImportError:
        logger.warning("proof_of_exploit module not available")
        return finding

    severity = finding.get("severity", "").lower()
    confidence = finding.get("confidence", 0.5)
    title_lower = finding.get("title", "").lower()

    # Only run PoE for high-severity findings with confidence below threshold
    if severity not in ("critical", "high"):
        return finding

    # Skip PoE for DOM XSS static analysis (no payload to execute)
    if finding.get("tool", "").lower() == "dom_xss":
        return finding

    # If already high confidence, skip PoE
    if confidence >= ConfidenceTier.HIGH:
        return finding

    # Check if this vulnerability type supports PoE
    vuln_type = None
    if "xss" in title_lower or "cross-site scripting" in title_lower:
        vuln_type = "xss"
    elif "sql" in title_lower and "inject" in title_lower:
        vuln_type = "sqli"
    elif any(x in title_lower for x in ["path traversal", "lfi", "local file"]):
        vuln_type = "path_traversal"
    elif "ssrf" in title_lower:
        vuln_type = "ssrf"
    elif any(x in title_lower for x in ["command injection", "rce"]):
        if safe_mode:
            # Skip command injection PoE in safe mode (too dangerous)
            return finding
        vuln_type = "command_injection"

    if vuln_type not in POE_SUPPORTED_TYPES:
        return finding

    # Attempt proof-of-exploit
    try:
        poe_result = await prove_vulnerability(finding)

        if poe_result.proven:
            # PoE succeeded - upgrade confidence
            finding["confidence"] = poe_result.confidence
            finding["confidence_tier"] = _confidence_tier(poe_result.confidence)
            finding["verified"] = True
            finding["needs_verification"] = False
            finding["suspected"] = False
            finding["poe_result"] = poe_result.to_dict()
            finding["validation"] = finding.get("validation", {})
            finding["validation"]["verified"] = True
            finding["validation"]["poe_proven"] = True
            finding["validation"]["poe_technique"] = poe_result.technique
            finding["validation"]["poe_evidence"] = poe_result.extracted_data
            finding["validation"]["evidence_level"] = "confirmed_exploit"

            logger.info(f"PoE succeeded for {finding.get('id')}: {poe_result.technique}")
        else:
            # PoE failed - might be FP, record attempt
            finding["poe_result"] = {
                "proven": False,
                "attempted": True,
                "reason": "Could not prove exploitation"
            }
            # Don't change confidence - let validator decision stand

    except Exception as e:
        logger.warning(f"PoE failed for {finding.get('id')}: {e}")
        finding["poe_result"] = {
            "proven": False,
            "attempted": True,
            "error": str(e)
        }

    return finding


# =============================================================================
# FINDING DEDUPLICATION
# =============================================================================
# Generate fingerprints for findings to detect duplicates.
# Same vulnerability reported by multiple tools should be deduplicated.

import hashlib


def generate_finding_fingerprint(finding: dict[str, Any]) -> str:
    """
    Generate a fingerprint for a finding to detect duplicates.

    Fingerprint is based on:
    - Tool that generated the finding
    - Title (normalized)
    - URL (normalized)
    - Vulnerability type
    - Parameter/injection point (if applicable)

    Returns:
        SHA-256 hex fingerprint (first 16 chars)
    """
    tool = finding.get("tool", "unknown")
    title = finding.get("title", "")
    title_lower = title.lower()
    evidence = finding.get("evidence", {})

    # Extract URL and normalize
    url = evidence.get("url", "") or evidence.get("target", "")
    if url:
        # Remove query string for fingerprinting (params are separate)
        url = url.split("?")[0].rstrip("/").lower()

    # Determine vulnerability type
    vuln_type = "unknown"
    if "xss" in title_lower:
        vuln_type = "xss"
    elif "sql" in title_lower:
        vuln_type = "sqli"
    elif "ssrf" in title_lower:
        vuln_type = "ssrf"
    elif "xxe" in title_lower:
        vuln_type = "xxe"
    elif "path traversal" in title_lower or "lfi" in title_lower:
        vuln_type = "path_traversal"
    elif "open redirect" in title_lower:
        vuln_type = "open_redirect"
    elif "csrf" in title_lower:
        vuln_type = "csrf"
    elif "idor" in title_lower or "bola" in title_lower:
        vuln_type = "idor"
    elif "cors" in title_lower:
        vuln_type = "cors"
    elif "exposed" in title_lower:
        vuln_type = "exposed_file"
    elif "takeover" in title_lower:
        vuln_type = "subdomain_takeover"

    # Extract parameter if present
    param = evidence.get("param", "") or evidence.get("parameter", "")

    # Build fingerprint string - include tool and title to distinguish different finding types
    fingerprint_parts = [tool, title_lower, url, vuln_type, param]
    fingerprint_str = "|".join(str(p) for p in fingerprint_parts)

    # Hash it
    return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]


def deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Remove duplicate findings, keeping the highest confidence version.

    Args:
        findings: List of findings to deduplicate

    Returns:
        Deduplicated list of findings
    """
    seen: dict[str, dict[str, Any]] = {}

    for finding in findings:
        fingerprint = generate_finding_fingerprint(finding)
        finding["fingerprint"] = fingerprint

        if fingerprint in seen:
            existing = seen[fingerprint]
            existing_conf = existing.get("confidence", 0.5)
            new_conf = finding.get("confidence", 0.5)

            # Keep the one with higher confidence
            if new_conf > existing_conf:
                # Merge tools info
                existing_tools = existing.get("detected_by", [existing.get("tool", "unknown")])
                new_tools = [finding.get("tool", "unknown")]
                finding["detected_by"] = list(set(existing_tools + new_tools))
                finding["duplicate_count"] = existing.get("duplicate_count", 1) + 1
                seen[fingerprint] = finding
            else:
                # Keep existing, but note the duplicate
                existing_tools = existing.get("detected_by", [existing.get("tool", "unknown")])
                existing_tools.append(finding.get("tool", "unknown"))
                existing["detected_by"] = list(set(existing_tools))
                existing["duplicate_count"] = existing.get("duplicate_count", 1) + 1
        else:
            finding["detected_by"] = [finding.get("tool", "unknown")]
            finding["duplicate_count"] = 1
            seen[fingerprint] = finding

    result = list(seen.values())

    # Log dedup stats
    if len(findings) > len(result):
        logger.info(f"Deduplicated findings: {len(findings)} → {len(result)}")

    return result


# =============================================================================
# COMPLETE VALIDATION PIPELINE
# =============================================================================
# This combines heuristic validation, proof-of-exploit, and AI analysis
# into a single coherent pipeline.


@dataclass
class ValidationPipelineConfig:
    """Configuration for the validation pipeline."""
    # Heuristic validation (always on)
    enable_heuristics: bool = True

    # Proof-of-exploit for high-severity findings
    enable_poe: bool = True
    poe_safe_mode: bool = True

    # AI validation for uncertain cases
    enable_ai: bool = False
    ai_url: str = ""
    ai_api_key: str = ""
    ai_model: str = "gpt-4o-mini"

    # Deduplication
    enable_dedup: bool = True

    # Filtering
    filter_low_confidence: bool = True
    min_confidence_to_report: float = 0.35


async def validate_findings_pipeline(
    findings: list[dict[str, Any]],
    response_cache: dict[str, str] | None = None,
    config: ValidationPipelineConfig | None = None
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """
    Run the complete validation pipeline on a list of findings.

    Pipeline stages:
    1. Heuristic validation (pattern-based, fast)
    2. Proof-of-exploit for high-severity uncertain findings
    3. AI validation for remaining uncertain cases (if enabled)
    4. Deduplication
    5. Filtering by confidence threshold

    Args:
        findings: List of findings to validate
        response_cache: Optional cache of URL -> response body
        config: Pipeline configuration

    Returns:
        Tuple of (validated_findings, stats_dict)
    """
    if config is None:
        config = ValidationPipelineConfig()

    response_cache = response_cache or {}

    stats = {
        "input_count": len(findings),
        "heuristic_validated": 0,
        "poe_attempted": 0,
        "poe_proven": 0,
        "ai_validated": 0,
        "ai_fp_detected": 0,
        "deduplicated": 0,
        "filtered": 0,
        "output_count": 0
    }

    validated = []

    for finding in findings:
        # Stage 1: Heuristic validation
        if config.enable_heuristics:
            url = finding.get("evidence", {}).get("url", "")
            response_body = response_cache.get(url, "")

            validation_result = validate_finding(finding, response_body)
            finding = apply_validation_to_finding(finding, validation_result)
            stats["heuristic_validated"] += 1

        # Stage 2: Proof-of-exploit for uncertain high-severity
        if config.enable_poe:
            current_conf = finding.get("confidence", 0.5)
            severity = finding.get("severity", "").lower()

            if severity in ("critical", "high") and current_conf < ConfidenceTier.HIGH:
                stats["poe_attempted"] += 1
                finding = await validate_with_poe(
                    finding,
                    safe_mode=config.poe_safe_mode
                )
                if finding.get("poe_result", {}).get("proven"):
                    stats["poe_proven"] += 1

        # Stage 3: AI validation for uncertain cases
        if config.enable_ai and config.ai_api_key:
            try:
                from .ai_classifier import enhance_finding_with_ai, should_use_ai_validation

                current_conf = finding.get("confidence", 0.5)
                if should_use_ai_validation(finding, current_conf, ai_enabled=True):
                    url = finding.get("evidence", {}).get("url", "")
                    response_body = response_cache.get(url, "")

                    finding = await enhance_finding_with_ai(
                        finding=finding,
                        response_body=response_body if response_body else None,
                        response_headers=None,
                        ai_url=config.ai_url,
                        ai_api_key=config.ai_api_key,
                        model=config.ai_model
                    )
                    stats["ai_validated"] += 1

                    if finding.get("ai_verdict") == "false_positive":
                        stats["ai_fp_detected"] += 1

            except ImportError:
                logger.debug("AI classifier not available")

        validated.append(finding)

    # Stage 4: Deduplication
    if config.enable_dedup:
        before_dedup = len(validated)
        validated = deduplicate_findings(validated)
        stats["deduplicated"] = before_dedup - len(validated)

    # Stage 5: Filter low-confidence findings
    if config.filter_low_confidence:
        before_filter = len(validated)
        filtered_out = []
        kept = []
        for f in validated:
            conf = f.get("confidence", 0.5)
            sev = f.get("severity", "").lower()
            tool = f.get("tool", "")
            passes = conf >= config.min_confidence_to_report or sev == "info"
            if passes:
                kept.append(f)
            else:
                filtered_out.append(f)
                # Debug: Log filtered DOM XSS findings to help diagnose
                if tool == "dom_xss":
                    logger.warning(
                        f"[filter] DROPPED DOM XSS: {f.get('title', '')[:50]} "
                        f"conf={conf} threshold={config.min_confidence_to_report}"
                    )
        validated = kept
        stats["filtered"] = before_filter - len(validated)

    stats["output_count"] = len(validated)

    # Log summary
    logger.info(
        f"Validation pipeline: {stats['input_count']} → {stats['output_count']} findings "
        f"(dedup: -{stats['deduplicated']}, filtered: -{stats['filtered']}, "
        f"AI FPs: {stats['ai_fp_detected']})"
    )

    return validated, stats


# Export key functions for use by scanner.py
__all__ = [
    "CONFIDENCE_THRESHOLDS",
    "ConfidenceTier",
    "ValidationPipelineConfig",
    "ValidationResult",
    "apply_validation_to_finding",
    "deduplicate_findings",
    "generate_finding_fingerprint",
    "should_report_finding",
    "validate_finding",
    "validate_findings_pipeline",
    "validate_with_poe",
]
