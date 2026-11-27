"""
Shared sensitive-content marker detection for exposed-file findings.

Used by scan-time exposure checks (active_checks.check_exposed_files) and by
the post-scan retest prover (proof_of_exploit.prove_exposed_file) so both
paths classify "is this response still sensitive?" with identical logic.
"""

from __future__ import annotations

import re

# Plain-text soft-404 error patterns (common generic error messages)
SOFT_404_PATTERNS = [
    "not found", "page not found", "404", "no available server",
    "file not found", "does not exist", "cannot be found",
    "resource not found", "invalid path", "unknown route",
    "service unavailable", "server error", "bad request",
    "access denied", "forbidden", "unauthorized", "not available",
    "error occurred", "something went wrong", "please try again",
    "the page you requested", "could not be found", "no longer exists"
]


def is_pem_private_key(content: str) -> bool:
    """Check if content looks like a PEM-encoded private key."""
    # Note: Binary formats (DER/PKCS#12) can't be reliably detected because
    # run() decodes stdout as UTF-8, dropping non-UTF8 bytes. PEM is text-based
    # and survives UTF-8 decoding intact.
    return "BEGIN" in content and "PRIVATE KEY" in content


def is_pem_certificate(content: str) -> bool:
    """Check if content looks like a PEM-encoded certificate."""
    return "BEGIN" in content and "CERTIFICATE" in content


# Critical files that MUST have valid PEM content markers to be reported.
# Binary formats (DER/PKCS#12) are not validated since run() decodes as UTF-8.
CRITICAL_FILE_VALIDATORS = {
    "id_rsa": is_pem_private_key,
    "id_dsa": is_pem_private_key,
    "id_ecdsa": is_pem_private_key,
    "id_ed25519": is_pem_private_key,
    ".pem": lambda c: is_pem_private_key(c) or is_pem_certificate(c),
    "server.key": is_pem_private_key,
    "private.key": is_pem_private_key,
    "privatekey": is_pem_private_key,
    "ssl.key": is_pem_private_key,
    "cert.key": is_pem_private_key,
    "privkey.pem": is_pem_private_key,
    "key.pem": is_pem_private_key,
}


def guess_confidence(path: str, content: str, content_type: str | None) -> str:
    p = path.lower()
    body = (content or "")[:2000]
    if any(k in p for k in ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".ssh/id_rsa", ".ssh/id_dsa", ".ssh/id_ecdsa", ".ssh/id_ed25519", "server.key", "privatekey", "private.key", "ssl.key", "cert.key", "certificate.key", "key.pem", "privkey.pem"]):
        if any(m in body for m in ["BEGIN OPENSSH PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN DSA PRIVATE KEY", "BEGIN EC PRIVATE KEY", "PRIVATE KEY-----"]):
            return "high"
        return "medium"
    if any(k in p for k in [".env", "database.yml", "database.yaml", "db.yml", "db.yaml"]):
        if any(x in body.lower() for x in ["password=", "secret=", "db_password", "database:", "production:", "username:"]):
            return "high"
        return "medium"
    if any(k in p for k in [".aws/credentials", ".kube/config", ".npmrc", ".pypirc", ".gem/credentials", "auth.json", "application_default_credentials.json", "service-account.json", "serviceAccount.json", "credentials.json"]):
        return "high"
    if content_type and any(t in content_type.lower() for t in ["application/json", "text/yaml", "application/x-yaml", "text/xml"]):
        return "medium"
    return "low"


def derive_markers(path: str, content: str) -> list[str]:
    markers: list[str] = []
    body = (content or "")[:4000]
    p = (path or "").lower()
    if any(m in body for m in ["BEGIN OPENSSH PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN DSA PRIVATE KEY", "BEGIN EC PRIVATE KEY", "PRIVATE KEY-----"]):
        markers.append("private_key_marker")
    if ".env" in p and re.search(r"(?m)^[A-Z0-9_]+=", body):
        markers.append("dotenv_format")
    if p.endswith(".sql") and re.search(r"(CREATE\s+TABLE|INSERT\s+INTO)", body, re.I):
        markers.append("sql_dump_signature")
    if re.search(r"(?i)password\s*[=:]|secret(_key)?\s*[=:]", body):
        markers.append("credential_like")
    # Deliberate document-sensitivity labels. Kept to strong, unambiguous
    # markings — NOT generic mentions of "password"/"secret" (those are covered
    # structurally by credential_like / private_key above) — so a browsable
    # confidential doc (e.g. a leaked business memo with no sensitive extension
    # and no structured marker) still classifies as sensitive and re-proves on
    # retest, while prose that merely mentions a secret word does not inflate.
    if any(kw in body.lower() for kw in _CONFIDENTIAL_LABELS):
        markers.append("confidential_content")
    return markers


# Document-sensitivity labels shared by scan-time harvest and the retest prover so
# both agree on what "confidential content" means (no target-specific strings).
_CONFIDENTIAL_LABELS = (
    "confidential", "classified", "restricted",
    "internal use only", "internal only",
    "do not distribute", "not for distribution", "proprietary",
)


def exposure_severity(
    markers: list[str] | None,
    confidence: str | None,
    *,
    sensitive_ext: bool = False,
    via_bypass: bool = False,
) -> str:
    """Severity for an exposed/harvested file, gated on evidence strength.

    Mirrors the confidence-gated model of ``check_exposed_files`` so a bare 200 +
    single keyword/extension does not inflate to HIGH (the directory-listing
    harvest historically hardcoded HIGH regardless of confidence, flooding the
    unverified-high ratio). HIGH requires strong evidence — a structured content
    marker, high confidence, or a successful allowlist bypass (reading a blocked
    file IS the vuln). Sensitive-extension-only or medium-confidence hits are
    MEDIUM; everything else LOW.
    """
    conf = str(confidence or "low").lower()
    if via_bypass or (markers or []) or conf == "high":
        return "high"
    if sensitive_ext or conf == "medium":
        return "medium"
    return "low"


def match_critical_validator(path: str):
    """Return the content validator for a critical file path, or None."""
    path_lower = (path or "").lower()
    for pattern, validator in CRITICAL_FILE_VALIDATORS.items():
        if pattern in path_lower:
            return validator
    return None


def looks_like_soft_404(content: str) -> bool:
    """Heuristic: short generic error page masquerading as a 200 response.

    Deliberately conservative, mirroring the scan-time check: only a SHORT body
    that is dominated by an error phrase counts. A longer file that merely
    mentions an error word (e.g. a log file containing "error occurred", or a
    config with "access denied" strings) is NOT treated as a soft 404 — that
    would falsely mark a still-exposed file as remediated on retest. Longer soft
    404 / catch-all pages are caught elsewhere (catch-all probe, HTML/shape
    checks) rather than here.
    """
    body = (content or "").strip().lower()
    if not body:
        return True
    # Config/secret-looking content (key=value / key: value) is never a soft 404.
    if re.search(r"(?m)^[A-Za-z0-9_][A-Za-z0-9_.\-]*\s*[=:]", content or ""):
        return False
    # Only short, error-dominated bodies qualify. Bodies large enough to be a
    # real exposed artifact are left to the shape/catch-all logic.
    if len(body) >= 256:
        return False
    for pattern in SOFT_404_PATTERNS:
        if pattern in body:
            if len(body) < 64 or len(pattern) >= len(body) * 0.25:
                return True
    return False
