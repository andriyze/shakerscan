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
    return markers


def match_critical_validator(path: str):
    """Return the content validator for a critical file path, or None."""
    path_lower = (path or "").lower()
    for pattern, validator in CRITICAL_FILE_VALIDATORS.items():
        if pattern in path_lower:
            return validator
    return None


def looks_like_soft_404(content: str) -> bool:
    """Heuristic: short generic error page masquerading as a 200 response."""
    body = (content or "").strip().lower()
    if not body:
        return True
    if len(body) >= 4096:
        return False
    # Config/secret-looking content (key=value / key: value) is never a soft 404.
    if re.search(r"(?m)^[A-Za-z0-9_][A-Za-z0-9_.\-]*\s*[=:]", content or ""):
        return False
    return any(pattern in body for pattern in SOFT_404_PATTERNS)
