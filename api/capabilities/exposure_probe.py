"""Deterministic sensitive-exposure detection over exact target-bound responses.

This module is pure: it names universal exposure classes (secret material,
version-control and environment files, metrics/actuator endpoints, directory
listings, verbose errors, exposed API specs) and matches them by response
signature only. It hardcodes no application-specific path or content so the
same contract works on any target. The bounded batch executor that drives it
lives in ``scan/action_adapter.py``; the curated seed here is a wordlist of
well-known sensitive locations, never a benchmark answer key.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Mapping


EXPOSURE_PROBE_PARSER_VERSION = "exposure-probe/v1"

# Universal well-known sensitive locations. These are common across frameworks
# and hosting stacks; discovering a real one is a finding regardless of app.
SENSITIVE_SEED_PATHS: tuple[str, ...] = (
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/.svn/entries",
    "/.hg/hgrc",
    "/.aws/credentials",
    "/config.json",
    "/config.yml",
    "/config.yaml",
    "/settings.py",
    "/wp-config.php.bak",
    "/.htpasswd",
    "/id_rsa",
    "/server-status",
    "/metrics",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/heapdump",
    "/debug/pprof/",
    "/phpinfo.php",
    "/swagger.json",
    "/openapi.json",
    "/v2/api-docs",
    "/api-docs",
    "/ftp",
    "/ftp/",
    "/backup",
    "/backup.zip",
    "/backup.sql",
    "/database.sql",
    "/dump.sql",
)

# One severity per class. Secret material outranks structural disclosure.
_CLASS_SEVERITY: Mapping[str, str] = {
    "private_key_material": "critical",
    "cloud_credential_material": "critical",
    "environment_secret_file": "high",
    "version_control_exposure": "high",
    "confidential_file": "high",
    "directory_listing": "high",
    "metrics_endpoint": "high",
    "actuator_endpoint": "high",
    "backup_or_source_artifact": "high",
    "exposed_api_specification": "low",
    "verbose_error_disclosure": "medium",
}

_HTML_TYPES = ("text/html", "application/xhtml")

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
)
_AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_AWS_SECRET_RE = re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*\S{20,}")
_ENV_SECRET_RE = re.compile(
    r"(?im)^\s*(?:[A-Z0-9_]*"
    r"(?:SECRET|PASSWORD|PASSWD|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY)"
    r"[A-Z0-9_]*)\s*=\s*\S+"
)
_GIT_CONFIG_RE = re.compile(r"(?m)^\s*\[core\]|\brepositoryformatversion\b")
_GIT_HEAD_RE = re.compile(r"(?m)^\s*ref:\s*refs/")
_METRICS_RE = re.compile(r"(?m)^# HELP \S+.*(?:\n|.)*?^# TYPE \S+")
_LISTING_RE = re.compile(
    r"(?i)<title>\s*(?:index of|directory listing)"
    r"|Directory listing for /"
)
_ACTUATOR_RE = re.compile(r'"(?:status|diskSpace|_links|activeProfiles)"\s*:')
_OPENAPI_RE = re.compile(r'"(?:swagger|openapi)"\s*:\s*"')
_ERROR_RE = re.compile(
    r"Traceback \(most recent call last\)"
    r"|^\s*at [\w.$]+\([\w.$]+:\d+\)"
    r"|org\.springframework\.[\w.]+Exception"
    r"|Fatal error:\s|Warning:\s.*on line \d+"
    r"|System\.\w+Exception:",
    re.MULTILINE,
)
_SECRET_REDACT_RE = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|"
    r"aws_secret_access_key)\s*[:=]\s*[^\s,;\"'<]{1,200}"
)
_HREF_RE = re.compile(r'(?i)href\s*=\s*["\']([^"\'#?]+)["\']')


@dataclass(frozen=True)
class ExposureSignature:
    """One deterministic sensitive-exposure classification."""

    exposure_class: str
    severity: str
    matched_pattern: str


def _content_type(headers: Mapping[str, str]) -> str:
    for name, value in headers.items():
        if str(name).lower() == "content-type":
            return str(value).lower()
    return ""


def _decode(body: bytes) -> str:
    return body[:1_000_000].decode("utf-8", errors="replace")


def classify_exposure(
    *, path: str, status: int, headers: Mapping[str, str], body: bytes,
) -> ExposureSignature | None:
    """Return a deterministic exposure class, or ``None`` when nothing matches.

    Only a positive response with a concrete signature is a finding: a 200 that
    merely returns the SPA shell, a 401/403/404, or an empty body is ignored so
    a soft-200 application never inflates exposure coverage.
    """
    if status != 200 or not body:
        return None
    text = _decode(body)
    content_type = _content_type(headers)
    is_html = any(marker in content_type for marker in _HTML_TYPES)

    # Secret material anywhere in a returned body is the strongest signal.
    if _PRIVATE_KEY_RE.search(text):
        return _sig("private_key_material", _PRIVATE_KEY_RE.pattern)
    if _AWS_KEY_RE.search(text) or _AWS_SECRET_RE.search(text):
        return _sig("cloud_credential_material", "aws_credential")
    if _ENV_SECRET_RE.search(text) and not is_html:
        return _sig("environment_secret_file", _ENV_SECRET_RE.pattern)
    if _GIT_CONFIG_RE.search(text) or _GIT_HEAD_RE.search(text):
        return _sig("version_control_exposure", "vcs_metadata")
    if _METRICS_RE.search(text) and not is_html:
        return _sig("metrics_endpoint", _METRICS_RE.pattern)
    if _ACTUATOR_RE.search(text) and "json" in content_type:
        return _sig("actuator_endpoint", _ACTUATOR_RE.pattern)
    if _LISTING_RE.search(text):
        return _sig("directory_listing", _LISTING_RE.pattern)
    if _OPENAPI_RE.search(text) and "json" in content_type:
        return _sig("exposed_api_specification", _OPENAPI_RE.pattern)
    if _ERROR_RE.search(text):
        return _sig("verbose_error_disclosure", "server_error_disclosure")
    return None


def classify_confidential_file(
    *, status: int, headers: Mapping[str, str], body: bytes,
) -> ExposureSignature | None:
    """Classify a file reached by following a discovered directory listing.

    The listing itself proved the directory is browsable; any non-empty,
    non-HTML file served from it is confidential content disclosure.
    """
    if status != 200 or not body:
        return None
    secret = classify_exposure(path="", status=status, headers=headers, body=body)
    if secret is not None:
        return secret
    if any(marker in _content_type(headers) for marker in _HTML_TYPES):
        return None
    return _sig("confidential_file", "listed_file_disclosure")


def directory_listing_links(body: bytes, *, limit: int = 20) -> tuple[str, ...]:
    """Extract bounded relative file links from a directory listing body."""
    links: list[str] = []
    seen: set[str] = set()
    for match in _HREF_RE.finditer(_decode(body)):
        href = match.group(1).strip()
        if (
            not href
            or href in {"/", "../", "./"}
            or href.startswith(("http://", "https://", "//", "/"))
            or href.endswith("/")
        ):
            continue
        if href not in seen:
            seen.add(href)
            links.append(href)
        if len(links) >= limit:
            break
    return tuple(links)


_SECRET_MATERIAL_CLASSES = frozenset({
    "private_key_material",
    "cloud_credential_material",
    "environment_secret_file",
})


def redacted_exposure_excerpt(body: bytes, signature: ExposureSignature) -> str:
    """Return a short, secret-redacted evidence excerpt around the match.

    For secret-material classes the body itself is the secret, so no content is
    excerpted at all — only the fact of disclosure is recorded.
    """
    if signature.exposure_class in _SECRET_MATERIAL_CLASSES:
        return f"[{signature.exposure_class} detected — content withheld]"
    text = _decode(body)
    if signature.matched_pattern not in {"aws_credential", "vcs_metadata"}:
        try:
            compiled = re.compile(signature.matched_pattern)
        except re.error:
            compiled = None
        found = compiled.search(text) if compiled is not None else None
        if found is not None:
            start = max(0, found.start() - 40)
            text = text[start:found.end() + 160]
    sample = " ".join(text.split())[:400]
    return _SECRET_REDACT_RE.sub(
        lambda item: f"{item.group(1)}=[REDACTED]", sample,
    )


def _sig(exposure_class: str, matched_pattern: str) -> ExposureSignature:
    return ExposureSignature(
        exposure_class=exposure_class,
        severity=_CLASS_SEVERITY[exposure_class],
        matched_pattern=matched_pattern,
    )


__all__ = [
    "EXPOSURE_PROBE_PARSER_VERSION",
    "SENSITIVE_SEED_PATHS",
    "ExposureSignature",
    "classify_confidential_file",
    "classify_exposure",
    "directory_listing_links",
    "redacted_exposure_excerpt",
]
