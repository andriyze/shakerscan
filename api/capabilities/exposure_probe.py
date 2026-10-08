"""Content classification and narrow exposure proof over target-bound responses.

This module is pure: it names observed content classes (secret material,
version-control and environment files, actuator property sources, API specs with
embedded credentials, configuration and backup files, debug pages, metrics,
directory listings, verbose errors) and proves each one by a deterministic
signature specific to that file type. Endpoint identity and reachability are
observations, not proof that their content is confidential. It hardcodes no
application-specific content so the same contract works on any target. The
bounded batch executor that drives it lives in ``scan/action_adapter.py``; the
curated seed here is a wordlist of well-known sensitive locations, never a
benchmark answer key.

What counts as a leaked secret is not decided here. Secret values are judged by
the narrow, entropy-screened contract in ``secret_material`` that the Hunt
``data_exposure`` verifier also uses; this module only recognises the document
structure that makes a key name meaningful. Raw values never leave a signature:
evidence carries key names, categories and scrypt fingerprints.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any

from .secret_material import (
    SecretEvidence,
    secret_evidence,
    selfevident_secret_evidence,
    structured_secret_assignments,
)

try:
    from redaction import redact_text as _shared_redact_text
except ModuleNotFoundError:  # package layout in host-side tests
    from scanner.redaction import redact_text as _shared_redact_text


EXPOSURE_PROBE_PARSER_VERSION = "exposure-probe/v3"

# Common discovery locations across frameworks and hosting stacks. Location
# alone never establishes sensitivity, confidentiality, or a verified finding.
# Every entry is a read-only GET of a fixed path. ``/actuator/heapdump`` is
# deliberately absent: requesting it makes the JVM write a full heap dump, so its
# existence is proved from the actuator index instead.
SENSITIVE_SEED_PATHS: tuple[str, ...] = (
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.dev",
    "/.env.bak",
    "/.git/config",
    "/.git/HEAD",
    "/.svn/entries",
    "/.hg/hgrc",
    "/.aws/credentials",
    "/config.json",
    "/appsettings.json",
    "/config.yml",
    "/config.yaml",
    "/settings.py",
    "/web.config",
    "/web.config.bak",
    "/wp-config.php.bak",
    "/.DS_Store",
    "/.htpasswd",
    "/id_rsa",
    "/server-status",
    "/metrics",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/configprops",
    "/debug/pprof/",
    "/console",
    "/phpinfo.php",
    "/info.php",
    "/swagger.json",
    "/openapi.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger/v1/swagger.json",
    "/api-docs",
    "/ftp",
    "/ftp/",
    "/backup",
    "/backup.zip",
    "/backup.sql",
    "/database.sql",
    "/dump.sql",
)

# Requests the probe never sends, even when discovery reports the route: each one
# makes the target do expensive work (a full JVM heap dump) rather than read a file.
_NEVER_REQUESTED_PATH_SUFFIXES: tuple[str, ...] = ("/heapdump",)

# Paths that cannot exist, requested only after a signature matched, to prove the
# match is specific to the path and not the host's answer for everything.
SOFT_404_CONTROL_COUNT = 2
# A directory listing may lead to at most this many follow-up reads per batch.
DIRECTORY_FOLLOW_UP_FLOOR = 10


def exposure_first_slice_hold(slice_count: int) -> dict[str, int]:
    """The reservation the first slice needs beyond its endpoint share.

    The seed list is probed once, in the first slice, on top of that slice's
    discovered endpoints. Sizing the slice by its endpoint count alone let a small
    manifest (three endpoints -> fifteen requests) silently cut the seed sweep short.
    One request and one wall second per seed, the soft-404 controls and the
    directory follow-up floor are held explicitly.
    """
    seeds = len(SENSITIVE_SEED_PATHS) + SOFT_404_CONTROL_COUNT
    endpoints = max(0, int(slice_count))
    return {
        "http_requests": seeds + endpoints + DIRECTORY_FOLLOW_UP_FLOOR,
        "tool_wall_seconds": seeds + 3 * endpoints,
    }


def is_never_requested(url: str) -> bool:
    path = urllib.parse.urlsplit(str(url or "")).path.rstrip("/").lower()
    return any(path.endswith(suffix) for suffix in _NEVER_REQUESTED_PATH_SUFFIXES)


# One severity per class. Secret material outranks structural disclosure; a class
# whose body also carries a proven secret is raised by ``_escalated``.
_CLASS_SEVERITY: Mapping[str, str] = {
    "private_key_material": "critical",
    "cloud_credential_material": "critical",
    "environment_secret_file": "high",
    "actuator_secret_disclosure": "high",
    "api_specification_secret": "high",
    "configuration_secret_file": "high",
    "version_control_exposure": "high",
    "actuator_heapdump_exposed": "high",
    "confidential_file": "high",
    "listed_file": "info",
    "directory_listing": "high",
    "directory_metadata_file": "low",
    "metrics_endpoint": "high",
    "actuator_endpoint": "info",
    "configuration_file": "info",
    "backup_or_source_artifact": "high",
    "exposed_api_specification": "info",
    "phpinfo_disclosure": "medium",
    "debug_interface_exposure": "medium",
    "verbose_error_disclosure": "medium",
}

# The deterministic proof contract each promotable class satisfies. Registered in
# ``proof_contracts.CANONICAL_PROOF_CONTRACTS``; a class without one never promotes.
EXPOSURE_PROOF_CONTRACTS: Mapping[str, str] = {
    "private_key_material": "private_key_exposure/v1",
    "cloud_credential_material": "cloud_credential_exposure/v1",
    "environment_secret_file": "dotenv_secret_exposure/v1",
    "actuator_secret_disclosure": "actuator_secret_exposure/v1",
    "api_specification_secret": "api_spec_secret_exposure/v1",
    "configuration_secret_file": "config_secret_exposure/v1",
    "version_control_exposure": "vcs_metadata_exposure/v1",
    "actuator_heapdump_exposed": "actuator_heapdump_exposure/v1",
    "backup_or_source_artifact": "backup_artifact_exposure/v1",
    "directory_listing": "directory_listing_exposure/v1",
    "directory_metadata_file": "directory_metadata_exposure/v1",
    "metrics_endpoint": "metrics_endpoint_exposure/v1",
    "phpinfo_disclosure": "phpinfo_exposure/v1",
    "debug_interface_exposure": "debug_interface_exposure/v1",
    "verbose_error_disclosure": "verbose_error_exposure/v1",
}

_HTML_TYPES = ("text/html", "application/xhtml")
_HTML_PREFIX_RE = re.compile(r"^\s*(?:<!doctype\s+html|<html[\s>])", re.IGNORECASE)

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
)
_AWS_SECRET_RE = re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*(\S{20,})")
# A git config is proved by its own grammar: the [core] section header on a line of
# its own, followed by one of the keys git itself writes there. HEAD is the whole
# body: a symbolic ref or a bare object id.
_GIT_CORE_HEADER_RE = re.compile(r"(?m)^\s*\[core\]\s*$")
_GIT_CORE_KEY_RE = re.compile(
    r"(?m)^\s*(?:repositoryformatversion|filemode|bare|logallrefupdates)\s*=\s*\S+"
)
_GIT_HEAD_RE = re.compile(r"^\s*(?:ref:\s*refs/[A-Za-z0-9._/-]+|[0-9a-f]{40}|[0-9a-f]{64})\s*$")
_DOTENV_LINE_RE = re.compile(
    r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.\-]*)\s*=\s*(.*?)\s*$"
)
_METRICS_RE = re.compile(r"(?m)^# HELP \S+.*(?:\n|.)*?^# TYPE \S+")
# Server-generated listing titles differ by stack: Apache and nginx autoindex
# say "Index of /", Python's http.server says "Directory listing for /", and
# the Node/Express serve-index middleware says "listing directory /". Matching
# only the first two missed an exposed directory whose links this module was
# already parsing correctly.
_LISTING_RE = re.compile(
    r"(?i)<title>\s*(?:index of|directory listing|listing directory)"
    r"|Directory listing for /"
)
# Endpoint identity is metadata, not proof of sensitive disclosure. The vendor
# media type is specific; ordinary HAL `_links` and generic health `status`
# values are not Spring-specific and must not be classified as actuator leaks.
_ACTUATOR_MEDIA_TYPE = "application/vnd.spring-boot.actuator."
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
# phpinfo() renders a fixed page: its own title and the "PHP Version" heading. A page
# about phpinfo has neither the exact title nor the version banner.
_PHPINFO_TITLE_RE = re.compile(r"(?i)<title>\s*(?:PHP [\d.]+[^<]{0,40}-\s*)?phpinfo\(\)\s*</title>")
_PHPINFO_VERSION_RE = re.compile(r"PHP Version\s*\d+\.\d+")
_HTML_ROW_RE = re.compile(
    r"(?is)<tr[^>]*>\s*<td[^>]*>\s*([^<]{1,200}?)\s*</td>\s*<td[^>]*>\s*([^<]{0,500}?)\s*</td>"
)
_WERKZEUG_CONSOLE_RE = re.compile(r"(?i)<title>[^<]*//\s*Werkzeug Debugger</title>")
_WERKZEUG_MARKER_RE = re.compile(r"__debugger__|\bEVALEX\b|CONSOLE_MODE")
_PPROF_RE = re.compile(r"(?i)<title>\s*/debug/pprof/\s*</title>")
_WEB_CONFIG_ROOT_RE = re.compile(r"<configuration[\s>]")
_WEB_CONFIG_SECTION_RE = re.compile(
    r"<(?:system\.web|system\.webServer|appSettings|connectionStrings)[\s>/]"
)
_XML_ADD_RE = re.compile(
    r'(?is)<add\s[^>]*?\bkey\s*=\s*"([^"]{1,200})"[^>]*?\bvalue\s*=\s*"([^"]{0,1000})"'
)
_CONNECTION_STRING_RE = re.compile(r'(?is)\bconnectionString\s*=\s*"([^"]{1,2000})"')
_CONNECTION_PASSWORD_RE = re.compile(r"(?i)(?:^|;)\s*(?:password|pwd)\s*=\s*([^;]+)")
_MACHINE_KEY_RE = re.compile(r'(?i)\b(validationKey|decryptionKey)\s*=\s*"([0-9A-F]{32,})"')
_SQL_DUMP_HEADER_RE = re.compile(
    r"(?m)^--\s*(?:MySQL dump|MariaDB dump|PostgreSQL database dump|Dumping data for table)"
)
_SQL_CREATE_RE = re.compile(r"(?im)^\s*CREATE TABLE\b")
_SQL_INSERT_RE = re.compile(r"(?im)^\s*INSERT INTO\b")
_BACKUP_SUFFIX_RE = re.compile(r"(?i)(?:\.bak|\.old|\.orig|\.save|\.backup|~)$")
_BACKUP_ARCHIVE_NAME_RE = re.compile(
    r"(?i)^(?:backup|backups|dump|database|db|site|www|htdocs|web|public_html|src|source)"
    r"\.(?:zip|tar\.gz|tgz|gz|7z|rar)$"
)
_ARCHIVE_MAGIC = (b"PK\x03\x04", b"\x1f\x8b", b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07")
_DS_STORE_MAGIC = b"\x00\x00\x00\x01Bud1"
# Configuration file names whose JSON body is a configuration document. Server-side
# names admit token/API-key names as secrets; client config may publish public keys.
_SERVER_CONFIG_NAMES = frozenset({"appsettings.json", "secrets.json", "credentials.json"})
_CLIENT_CONFIG_NAMES = frozenset({"config.json", "settings.json"})
_EXAMPLE_KEYS = frozenset({"example", "examples", "x-example", "x-examples"})


@dataclass(frozen=True)
class ExposureSignature:
    """One content classification; only an explicit subset proves sensitivity."""

    exposure_class: str
    severity: str
    matched_pattern: str
    # Proven secrets in the body. Each carries its key, category and fingerprint; the
    # raw value is kept only in memory (repr-hidden) for scrubbing excerpts.
    secrets: tuple[SecretEvidence, ...] = ()

    @property
    def proves_sensitive_exposure(self) -> bool:
        return is_sensitive_exposure_class(self.exposure_class)

    @property
    def proof_contract(self) -> str | None:
        if not self.proves_sensitive_exposure:
            return None
        return EXPOSURE_PROOF_CONTRACTS.get(self.exposure_class)

    def secret_evidence(self) -> list[dict[str, object]]:
        """Key names, categories and fingerprints only -- never a value."""
        return [item.public() for item in self.secrets]


def _content_type(headers: Mapping[str, str]) -> str:
    for name, value in headers.items():
        if str(name).lower() == "content-type":
            return str(value).lower()
    return ""


def _decode(body: bytes) -> str:
    return body[:1_000_000].decode("utf-8", errors="replace")


def _last_segment(path: str) -> str:
    return urllib.parse.urlsplit(str(path or "")).path.rstrip("/").rsplit("/", 1)[-1].lower()


def _dedupe(items: list[SecretEvidence]) -> tuple[SecretEvidence, ...]:
    """One entry per value: the configuration key that holds it, the provider category if known."""
    kept: dict[str, SecretEvidence] = {}
    for item in items:
        prior = kept.get(item.fingerprint)
        if prior is None:
            kept[item.fingerprint] = item
        elif prior.category == "config_secret_assignment" and item.category != prior.category:
            kept[item.fingerprint] = replace(prior, category=item.category)
    return tuple(list(kept.values())[:50])


def _flatten(value: Any, prefix: str = "", depth: int = 0) -> list[tuple[str, object]]:
    """Leaf ``(dotted.key, value)`` pairs of a JSON document, bounded in depth and size."""
    if depth > 8:
        return []
    pairs: list[tuple[str, object]] = []
    if isinstance(value, Mapping):
        for key, item in list(value.items())[:2_000]:
            name = f"{prefix}.{key}" if prefix else str(key)
            pairs.extend(_flatten(item, name, depth + 1))
    elif isinstance(value, list):
        for index, item in enumerate(value[:2_000]):
            pairs.extend(_flatten(item, f"{prefix}[{index}]", depth + 1))
    elif isinstance(value, (str, int, float)) and not isinstance(value, bool):
        pairs.append((prefix, value))
    return pairs


def _leaf_key(dotted: str) -> str:
    return re.split(r"[.\[]", dotted.rstrip("]"))[-1] if dotted else dotted


def _json_document(text: str) -> Any:
    stripped = text.lstrip()
    if not stripped.startswith(("{", "[")):
        return None
    try:
        return json.loads(stripped)
    except ValueError:
        return None


def _dotenv_pairs(text: str) -> list[tuple[str, str]] | None:
    """The assignments of a dotenv/properties file, or None when the body is not one.

    The structure is the proof that key names mean something: at least two
    assignments, and assignments make up at least four in five meaningful lines.
    """
    lines = [
        line for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith(("#", "!"))
    ]
    if len(lines) < 2:
        return None
    pairs: list[tuple[str, str]] = []
    for line in lines:
        match = _DOTENV_LINE_RE.match(line)
        if match:
            pairs.append((match.group(1), match.group(2)))
    if len(pairs) < 2 or len(pairs) * 5 < len(lines) * 4:
        return None
    return pairs


def _secrets(
    text: str, pairs: list[tuple[str, object]], *, server_side: bool,
) -> tuple[SecretEvidence, ...]:
    """Structured secret assignments plus self-evident provider secrets in ``text``."""
    found = structured_secret_assignments(pairs, server_side=server_side)
    found.extend(selfevident_secret_evidence(text))
    return _dedupe(found)


def _escalated(
    exposure_class: str, secrets: tuple[SecretEvidence, ...], base: str | None = None,
) -> str:
    severity = base or _CLASS_SEVERITY[exposure_class]
    categories = {item.category for item in secrets}
    if categories & {"private_key", "aws_access_key"}:
        return "critical"
    if secrets and severity in {"info", "low", "medium"}:
        return "high"
    return severity


def _sig(
    exposure_class: str, matched_pattern: str,
    secrets: tuple[SecretEvidence, ...] = (), *, severity: str | None = None,
) -> ExposureSignature:
    return ExposureSignature(
        exposure_class=exposure_class,
        severity=_escalated(exposure_class, secrets, severity),
        matched_pattern=matched_pattern,
        secrets=secrets,
    )


def _scalar(value: Any) -> bool:
    return isinstance(value, (str, int, float)) and not isinstance(value, bool)


def _actuator_pairs(document: Any) -> list[tuple[str, object]] | None:
    """Property pairs of a Spring actuator ``env`` or ``configprops`` body, else None."""
    if not isinstance(document, Mapping):
        return None
    sources = document.get("propertySources")
    if isinstance(sources, list):  # Boot 2/3 env
        pairs: list[tuple[str, object]] = []
        for source in sources[:200]:
            properties = source.get("properties") if isinstance(source, Mapping) else None
            if not isinstance(properties, Mapping):
                continue
            for key, item in list(properties.items())[:2_000]:
                value = item.get("value") if isinstance(item, Mapping) else item
                if _scalar(value):
                    pairs.append((str(key), value))
        return pairs
    contexts = document.get("contexts")
    if isinstance(contexts, Mapping):  # Boot 2/3 configprops
        bean_maps = [
            context["beans"] for context in list(contexts.values())[:20]
            if isinstance(context, Mapping) and isinstance(context.get("beans"), Mapping)
        ]
        if not bean_maps:
            return None
        pairs = []
        for beans in bean_maps:
            for bean in list(beans.values())[:2_000]:
                if isinstance(bean, Mapping) and isinstance(bean.get("properties"), Mapping):
                    pairs.extend(_flatten(bean["properties"], str(bean.get("prefix") or "")))
        return pairs
    if isinstance(document.get("profiles"), list) and any(
        isinstance(value, Mapping) for value in document.values()
    ):  # Boot 1.x env
        pairs = []
        for source in document.values():
            if isinstance(source, Mapping):
                pairs.extend(
                    (str(key), value) for key, value in list(source.items())[:2_000]
                    if _scalar(value)
                )
        return pairs
    return None


def _actuator_index_advertises_heapdump(document: Any) -> bool:
    """The anonymous actuator index lists a web-exposed heapdump endpoint.

    Spring only lists an endpoint in ``/actuator`` when it is enabled and exposed
    over HTTP, so the index proves the heap dump is served without requesting it.
    """
    links = document.get("_links") if isinstance(document, Mapping) else None
    if not isinstance(links, Mapping) or not isinstance(links.get("self"), Mapping):
        return False
    heapdump = links.get("heapdump")
    href = heapdump.get("href") if isinstance(heapdump, Mapping) else None
    return isinstance(href, str) and href.rstrip("/").endswith("/heapdump")


def _openapi_secrets(document: Any) -> tuple[SecretEvidence, ...] | None:
    """Self-evident secrets in an OpenAPI/Swagger document, or None when it is not one.

    Values under ``example``/``examples`` are documentation by definition and are not
    searched: a sample key in an example proves nothing. Key names alone never count
    in a specification -- it describes parameters, it does not configure a server.
    """
    if not isinstance(document, Mapping):
        return None
    version = document.get("swagger") or document.get("openapi")
    if not isinstance(version, str) or not (
        isinstance(document.get("paths"), Mapping) or isinstance(document.get("info"), Mapping)
    ):
        return None
    found: list[SecretEvidence] = []

    def walk(value: Any, path: str, depth: int) -> None:
        if depth > 12 or len(found) >= 50:
            return
        if isinstance(value, Mapping):
            for key, item in list(value.items())[:2_000]:
                if str(key).lower() in _EXAMPLE_KEYS:
                    continue
                walk(item, f"{path}.{key}" if path else str(key), depth + 1)
        elif isinstance(value, list):
            for index, item in enumerate(value[:2_000]):
                walk(item, f"{path}[{index}]", depth + 1)
        elif isinstance(value, str):
            found.extend(selfevident_secret_evidence(value, key=path))

    walk(document, "", 0)
    return _dedupe(found)


def _web_config(path: str, text: str) -> ExposureSignature | None:
    if not (_WEB_CONFIG_ROOT_RE.search(text) and _WEB_CONFIG_SECTION_RE.search(text)):
        return None
    pairs: list[tuple[str, object]] = list(_XML_ADD_RE.findall(text))
    for connection in _CONNECTION_STRING_RE.findall(text):
        pairs.extend(
            ("connectionString.password", match.strip())
            for match in _CONNECTION_PASSWORD_RE.findall(connection)
        )
    found = list(structured_secret_assignments(pairs, server_side=True))
    found.extend(
        secret_evidence(name, "config_secret_assignment", value)
        for name, value in _MACHINE_KEY_RE.findall(text)
    )
    found.extend(selfevident_secret_evidence(text))
    secrets = _dedupe(found)
    if secrets:
        return _sig("configuration_secret_file", "aspnet_web_config", secrets)
    if _BACKUP_SUFFIX_RE.search(_last_segment(path)):
        return _sig("backup_or_source_artifact", "aspnet_web_config_backup")
    return _sig("configuration_file", "aspnet_web_config")


def _json_signature(path: str, text: str, document: Any) -> ExposureSignature | None:
    actuator = _actuator_pairs(document)
    if actuator is not None:
        secrets = _secrets(text, actuator, server_side=True)
        if secrets:
            return _sig("actuator_secret_disclosure", "actuator_property_sources", secrets)
        return _sig("actuator_endpoint", "actuator_property_sources")
    if _actuator_index_advertises_heapdump(document):
        return _sig("actuator_heapdump_exposed", "actuator_index_heapdump_link")
    spec_secrets = _openapi_secrets(document)
    if spec_secrets is not None:
        if spec_secrets:
            return _sig("api_specification_secret", "openapi_document_secret", spec_secrets)
        return _sig("exposed_api_specification", "openapi_document")
    name = _last_segment(path)
    if name not in _SERVER_CONFIG_NAMES and name not in _CLIENT_CONFIG_NAMES:
        return None
    pairs = _flatten(document)
    leaf_pairs: list[tuple[str, object]] = [(_leaf_key(key), value) for key, value in pairs]
    for key, value in pairs:
        if "connection" in key.lower() and isinstance(value, str):
            leaf_pairs.extend(
                (f"{_leaf_key(key)}.password", match.strip())
                for match in _CONNECTION_PASSWORD_RE.findall(value)
            )
    secrets = _secrets(text, leaf_pairs, server_side=name in _SERVER_CONFIG_NAMES)
    if secrets:
        return _sig("configuration_secret_file", "json_configuration_secret", secrets)
    return None


def _structured_text(path: str, text: str) -> ExposureSignature | None:
    """Proofs for non-HTML bodies whose own grammar identifies the file type."""
    if _GIT_CORE_HEADER_RE.search(text) and _GIT_CORE_KEY_RE.search(text):
        return _sig("version_control_exposure", "git_config_core_section",
                    _dedupe(selfevident_secret_evidence(text)))
    if _GIT_HEAD_RE.match(text):
        return _sig("version_control_exposure", "git_head_ref")
    document = _json_document(text)
    if document is not None:
        return _json_signature(path, text, document)
    dotenv = _dotenv_pairs(text)
    if dotenv is not None:
        secrets = _secrets(text, list(dotenv), server_side=True)
        if secrets:
            return _sig("environment_secret_file", "dotenv_secret_assignment", secrets)
        return _sig("configuration_file", "dotenv_assignments")
    web_config = _web_config(path, text)
    if web_config is not None:
        return web_config
    if _SQL_DUMP_HEADER_RE.search(text) or (
        _SQL_CREATE_RE.search(text) and _SQL_INSERT_RE.search(text)
    ):
        return _sig("backup_or_source_artifact", "sql_dump",
                    _dedupe(selfevident_secret_evidence(text)))
    return None


def _structured_html(text: str) -> ExposureSignature | None:
    """Proofs for server-generated diagnostic pages, which are HTML by nature."""
    if _PHPINFO_TITLE_RE.search(text) and _PHPINFO_VERSION_RE.search(text):
        rows: list[tuple[str, object]] = list(_HTML_ROW_RE.findall(text))
        return _sig("phpinfo_disclosure", "phpinfo_page", _secrets(text, rows, server_side=True))
    if _WERKZEUG_CONSOLE_RE.search(text) and _WERKZEUG_MARKER_RE.search(text):
        # An interactive debugger console executes code once its PIN is known.
        return _sig("debug_interface_exposure", "werkzeug_debugger_console", severity="high")
    if _PPROF_RE.search(text):
        return _sig("debug_interface_exposure", "go_pprof_index")
    return None


def _cloud_credentials(text: str) -> tuple[SecretEvidence, ...]:
    found = [
        item for item in selfevident_secret_evidence(text)
        if item.category == "aws_access_key"
    ]
    found.extend(
        item for item in structured_secret_assignments(
            [("aws_secret_access_key", value) for value in _AWS_SECRET_RE.findall(text)],
            server_side=True,
        )
    )
    return _dedupe(found)


def classify_exposure(
    *, path: str, status: int, headers: Mapping[str, str], body: bytes,
) -> ExposureSignature | None:
    """Return a deterministic exposure class, or ``None`` when nothing matches.

    A concrete response signature identifies observed content, not necessarily
    a vulnerability. A 200 that
    merely returns the SPA shell, a 401/403/404, or an empty body is ignored so
    a soft-200 application never inflates exposure coverage. Every file-type
    proof matches the file's own grammar, never a word that a page of prose about
    the file could also contain; and a generic secret pattern is only read from a
    non-HTML body, so a documentation page quoting a sample key proves nothing.
    """
    if status != 200 or not body:
        return None
    if body.startswith(_DS_STORE_MAGIC):
        return _sig("directory_metadata_file", "ds_store_bud1_header")
    if body.startswith(_ARCHIVE_MAGIC) and _BACKUP_ARCHIVE_NAME_RE.match(_last_segment(path)):
        return _sig("backup_or_source_artifact", "backup_archive_magic")
    text = _decode(body)
    content_type = _content_type(headers)
    is_html = any(marker in content_type for marker in _HTML_TYPES) or bool(
        _HTML_PREFIX_RE.match(text[:512])
    )

    structured = _structured_html(text) if is_html else _structured_text(path, text)
    if structured is not None:
        return structured

    # Secret material in any other non-HTML body is the strongest remaining signal.
    if not is_html:
        if _PRIVATE_KEY_RE.search(text):
            return _sig("private_key_material", _PRIVATE_KEY_RE.pattern,
                        _dedupe(selfevident_secret_evidence(text)))
        cloud = _cloud_credentials(text)
        if cloud:
            return _sig("cloud_credential_material", "aws_credential", cloud)
    if _METRICS_RE.search(text) and not is_html:
        return _sig("metrics_endpoint", _METRICS_RE.pattern)
    if content_type.startswith(_ACTUATOR_MEDIA_TYPE) and "+json" in content_type:
        return _sig("actuator_endpoint", "actuator_vendor_media_type")
    if _LISTING_RE.search(text):
        return _sig("directory_listing", _LISTING_RE.pattern)
    if _ERROR_RE.search(text):
        return _sig("verbose_error_disclosure", "server_error_disclosure")
    return None


def classify_confidential_file(
    *, path: str, status: int, headers: Mapping[str, str], body: bytes,
) -> ExposureSignature | None:
    """Record listed-file reachability without inventing confidentiality.

    A filename, path, content type, or the word "confidential" is not an
    authorization oracle. Only the existing content-specific secret contracts
    may produce verified sensitivity. RFC 8615 defines a discovery namespace,
    not a blanket public/nonsensitive exemption for everything below it.
    """
    if status != 200 or not body:
        return None
    signature = classify_exposure(path=path, status=status, headers=headers, body=body)
    if signature is not None:
        return signature
    if any(marker in _content_type(headers) for marker in _HTML_TYPES):
        return None
    return _sig("listed_file", "listed_file_reachable")


def is_sensitive_exposure_class(exposure_class: str) -> bool:
    """Promotion boundary, also applied to historical observations.

    A deterministic exposure of secret content or source, or a server autoindexing a
    directory / serving an internal metrics endpoint, debug interface or heap dump, is a
    finding: the server state is itself the proof. Pure identity or reachability --
    framework fingerprint (``actuator_endpoint``), the mere presence of an API spec or
    a configuration file without a proven secret, and a file whose listing establishes
    no sensitivity (``listed_file``) -- stays an unpromoted observation; a secret leaked
    through any of them is still caught by the content-specific classes.
    """
    return exposure_class in _PROMOTABLE_EXPOSURE_CLASSES


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


SECRET_MATERIAL_CLASSES = frozenset({
    "private_key_material",
    "cloud_credential_material",
    "environment_secret_file",
    "actuator_secret_disclosure",
    "api_specification_secret",
    "configuration_secret_file",
})
_SECRET_MATERIAL_CLASSES = SECRET_MATERIAL_CLASSES

# Classes that promote to a finding: exactly those with a deterministic proof contract.
_PROMOTABLE_EXPOSURE_CLASSES = frozenset(EXPOSURE_PROOF_CONTRACTS)


def redacted_exposure_excerpt(body: bytes, signature: ExposureSignature) -> str:
    """Return a short, secret-redacted evidence excerpt around the match.

    For secret-material classes, and for any body in which a secret was proven, the
    body itself is the secret, so no content is excerpted at all -- only the fact of
    disclosure and the fingerprinted key names are recorded. Other excerpts pass
    through the shared redactor with every value this body is known to hold.
    """
    if signature.exposure_class == "listed_file":
        return "[File reachable; sensitivity not established; content withheld]"
    if signature.exposure_class in _SECRET_MATERIAL_CLASSES or signature.secrets:
        return (
            f"[{signature.exposure_class} detected - content withheld; "
            f"{len(signature.secrets)} secret value(s) fingerprinted]"
        )
    if body.startswith((_DS_STORE_MAGIC, *_ARCHIVE_MAGIC)):
        return f"[{signature.exposure_class} detected - binary content withheld]"
    text = _decode(body)
    try:
        compiled = re.compile(signature.matched_pattern)
    except re.error:
        compiled = None
    found = compiled.search(text) if compiled is not None else None
    if found is not None:
        start = max(0, found.start() - 40)
        text = text[start:found.end() + 160]
    sample = " ".join(text.split())[:400]
    known = [item.value for item in selfevident_secret_evidence(_decode(body)) if item.value]
    sample = _shared_redact_text(sample, known_values=known)
    return _SECRET_REDACT_RE.sub(
        lambda item: f"{item.group(1)}=[REDACTED]", sample,
    )


__all__ = [
    "DIRECTORY_FOLLOW_UP_FLOOR",
    "EXPOSURE_PROBE_PARSER_VERSION",
    "EXPOSURE_PROOF_CONTRACTS",
    "SECRET_MATERIAL_CLASSES",
    "SENSITIVE_SEED_PATHS",
    "SOFT_404_CONTROL_COUNT",
    "ExposureSignature",
    "classify_confidential_file",
    "classify_exposure",
    "directory_listing_links",
    "exposure_first_slice_hold",
    "is_never_requested",
    "is_sensitive_exposure_class",
    "redacted_exposure_excerpt",
]
