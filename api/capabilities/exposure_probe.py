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
from dataclasses import dataclass, field
from typing import Any
from .error_disclosure import runtime_error_disclosed

from .graphql_probe import (
    GRAPHQL_IDE_HEADERS,
    GRAPHQL_IDE_PATHS,
    GRAPHQL_REQUEST_HEADERS,
    INTROSPECTION_QUERY,
    graphql_request_url,
    ide_page as graphql_ide_page,
    introspection_summary as graphql_introspection_summary,
    is_ide_location as graphql_ide_location,
    is_introspection_request as graphql_introspection_request,
    seed_endpoint_urls as graphql_seed_endpoint_urls,
)
from .secret_material import (
    is_masked_or_indirect_value,
    normalized_key_name,
    SecretEvidence,
    fingerprinted_secret_evidence,
    is_structured_secret_value,
    redact_text_assignments,
    redactable_assignments,
    secret_evidence,
    selfevident_secret_evidence,
    structured_secret_assignments,
    text_assignment_values,
)

try:
    from redaction import redact_text as _shared_redact_text
except ModuleNotFoundError:  # package layout in host-side tests
    from scanner.redaction import redact_text as _shared_redact_text


EXPOSURE_PROBE_PARSER_VERSION = "exposure-probe/v4"

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
    # Credential stores a deployed home or build directory can leak (soak N42): git's
    # credential helper store, netrc, and the npm and PyPI publishing configurations.
    "/.git-credentials",
    "/.netrc",
    "/.npmrc",
    "/.pypirc",
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



def graphql_seed_probes(base_origin: str) -> tuple[tuple[str, tuple[tuple[str, str], ...]], ...]:
    """Fixed GraphQL reads probed once with the seed list: ``(url, headers)``.

    Each conventional endpoint is sent the fixed introspection document over GET (read-only by
    GraphQL over HTTP: a GET carries only a query, and this one selects only ``__schema``);
    each IDE location is requested as a browser would. Nothing varies with the target.
    """
    return (
        *(
            (graphql_request_url(url, INTROSPECTION_QUERY), GRAPHQL_REQUEST_HEADERS)
            for url in graphql_seed_endpoint_urls(base_origin)
        ),
        *((f"{base_origin}{path}", GRAPHQL_IDE_HEADERS) for path in GRAPHQL_IDE_PATHS),
    )


GRAPHQL_SEED_PROBE_COUNT = len(graphql_seed_probes(""))

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
    seeds = len(SENSITIVE_SEED_PATHS) + GRAPHQL_SEED_PROBE_COUNT + SOFT_404_CONTROL_COUNT
    endpoints = max(0, int(slice_count))
    return {
        "http_requests": seeds + endpoints + DIRECTORY_FOLLOW_UP_FLOOR,
        "tool_wall_seconds": seeds + 3 * endpoints,
    }


# Per-probe timeout (soak N37). Dividing the batch's wall by its request allowance gave every
# probe about 0.86 s on honey, so /.env -- the first probe, carrying the connection set-up --
# timed out and was recorded as examined. A probe now waits at least the floor, longer on a host
# whose measured responses are slow, never past the ceiling, and never past the batch's wall.
EXPOSURE_PROBE_TIMEOUT_FLOOR_SECONDS = 5.0
EXPOSURE_PROBE_TIMEOUT_CEILING_SECONDS = 15.0
# A probe may take this many times the slowest response the batch has measured.
EXPOSURE_PROBE_LATENCY_MULTIPLE = 4.0
# Below this much wall left, a probe is not started: it could only time out.
EXPOSURE_PROBE_MIN_START_SECONDS = 1.0


def exposure_probe_timeout(
    *, measured_ms: tuple[int, ...] | list[int], remaining_wall_seconds: float, retry: bool = False,
) -> float:
    """Seconds one exposure probe may wait, from the latency the batch measured.

    The first attempt waits the larger of the floor and ``EXPOSURE_PROBE_LATENCY_MULTIPLE``
    times the slowest measured response, capped at the ceiling. A retry of a probe that timed
    out waits the ceiling. Either is cut to the wall the batch has left.
    """
    slowest = max((int(item) for item in measured_ms if int(item) > 0), default=0) / 1000.0
    wanted = (
        EXPOSURE_PROBE_TIMEOUT_CEILING_SECONDS if retry
        else max(EXPOSURE_PROBE_TIMEOUT_FLOOR_SECONDS, EXPOSURE_PROBE_LATENCY_MULTIPLE * slowest)
    )
    return max(0.0, min(EXPOSURE_PROBE_TIMEOUT_CEILING_SECONDS, wanted, float(remaining_wall_seconds)))


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
    # A developer left a credential in an HTML comment that every visitor receives.
    "html_comment_secret": "high",
    # An anonymous response lists several user records with their plaintext passwords.
    "credential_record_disclosure": "critical",
    # The whole schema is readable without credentials, and an in-browser IDE is served to
    # anyone; both are configuration that production GraphQL deployments turn off.
    "graphql_introspection_enabled": "low",
    "graphql_ide_exposure": "low",
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
    "html_comment_secret": "html_comment_secret_exposure/v1",
    "credential_record_disclosure": "credential_record_exposure/v1",
    "graphql_introspection_enabled": "graphql_introspection_exposure/v1",
    "graphql_ide_exposure": "graphql_ide_exposure/v1",
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
#
# Every pattern here runs over a hostile body of up to a megabyte, so none may backtrack
# super-linearly: a line anchor is followed by ``[ \t]*`` (``\s*`` would also eat newlines and
# rescan every following blank line from every line start), repetitions that can fail are
# bounded, and multi-part grammars are matched in linear steps rather than one lazy pattern.
_GIT_CORE_HEADER_RE = re.compile(r"(?m)^[ \t]*\[core\][ \t]*\r?$")
_GIT_CORE_KEY_RE = re.compile(
    r"(?m)^[ \t]*(?:repositoryformatversion|filemode|bare|logallrefupdates)[ \t]*=[ \t]*\S"
)
_GIT_HEAD_RE = re.compile(r"^\s*(?:ref:\s*refs/[A-Za-z0-9._/-]+|[0-9a-f]{40}|[0-9a-f]{64})\s*$")
_DOTENV_LINE_RE = re.compile(
    r"[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_.\-]{0,199})[ \t]*=(.*)"
)
# A Prometheus exposition: a ``# HELP`` line and, after it, a ``# TYPE`` line.
_METRICS_HELP_RE = re.compile(r"(?m)^# HELP \S")
_METRICS_TYPE_RE = re.compile(r"(?m)^# TYPE \S")
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
    r"|^[ \t]*at [\w.$]{1,300}\([\w.$]{1,300}:\d+\)"
    r"|org\.springframework\.[\w.]{1,300}Exception"
    r"|Fatal error:\s|Warning:[ \t][^\n]{0,300}?on line \d+"
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
    r"(?is)<tr[^<>]{0,256}>[ \t\r\n]{0,64}<td[^<>]{0,256}>([^<]{1,200})</td>[ \t\r\n]{0,64}"
    r"<td[^<>]{0,256}>([^<]{0,500})</td>"
)
_WERKZEUG_CONSOLE_RE = re.compile(r"(?i)<title>[^<]*//\s*Werkzeug Debugger</title>")
_WERKZEUG_MARKER_RE = re.compile(r"__debugger__|\bEVALEX\b|CONSOLE_MODE")
_PPROF_RE = re.compile(r"(?i)<title>\s*/debug/pprof/\s*</title>")
_WEB_CONFIG_ROOT_RE = re.compile(r"<configuration[\s>]")
_WEB_CONFIG_SECTION_RE = re.compile(
    r"<(?:system\.web|system\.webServer|appSettings|connectionStrings)[\s>/]"
)
# An ``<add .../>`` element is read as one bounded tag, then its attributes are tokenized:
# the tag cannot run past the next ``<``, so the scan is linear in the body.
_XML_ADD_TAG_RE = re.compile(r"(?i)<add\s([^<>]{0,4096})>")
_XML_ATTRIBUTE_RE = re.compile(r'([A-Za-z_:][\w:.\-]{0,63})[ \t\r\n]*=[ \t\r\n]*"([^"]{0,2000})"')
_CONNECTION_STRING_RE = re.compile(r'(?is)\bconnectionString\s*=\s*"([^"]{1,2000})"')
_CONNECTION_PASSWORD_RE = re.compile(r"(?i)(?:^|;)\s*(?:password|pwd)\s*=\s*([^;]+)")
_MACHINE_KEY_RE = re.compile(r'(?i)\b(validationKey|decryptionKey)\s*=\s*"([0-9A-F]{32,})"')
_SQL_DUMP_HEADER_RE = re.compile(
    r"(?m)^--\s*(?:MySQL dump|MariaDB dump|PostgreSQL database dump|Dumping data for table)"
)
_SQL_CREATE_RE = re.compile(r"(?im)^[ \t]*CREATE TABLE\b")
_SQL_INSERT_RE = re.compile(r"(?im)^[ \t]*INSERT INTO\b")
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
# Key/value grammars (dotenv, XML attributes, phpinfo rows) are parsed over at most this many
# characters of a body; a configuration file is a few kilobytes. Leaf pairs taken from one
# JSON document are bounded the same way.
_PARSE_MAX_CHARS = 262_144
_MAX_DOCUMENT_PAIRS = 20_000


def exposure_signature_contract(exposure_class: str, matched_pattern: str) -> str | None:
    """The producer chooses a contract from recognized class/signature metadata."""
    if matched_pattern == "http_error_stack_trace":
        return "verbose_error_exposure/v2" if exposure_class == "verbose_error_disclosure" else None
    return EXPOSURE_PROOF_CONTRACTS.get(exposure_class)


def exposure_observation_contract(observation: Mapping[str, Any]) -> str | None:
    """Reconstruct the producer's contract; a stored contract name grants no proof."""
    exposure_class = str(observation.get("exposure_class") or "")
    pattern = str(observation.get("matched_signature") or "")
    status = observation.get("response_status")
    if pattern == "http_error_stack_trace":
        if type(status) is not int or not 500 <= status <= 599:
            return None
    elif type(status) is not int or status != 200:
        return None
    return exposure_signature_contract(exposure_class, pattern)


@dataclass(frozen=True)
class ExposureSignature:
    """One content classification; only an explicit subset proves sensitivity."""

    exposure_class: str
    severity: str
    matched_pattern: str
    # Proven secrets in the body. Each carries its key, category and fingerprint; the
    # raw value is kept only in memory (repr-hidden) for scrubbing excerpts.
    secrets: tuple[SecretEvidence, ...] = ()
    # Every secret-NAMED key of a recognised document, proven or not, and its raw value
    # (memory only, repr-hidden). Proof decides the class; these decide what is never shown.
    withheld_keys: tuple[str, ...] = ()
    withheld_values: tuple[str, ...] = field(default=(), repr=False, compare=False)

    @property
    def proves_sensitive_exposure(self) -> bool:
        return is_sensitive_exposure_class(self.exposure_class)

    @property
    def proof_contract(self) -> str | None:
        if not self.proves_sensitive_exposure:
            return None
        return exposure_signature_contract(self.exposure_class, self.matched_pattern)

    def secret_evidence(self) -> list[dict[str, object]]:
        """Key names, categories and fingerprints only -- never a value."""
        return [item.public() for item in self.secrets]

    @property
    def withholds_content(self) -> bool:
        """No excerpt and no plain digest of this body is stored: it is secret material, a
        configuration document, a file of unestablished sensitivity, or it carries a proven
        secret or a value under a secret-named key."""
        return bool(
            self.exposure_class in SECRET_MATERIAL_CLASSES
            or self.exposure_class == "listed_file"
            or self.matched_pattern in _CONFIG_DOCUMENT_PATTERNS
            or self.secrets or self.withheld_keys or self.withheld_values
        )


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
    """One entry per value, cut before any value is fingerprinted."""
    return fingerprinted_secret_evidence(items)


def _flatten(value: Any, prefix: str = "") -> list[tuple[str, object]]:
    """Leaf ``(dotted.key, value)`` pairs of a JSON document, bounded in depth and total size."""
    pairs: list[tuple[str, object]] = []

    def walk(item: Any, name: str, depth: int) -> None:
        if depth > 8 or len(pairs) >= _MAX_DOCUMENT_PAIRS:
            return
        if isinstance(item, Mapping):
            for key, child in list(item.items())[:2_000]:
                walk(child, f"{name}.{key}" if name else str(key), depth + 1)
        elif isinstance(item, list):
            for index, child in enumerate(item[:2_000]):
                walk(child, f"{name}[{index}]", depth + 1)
        elif isinstance(item, (str, int, float)) and not isinstance(item, bool):
            pairs.append((name, item))

    walk(value, prefix, 0)
    return pairs


def _leaf_key(dotted: str) -> str:
    return re.split(r"[.\[]", dotted.rstrip("]"))[-1] if dotted else dotted


def _json_document(text: str) -> Any:
    stripped = text.lstrip()
    if not stripped.startswith(("{", "[")):
        return None
    try:
        return json.loads(stripped)
    except (ValueError, RecursionError):  # a hostile, deeply nested body
        return None


def _dotenv_pairs(text: str) -> list[tuple[str, str]] | None:
    """The assignments of a dotenv/properties file, or None when the body is not one.

    The structure is the proof that key names mean something: at least two
    assignments, and assignments make up at least four in five meaningful lines.
    """
    lines = [
        line for line in text[:_PARSE_MAX_CHARS].splitlines()
        if line.strip() and not line.lstrip().startswith(("#", "!"))
    ]
    if len(lines) < 2:
        return None
    pairs: list[tuple[str, str]] = []
    for line in lines:
        match = _DOTENV_LINE_RE.fullmatch(line)
        if match:
            pairs.append((match.group(1), match.group(2).strip()))
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
    pairs: list[tuple[str, object]] | None = None,
) -> ExposureSignature:
    """``pairs`` are the document's key/value pairs: every secret-named one is withheld."""
    keys, values = redactable_assignments(pairs) if pairs else ((), ())
    return ExposureSignature(
        exposure_class=exposure_class,
        severity=_escalated(exposure_class, secrets, severity),
        matched_pattern=matched_pattern,
        secrets=secrets,
        withheld_keys=keys,
        withheld_values=values,
    )


def _scalar(value: Any) -> bool:
    return isinstance(value, (str, int, float)) and not isinstance(value, bool)


def _actuator_pairs(document: Any) -> list[tuple[str, object]] | None:
    """Property pairs of a Spring actuator ``env``, ``configprops`` or ``auditevents`` body, else None."""
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
            if len(pairs) >= _MAX_DOCUMENT_PAIRS:
                break
        return pairs[:_MAX_DOCUMENT_PAIRS]
    events = document.get("events")
    if isinstance(events, list) and events and all(
        isinstance(event, Mapping) and "type" in event and "timestamp" in event
        for event in events[:200]
    ):  # Boot 2/3 auditevents: each event's data is what the application recorded
        pairs = []
        for event in events[:2_000]:
            data = event.get("data")
            if isinstance(data, Mapping):
                pairs.extend((_leaf_key(key), value) for key, value in _flatten(data))
            if len(pairs) >= _MAX_DOCUMENT_PAIRS:
                break
        return pairs[:_MAX_DOCUMENT_PAIRS]
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
                if len(pairs) >= _MAX_DOCUMENT_PAIRS:
                    return pairs[:_MAX_DOCUMENT_PAIRS]
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
        return pairs[:_MAX_DOCUMENT_PAIRS]
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


# Actuator endpoints the index may lead to: read-only property and event dumps. Only these are
# followed, only same-origin, never templated hrefs, and never the heap dump.
ACTUATOR_FOLLOW_ENDPOINTS: tuple[str, ...] = ("auditevents", "env", "configprops")


def actuator_index_links(body: bytes, base_url: str) -> tuple[str, ...]:
    """Same-origin URLs of the read-only endpoints an anonymous actuator index advertises."""
    document = _json_document(_decode(body))
    links = document.get("_links") if isinstance(document, Mapping) else None
    if not isinstance(links, Mapping) or not isinstance(links.get("self"), Mapping):
        return ()
    origin = urllib.parse.urlsplit(base_url)
    found: list[str] = []
    for name in ACTUATOR_FOLLOW_ENDPOINTS:
        entry = links.get(name)
        if not isinstance(entry, Mapping) or entry.get("templated") is True:
            continue
        href = entry.get("href")
        if not isinstance(href, str) or not href:
            continue
        parts = urllib.parse.urlsplit(urllib.parse.urljoin(base_url, href))
        # The index names its own host; follow the path on the origin actually probed.
        if parts.path.rstrip("/").rsplit("/", 1)[-1] != name or is_never_requested(parts.path):
            continue
        found.append(urllib.parse.urlunsplit((origin.scheme, origin.netloc, parts.path, "", "")))
    return tuple(found)


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


def _xml_add_pairs(text: str) -> list[tuple[str, object]]:
    """``(key, value)`` of each ``<add key=".." value=".."/>`` element, in linear time."""
    pairs: list[tuple[str, object]] = []
    for tag in _XML_ADD_TAG_RE.finditer(text):
        attributes = {
            name.lower(): value for name, value in _XML_ATTRIBUTE_RE.findall(tag.group(1))
        }
        key = attributes.get("key")
        if key and "value" in attributes:
            pairs.append((key[:200], attributes["value"]))
        if len(pairs) >= _MAX_DOCUMENT_PAIRS:
            break
    return pairs


def _web_config(path: str, text: str) -> ExposureSignature | None:
    if not (_WEB_CONFIG_ROOT_RE.search(text) and _WEB_CONFIG_SECTION_RE.search(text)):
        return None
    text = text[:_PARSE_MAX_CHARS]
    pairs = _xml_add_pairs(text)
    for connection in _CONNECTION_STRING_RE.findall(text):
        pairs.extend(
            ("connectionString.password", match.strip())
            for match in _CONNECTION_PASSWORD_RE.findall(connection)
        )
    machine_keys = _MACHINE_KEY_RE.findall(text)
    found = list(structured_secret_assignments(pairs, server_side=True))
    found.extend(
        secret_evidence(name, "config_secret_assignment", value) for name, value in machine_keys
    )
    found.extend(selfevident_secret_evidence(text))
    secrets = _dedupe(found)
    pairs.extend(machine_keys)
    if secrets:
        return _sig("configuration_secret_file", "aspnet_web_config", secrets, pairs=pairs)
    if _BACKUP_SUFFIX_RE.search(_last_segment(path)):
        return _sig("backup_or_source_artifact", "aspnet_web_config_backup", pairs=pairs)
    return _sig("configuration_file", "aspnet_web_config", pairs=pairs)


def _json_signature(path: str, text: str, document: Any) -> ExposureSignature | None:
    # Introspection is proven by the answer to the introspection request only; a schema file
    # served as a static document says nothing about the server answering introspection.
    if graphql_introspection_request(path) and graphql_introspection_summary(document) is not None:
        return _sig("graphql_introspection_enabled", '"__schema"')
    records = _credential_record_signature(document)
    if records is not None:
        return records
    actuator = _actuator_pairs(document)
    if actuator is not None:
        secrets = _secrets(text, actuator, server_side=True)
        if secrets:
            return _sig("actuator_secret_disclosure", "actuator_property_sources", secrets,
                        pairs=actuator)
        return _sig("actuator_endpoint", "actuator_property_sources", pairs=actuator)
    if _actuator_index_advertises_heapdump(document):
        # The index advertises a route, not its authorization or response. Fetching a
        # heap dump is deliberately forbidden: retain discovery without claiming proof.
        return _sig("actuator_endpoint", "actuator_index_heapdump_link")
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
        return _sig("configuration_secret_file", "json_configuration_secret", secrets,
                    pairs=leaf_pairs)
    return None


# --- Credential stores (soak N42) -----------------------------------------------------------
# Each is proved by its own grammar, never its name alone, and the whole body is withheld.
# `.git-credentials`: one credentialed URL per line, as `git credential-store` writes them.
_GIT_CREDENTIAL_LINE_RE = re.compile(
    r"(?:https?|ftps?)://([^:/@\s]{1,256}):([^@\s]{1,1024})@([A-Za-z0-9.\-]{1,253})(?::\d{1,5})?(?:/\S{0,2048})?"
)
# `.npmrc`: ini assignments; an auth key, possibly scoped to a registry (`//host/:_authToken`).
_NPMRC_LINE_RE = re.compile(r"[ \t]*([^=\s#;][^=\r\n]{0,511}?)[ \t]*=[ \t]*(.*?)[ \t]*")
_NPMRC_AUTH_KEY_RE = re.compile(r"(?:^|:)(_authToken|_auth|_password)$")
# `.pypirc`: an ini file with a [distutils] index-servers list or a [pypi]/[testpypi] section.
_INI_SECTION_RE = re.compile(r"[ \t]*\[([^\]\r\n]{1,128})\][ \t]*")
_INI_ASSIGNMENT_RE = re.compile(r"[ \t]*([A-Za-z0-9_.\-]{1,128})[ \t]*[=:][ \t]*(.*?)[ \t]*")
_NETRC_KEYWORDS = frozenset({"machine", "default", "login", "password", "account", "macdef"})
_CREDENTIAL_STORE_NAMES = frozenset({".git-credentials", ".netrc", "_netrc", ".npmrc", ".pypirc"})


def _grammar_lines(text: str) -> list[str]:
    return [
        line.strip() for line in text[:_PARSE_MAX_CHARS].splitlines()
        if line.strip() and not line.lstrip().startswith(("#", ";"))
    ]


def _git_credentials_pairs(text: str) -> list[tuple[str, object]] | None:
    lines = _grammar_lines(text)
    pairs: list[tuple[str, object]] = []
    for line in lines:
        match = _GIT_CREDENTIAL_LINE_RE.fullmatch(line)
        if match:
            pairs.append((f"{match.group(3).lower()}.password", urllib.parse.unquote(match.group(2))))
    # Every meaningful line is a credentialed URL, as the credential store writes them.
    if not pairs or len(pairs) * 5 < len(lines) * 4:
        return None
    return pairs[:_MAX_DOCUMENT_PAIRS]


def _netrc_pairs(text: str) -> list[tuple[str, object]] | None:
    tokens = " ".join(_grammar_lines(text)).split()[:_MAX_DOCUMENT_PAIRS]
    if not tokens or tokens[0] not in {"machine", "default"}:
        return None
    pairs: list[tuple[str, object]] = []
    machine = "default"
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "default":
            machine, index = "default", index + 1
            continue
        if token not in _NETRC_KEYWORDS or index + 1 >= len(tokens):
            return None
        value = tokens[index + 1]
        if token == "machine":
            machine = value.lower()
        elif token in {"password", "account"}:
            pairs.append((f"{machine}.{token}", value))
        elif token == "macdef":
            break
        index += 2
    return pairs or None


def _npmrc_pairs(text: str) -> list[tuple[str, object]] | None:
    lines = _grammar_lines(text)
    assignments = [match for line in lines if (match := _NPMRC_LINE_RE.fullmatch(line))]
    if len(assignments) * 5 < len(lines) * 4:
        return None
    pairs: list[tuple[str, object]] = [
        (match.group(1).strip(), match.group(2).strip().strip("\"'"))
        for match in assignments if _NPMRC_AUTH_KEY_RE.search(match.group(1).strip())
    ]
    return pairs[:_MAX_DOCUMENT_PAIRS] or None


def _pypirc_pairs(text: str) -> list[tuple[str, object]] | None:
    section = ""
    sections: set[str] = set()
    pairs: list[tuple[str, object]] = []
    for line in _grammar_lines(text):
        header = _INI_SECTION_RE.fullmatch(line)
        if header:
            section = header.group(1).strip().lower()
            sections.add(section)
            continue
        assignment = _INI_ASSIGNMENT_RE.fullmatch(line)
        if assignment is None:
            if section == "distutils":
                continue  # an index-servers continuation line
            return None
        if assignment.group(1).lower() == "password" and section:
            pairs.append((f"{section}.password", assignment.group(2)))
    if not sections & {"distutils", "pypi", "testpypi"}:
        return None
    return pairs[:_MAX_DOCUMENT_PAIRS] or None


_CREDENTIAL_STORE_PARSERS = (
    (".git-credentials", "git_credentials_store", _git_credentials_pairs),
    (".netrc", "netrc_credentials", _netrc_pairs),
    ("_netrc", "netrc_credentials", _netrc_pairs),
    (".npmrc", "npmrc_auth_token", _npmrc_pairs),
    (".pypirc", "pypirc_credentials", _pypirc_pairs),
)


def _credential_store(path: str, text: str) -> ExposureSignature | None:
    """A credential store proved by its own grammar.

    A stored credential that passes the shared entropy screen (or is a provider-format token)
    verifies a ``configuration_secret_file``; a store whose values are placeholders, masked,
    indirect (``${NPM_TOKEN}``) or low-entropy is a ``configuration_file`` observation. Either
    way the body is withheld: the record keeps the class, the key names and fingerprints.
    """
    name = _last_segment(path)
    if name not in _CREDENTIAL_STORE_NAMES:
        return None
    for file_name, pattern, parse in _CREDENTIAL_STORE_PARSERS:
        if name != file_name:
            continue
        pairs = parse(text)
        if pairs is None:
            return None
        found = [
            secret_evidence(str(key), "config_secret_assignment", str(value).strip())
            for key, value in pairs if is_structured_secret_value(value)
        ]
        found.extend(selfevident_secret_evidence(text[:_PARSE_MAX_CHARS]))
        secrets = _dedupe(found)
        if secrets:
            return _sig("configuration_secret_file", pattern, secrets, pairs=pairs)
        return _sig("configuration_file", pattern, pairs=pairs)
    return None


# --- Password-hash files ---------------------------------------------------------------------
# ``user:hash`` lines as htpasswd (and the shadow file, with its trailing fields) store them. The
# hash shape is the proof: modular crypt (``$apr1$``, ``$1$``, ``$5$``, ``$6$``, bcrypt, argon2) or
# an LDAP-style ``{SHA}``/``{SSHA}`` digest. Thirteen-character DES crypt has no marker of its own,
# so it counts only in a file named as a password file.
_PASSWORD_FILE_LINE_RE = re.compile(r"([^:\s#][^:\s]{0,255}):([^:\s]{1,512})(?::\S{0,1024})?")
_PASSWORD_HASH_FIELD_RE = re.compile(
    r"\$(?:apr1|1|5|6)\$(?:rounds=\d{1,9}\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{22,86}"
    r"|\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}"
    r"|\$argon2(?:id|i|d)\$[A-Za-z0-9+/=,$]{20,256}"
    r"|\{SHA\}[A-Za-z0-9+/]{27}="
    r"|\{SSHA\}[A-Za-z0-9+/]{24,128}={0,2}"
)
_DES_CRYPT_FIELD_RE = re.compile(r"[./A-Za-z0-9]{13}")
_PASSWORD_FILE_NAME_RE = re.compile(
    r"(?i)^(?:\.?htpasswd[\w.\-]{0,32}|[\w.\-]{0,32}\.htpasswd|\.?passwd|shadow)$"
)


def _password_hash_file(path: str, text: str) -> ExposureSignature | None:
    """A password file: every meaningful line is ``user:field`` and at least one field is a hash.

    The hash is the secret: it is cracked offline at the attacker's pace. Each one is
    fingerprinted under ``<user>.password`` (category ``password_hash``) and the whole body is
    withheld.
    """
    lines = _grammar_lines(text)
    if not lines:
        return None
    named = bool(_PASSWORD_FILE_NAME_RE.match(_last_segment(path)))
    grammar = 0
    pairs: list[tuple[str, object]] = []
    for line in lines:
        match = _PASSWORD_FILE_LINE_RE.fullmatch(line)
        if match is None:
            continue
        grammar += 1
        user, hashed = match.group(1), match.group(2)
        if _PASSWORD_HASH_FIELD_RE.fullmatch(hashed) or (
            named and _DES_CRYPT_FIELD_RE.fullmatch(hashed)
        ):
            pairs.append((f"{user}.password", hashed))
            if len(pairs) >= _MAX_DOCUMENT_PAIRS:
                break
    if not pairs or grammar * 5 < len(lines) * 4:
        return None
    secrets = _dedupe([secret_evidence(str(key), "password_hash", str(value)) for key, value in pairs])
    # The signature name avoids secret words: receipt redaction masks ``password_*`` labels.
    return _sig("configuration_secret_file", "htpasswd_hash_lines", secrets, pairs=pairs)


# --- YAML configuration ----------------------------------------------------------------------
# Block-mapping YAML as configuration files are written: ``key:`` opens a section, ``key: value``
# sets a scalar, ``- item`` lists. Only read from a body named or typed as YAML, and only when
# those lines make up the document, so prose with colons in it is not configuration.
_YAML_NAME_RE = re.compile(r"(?i)\.ya?ml$")
_YAML_MAPPING_RE = re.compile(
    r"( {0,64})([A-Za-z_][A-Za-z0-9_.\-]{0,127})[ \t]*:(?:[ \t]+([^\r\n]{0,2048}))?"
)
_YAML_LIST_RE = re.compile(r" {0,64}-(?:[ \t][^\r\n]{0,2048})?")
_YAML_QUOTED_RE = re.compile(r"\"((?:[^\"\\]|\\.){0,1024})\"|'((?:[^']|''){0,1024})'")


def _yaml_scalar(raw: str) -> str | None:
    """The plain or quoted scalar a YAML value holds; None for a block, flow, anchor or alias."""
    value = raw.strip()
    if not value or value[0] in "|>{[&*!":
        return None
    quoted = _YAML_QUOTED_RE.match(value)
    if quoted is not None:
        return quoted.group(1) if quoted.group(1) is not None else quoted.group(2).replace("''", "'")
    comment = value.find(" #")
    return (value[:comment] if comment >= 0 else value).strip() or None


def _yaml_pairs(text: str) -> list[tuple[str, object]] | None:
    """``(dotted.key, scalar)`` of a block-mapping YAML document, or None when it is not one."""
    meaningful = structural = 0
    stack: list[tuple[int, str]] = []
    pairs: list[tuple[str, object]] = []
    for line in text[:_PARSE_MAX_CHARS].splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped in {"---", "..."}:
            continue
        meaningful += 1
        line = line.rstrip()
        match = _YAML_MAPPING_RE.fullmatch(line)
        if match is None:
            structural += 1 if _YAML_LIST_RE.fullmatch(line) else 0
            continue
        structural += 1
        indent, key = len(match.group(1)), match.group(2)
        while stack and stack[-1][0] >= indent:
            stack.pop()
        scalar = _yaml_scalar(match.group(3) or "")
        if scalar is None:
            if len(stack) < 16:
                stack.append((indent, key))
        elif len(pairs) < _MAX_DOCUMENT_PAIRS:
            pairs.append((".".join([name for _indent, name in stack] + [key]), scalar))
    if structural < 2 or structural * 5 < meaningful * 4:
        return None
    return pairs


def _yaml_configuration(path: str, text: str, content_type: str) -> ExposureSignature | None:
    if "yaml" not in content_type and not _YAML_NAME_RE.search(_last_segment(path)):
        return None
    pairs = _yaml_pairs(text)
    # An API description in YAML describes parameters, it does not configure a server; its
    # example values are documentation (the JSON form is read by ``_openapi_secrets``).
    if not pairs or any(key in {"openapi", "swagger"} for key, _value in pairs):
        return None
    pairs = [
        (key, value) for key, value in pairs
        if not _EXAMPLE_KEYS.intersection(segment.lower() for segment in key.split("."))
    ]
    secrets = _secrets(text, pairs, server_side=True)
    if secrets:
        return _sig("configuration_secret_file", "yaml_configuration_secret", secrets, pairs=pairs)
    if redactable_assignments(pairs)[0]:
        # Secret-named keys whose values prove no secret: an observation, its body withheld.
        return _sig("configuration_file", "yaml_configuration", pairs=pairs)
    return None


# --- Server status pages ---------------------------------------------------------------------
# Apache mod_status (HTML and its ``?auto`` text form) and nginx stub_status, each by its own fixed
# output: a page that only mentions server-status has neither the heading with its fields nor the
# counters in this order.
_APACHE_STATUS_RE = re.compile(r"Apache Server Status for ")
_APACHE_STATUS_FIELD_RE = re.compile(r"Server (?:Version|MPM|Built|uptime):")
_APACHE_STATUS_AUTO_RE = re.compile(r"(?m)^Scoreboard: [_SRWKDCLGI.]{1,4096}[ \t]*\r?$")
_APACHE_STATUS_WORKERS_RE = re.compile(r"(?m)^(?:BusyWorkers|IdleWorkers): \d{1,9}[ \t]*\r?$")
_NGINX_STATUS_RE = re.compile(r"(?m)^Active connections:[ \t]*\d{1,12}[ \t]*\r?$")
_NGINX_STATUS_COUNTERS_RE = re.compile(
    r"(?m)^server accepts handled requests[ \t]*\r?\n[ \t]*\d{1,20}[ \t]+\d{1,20}[ \t]+\d{1,20}"
)


def _server_status(text: str) -> ExposureSignature | None:
    head = text[:_PARSE_MAX_CHARS]
    if _APACHE_STATUS_RE.search(head) and _APACHE_STATUS_FIELD_RE.search(head):
        return _sig("metrics_endpoint", _APACHE_STATUS_RE.pattern)
    if _APACHE_STATUS_AUTO_RE.search(head) and _APACHE_STATUS_WORKERS_RE.search(head):
        return _sig("metrics_endpoint", _APACHE_STATUS_AUTO_RE.pattern)
    if _NGINX_STATUS_RE.search(head) and _NGINX_STATUS_COUNTERS_RE.search(head):
        return _sig("metrics_endpoint", _NGINX_STATUS_RE.pattern)
    return None


def _structured_text(path: str, text: str, content_type: str = "") -> ExposureSignature | None:
    """Proofs for non-HTML bodies whose own grammar identifies the file type."""
    credential_store = _credential_store(path, text)
    if credential_store is not None:
        return credential_store
    password_file = _password_hash_file(path, text)
    if password_file is not None:
        return password_file
    if _GIT_CORE_HEADER_RE.search(text) and _GIT_CORE_KEY_RE.search(text):
        return _sig("version_control_exposure", "git_config_core_section",
                    _dedupe(selfevident_secret_evidence(text)))
    if _GIT_HEAD_RE.match(text):
        return _sig("version_control_exposure", "git_head_ref")
    markdown = _markdown_env_blocks(path, content_type, text)
    if markdown is not None:
        return markdown
    document = _json_document(text)
    if document is not None:
        return _json_signature(path, text, document)
    yaml_config = _yaml_configuration(path, text, content_type)
    if yaml_config is not None:
        return yaml_config
    dotenv = _dotenv_pairs(text)
    if dotenv is not None:
        pairs: list[tuple[str, object]] = list(dotenv)
        secrets = _secrets(text, pairs, server_side=True)
        if secrets:
            return _sig("environment_secret_file", "dotenv_secret_assignment", secrets,
                        pairs=pairs)
        return _sig("configuration_file", "dotenv_assignments", pairs=pairs)
    web_config = _web_config(path, text)
    if web_config is not None:
        return web_config
    if _SQL_DUMP_HEADER_RE.search(text) or (
        _SQL_CREATE_RE.search(text) and _SQL_INSERT_RE.search(text)
    ):
        return _sig("backup_or_source_artifact", "sql_dump",
                    _dedupe(selfevident_secret_evidence(text)))
    return None


def _structured_html(text: str, path: str = "") -> ExposureSignature | None:
    """Proofs for server-generated diagnostic pages, which are HTML by nature."""
    if _PHPINFO_TITLE_RE.search(text) and _PHPINFO_VERSION_RE.search(text):
        rows: list[tuple[str, object]] = [
            (key.strip(), value.strip())
            for key, value in _HTML_ROW_RE.findall(text[:_PARSE_MAX_CHARS])
        ][:_MAX_DOCUMENT_PAIRS]
        return _sig("phpinfo_disclosure", "phpinfo_page", _secrets(text, rows, server_side=True),
                    pairs=rows)
    if _WERKZEUG_CONSOLE_RE.search(text) and _WERKZEUG_MARKER_RE.search(text):
        # An interactive debugger console executes code once its PIN is known.
        return _sig("debug_interface_exposure", "werkzeug_debugger_console", severity="high")
    if _PPROF_RE.search(text):
        return _sig("debug_interface_exposure", "go_pprof_index")
    # Only at an IDE location: a documentation page showing the same setup code is not an IDE.
    ide = graphql_ide_page(text) if graphql_ide_location(path) else None
    if ide is not None:
        return _sig("graphql_ide_exposure", "(?i)graphiql|graphqlplayground")
    return _html_comment_secret(text)


# --- Source and document grammars --------------------------------------------------------------
# A PHP file that reaches the client starting with its own open tag was served as source, not
# executed: an interpreter never emits ``<?php``. The statement check keeps a text file that
# merely starts with the tag (a one-line note) from counting as source.
_PHP_OPEN_RE = re.compile(r"^﻿?[ \t\r\n]{0,64}<\?php\b")
_PHP_STATEMENT_RE = re.compile(
    r"(?m)^[ \t]*(?:\$[A-Za-z_]\w{0,63}[ \t]*(?:\[[^\]\r\n]{1,128}\][ \t]*){0,4}=[^=]"
    r"|define[ \t]*\(|(?:require|include)(?:_once)?\b|(?:abstract[ \t]+|final[ \t]+)?class[ \t]+\w"
    r"|function[ \t]+\w|namespace[ \t]+\w|use[ \t]+[A-Z\\]|if[ \t]*\(|echo\b|return\b)"
)
# ``$name = ...;`` / ``$_CONF['db_password'] = ...;`` and ``define('DB_PASSWORD', ...);`` --
# every repetition bounded and each statement read on one line, so the scan is linear.
_PHP_ASSIGN_RE = re.compile(
    r"(?m)^[ \t]*\$([A-Za-z_]\w{0,63})((?:[ \t]*\[[ \t]*['\"][^'\"\r\n]{1,128}['\"][ \t]*\]){0,4})"
    r"[ \t]*=[ \t]*([^;\r\n]{1,1024});"
)
_PHP_DEFINE_RE = re.compile(
    r"(?im)^[ \t]*define[ \t]*\([ \t]*['\"]([A-Za-z_][\w.\-]{0,127})['\"][ \t]*,[ \t]*([^;\r\n]{1,1024})\)[ \t]*;"
)
_PHP_LAST_KEY_RE = re.compile(r"\[[ \t]*['\"]([^'\"\r\n]{1,128})['\"][ \t]*\][ \t]*$")
_PHP_LITERAL_RE = re.compile(r"^'((?:[^'\\\r\n]|\\.){0,512})'$|^\"((?:[^\"\\\r\n$]|\\.){0,512})\"$")
# A literal default after ``?:`` / ``??`` is the value used whenever the environment is unset.
_PHP_DEFAULT_RE = re.compile(r"(?:\?:|\?\?)[ \t]*('(?:[^'\\\r\n]|\\.){0,512}'|\"(?:[^\"\\\r\n$]|\\.){0,512}\")[ \t]*\)?$")


def _php_literal(expression: str) -> str | None:
    """The string a PHP right-hand side evaluates to when it is a literal or a literal default."""
    expression = expression.strip()
    match = _PHP_LITERAL_RE.match(expression)
    if match is None:
        default = _PHP_DEFAULT_RE.search(expression)
        match = _PHP_LITERAL_RE.match(default.group(1)) if default else None
    if match is None:
        return None
    return match.group(1) if match.group(1) is not None else match.group(2)


def _php_source(text: str) -> ExposureSignature | None:
    """PHP source served instead of executed, with its literal configuration assignments."""
    if not _PHP_OPEN_RE.match(text[:256]) or not _PHP_STATEMENT_RE.search(text[:_PARSE_MAX_CHARS]):
        return None
    body = text[:_PARSE_MAX_CHARS]
    pairs: list[tuple[str, object]] = []
    for match in _PHP_ASSIGN_RE.finditer(body):
        last_key = _PHP_LAST_KEY_RE.search(match.group(2) or "")
        value = _php_literal(match.group(3))
        if value is not None:
            pairs.append((last_key.group(1) if last_key else match.group(1), value))
        if len(pairs) >= _MAX_DOCUMENT_PAIRS:
            break
    for match in _PHP_DEFINE_RE.finditer(body):
        value = _php_literal(match.group(2))
        if value is not None:
            pairs.append((match.group(1), value))
        if len(pairs) >= _MAX_DOCUMENT_PAIRS:
            break
    secrets = _secrets(text, pairs, server_side=True)
    if secrets:
        return _sig("configuration_secret_file", "php_configuration_secret", secrets, pairs=pairs)
    return _sig("backup_or_source_artifact", "php_source_served",
                _dedupe(selfevident_secret_evidence(body)), pairs=pairs)


# A fenced code block in a Markdown document (CommonMark ``` or ~~~ fences).
_MARKDOWN_FENCE_RE = re.compile(r"^[ \t]{0,3}(`{3,}|~{3,})")
# ``NAME=value`` / ``export NAME="value"``: an environment name in the conventional upper case.
_ENV_ASSIGNMENT_RE = re.compile(r"[ \t]*(?:export[ \t]+)?([A-Z][A-Z0-9_]{1,127})[ \t]*=[ \t]*(\S.{0,1023})")
_MARKDOWN_NAME_RE = re.compile(r"(?i)\.(?:md|markdown|mdx)$")


def _markdown_env_blocks(path: str, headers_type: str, text: str) -> ExposureSignature | None:
    """Environment assignments inside the fenced code blocks of a served Markdown document.

    Prose never counts: only lines inside a fence, in the ``NAME=value`` grammar a shell or a
    dotenv file reads, and only values that pass the shared screen. A README showing
    ``API_TOKEN=<your-token>`` proves nothing; a runbook that inlines the real token does.
    """
    if "markdown" not in headers_type and not _MARKDOWN_NAME_RE.search(_last_segment(path)):
        return None
    pairs: list[tuple[str, object]] = []
    fence = ""
    for line in text[:_PARSE_MAX_CHARS].splitlines():
        marker = _MARKDOWN_FENCE_RE.match(line)
        if marker:
            token = marker.group(1)
            if not fence:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = ""
            continue
        if not fence:
            continue
        match = _ENV_ASSIGNMENT_RE.fullmatch(line.rstrip())
        if match:
            pairs.append((match.group(1), match.group(2).strip().strip("\"'")))
            if len(pairs) >= _MAX_DOCUMENT_PAIRS:
                break
    if not pairs:
        return None
    secrets = _dedupe(structured_secret_assignments(pairs, server_side=True))
    if not secrets:
        return None
    return _sig("environment_secret_file", "markdown_env_block_secret", secrets, pairs=pairs)


# A credential a developer left in an HTML comment: ``<!-- db_password = ... -->``. Comments are
# read one by one (bounded count and length) and only a secret-named key with a screened value
# counts, so a comment that talks about passwords proves nothing.
_HTML_COMMENT_OPEN = "<!--"
_HTML_COMMENT_CLOSE = "-->"
_MAX_HTML_COMMENTS = 500
_MAX_HTML_COMMENT_CHARS = 2_000
_COMMENT_ASSIGNMENT_RE = re.compile(
    r"(?<![A-Za-z0-9_.\-])([A-Za-z][A-Za-z0-9_.\-]{0,80})[ \t]*[:=][ \t]*(\S[^\r\n]{0,511})"
)


def _html_comment_pairs(text: str) -> list[tuple[str, object]]:
    pairs: list[tuple[str, object]] = []
    position = 0
    body = text[:_PARSE_MAX_CHARS]
    for _ in range(_MAX_HTML_COMMENTS):
        start = body.find(_HTML_COMMENT_OPEN, position)
        if start < 0:
            break
        end = body.find(_HTML_COMMENT_CLOSE, start + 4)
        if end < 0:
            break
        position = end + 3
        comment = body[start + 4:end]
        if len(comment) > _MAX_HTML_COMMENT_CHARS or comment.lstrip().startswith(("[if", "<![endif")):
            continue
        for line in comment.splitlines():
            for match in _COMMENT_ASSIGNMENT_RE.finditer(line):
                value = match.group(2).strip().rstrip("-").strip().strip("\"'")
                pairs.append((match.group(1), value))
    return pairs[:_MAX_DOCUMENT_PAIRS]


def _html_comment_secret(text: str) -> ExposureSignature | None:
    if _HTML_COMMENT_OPEN not in text:
        return None
    pairs = _html_comment_pairs(text)
    if not pairs:
        return None
    secrets = _dedupe(structured_secret_assignments(pairs, server_side=False))
    if not secrets:
        return None
    return _sig("html_comment_secret", "html_comment_credential", secrets, pairs=pairs)


# Records that pair an account identity with its password, served to an anonymous reader. The
# record shape is the proof: several objects in one list, each naming an account and carrying a
# plaintext password value. Hashes are left to the self-evident ``password_hash`` contract.
_IDENTITY_KEYS = frozenset({"username", "user_name", "login", "email", "email_address", "user", "account"})
_PASSWORD_KEYS = frozenset({"password", "passwd", "pwd", "pass", "user_password", "plain_password",
                            "plaintext_password", "cleartext_password"})
_HASH_SHAPE_RE = re.compile(r"^(?:\$[0-9a-z]{1,8}\$\S{8,}|[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{128}|\{[A-Z0-9-]{2,16}\}\S{8,}|pbkdf2[_:$]\S{8,}|scrypt[:$]\S{8,})$", re.IGNORECASE)
_MIN_CREDENTIAL_RECORDS = 2


def _credential_records(document: Any) -> list[tuple[str, object]]:
    """``(field, plaintext password)`` of each account record in the first list that has two."""
    found: list[tuple[str, object]] = []

    def plaintext(value: object) -> str | None:
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            return None
        text = str(value).strip()
        if (not text or len(text) > 256 or is_masked_or_indirect_value(text)
                or _HASH_SHAPE_RE.match(text) or text.lower() in {"null", "none", "n/a", "-"}):
            return None
        return text

    def records(items: list[Any], name: str) -> list[tuple[str, object]]:
        out: list[tuple[str, object]] = []
        identities: set[str] = set()
        for index, item in enumerate(items[:2_000]):
            if not isinstance(item, Mapping):
                continue
            keys = {normalized_key_name(str(key)): value for key, value in list(item.items())[:200]}
            if not any(key in _IDENTITY_KEYS and isinstance(keys[key], str) and keys[key].strip()
                       for key in keys):
                continue
            identity = next((keys[key].strip().casefold() for key in
                ('email', 'email_address', 'username', 'user_name', 'login', 'user', 'account')
                if isinstance(keys.get(key), str) and keys[key].strip()), '')
            if identity in identities:
                continue
            for key, value in keys.items():
                if key in _PASSWORD_KEYS and (secret := plaintext(value)) is not None:
                    out.append((f"{name}[{index}].{key}", secret))
                    identities.add(identity)
                    break
        return out

    def walk(value: Any, name: str, depth: int) -> None:
        if found or depth > 4:
            return
        if isinstance(value, list):
            hits = records(value, name)
            if len(hits) >= _MIN_CREDENTIAL_RECORDS:
                found.extend(hits[:_MAX_DOCUMENT_PAIRS])
                return
            for index, item in enumerate(value[:50]):
                walk(item, f"{name}[{index}]", depth + 1)
        elif isinstance(value, Mapping):
            # OpenAPI/JSON Schema example records describe a schema, not account data.
            if any(key in value for key in ('openapi', 'swagger', '$schema')):
                return
            for key, item in list(value.items())[:200]:
                if str(key).lower() in _EXAMPLE_KEYS | {'schemas', 'definitions'}:
                    continue
                walk(item, f"{name}.{key}" if name else str(key), depth + 1)

    walk(document, "", 0)
    return found


def _credential_record_signature(document: Any) -> ExposureSignature | None:
    pairs = _credential_records(document)
    if not pairs:
        return None
    secrets = _dedupe([
        secret_evidence(str(field_name), "plaintext_password_record", str(value))
        for field_name, value in pairs
    ])
    return _sig("credential_record_disclosure", "account_records_with_plaintext_passwords",
                secrets, pairs=[(f"{name}.password", value) for name, value in pairs])


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


def _is_metrics_exposition(text: str) -> bool:
    help_line = _METRICS_HELP_RE.search(text)
    return help_line is not None and _METRICS_TYPE_RE.search(text, help_line.end()) is not None


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
    A 5xx response is examined only for a structured runtime stack trace, under
    its own versioned contract; its status alone is never an exposure.
    """
    if not body:
        return None
    if status != 200:
        if type(status) is int and 500 <= status <= 599 and runtime_error_disclosed(_decode(body), _content_type(headers)):
            return _sig("verbose_error_disclosure", "http_error_stack_trace")
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

    # Source served instead of executed, whatever content type the server guessed for it.
    php = _php_source(text)
    if php is not None:
        return php
    # A server status page is HTML (Apache) or plain text (Apache ?auto, nginx): read both.
    status_page = _server_status(text)
    if status_page is not None:
        return status_page
    structured = (
        _structured_html(text, path) if is_html else _structured_text(path, text, content_type)
    )
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
    if not is_html and _is_metrics_exposition(text):
        return _sig("metrics_endpoint", _METRICS_HELP_RE.pattern)
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
    "html_comment_secret",
    "credential_record_disclosure",
})
_SECRET_MATERIAL_CLASSES = SECRET_MATERIAL_CLASSES

# Classes that promote to a finding: exactly those with a deterministic proof contract.
_PROMOTABLE_EXPOSURE_CLASSES = frozenset(EXPOSURE_PROOF_CONTRACTS)


# Configuration documents: their body is withheld whether or not a secret in it was proven,
# because the entropy screen decides proof, never whether a value may be shown.
_CONFIG_DOCUMENT_PATTERNS = frozenset({
    "dotenv_secret_assignment", "dotenv_assignments", "aspnet_web_config",
    "aspnet_web_config_backup", "actuator_property_sources", "json_configuration_secret",
    "sql_dump", "git_credentials_store", "netrc_credentials", "npmrc_auth_token",
    "pypirc_credentials", "php_configuration_secret", "php_source_served",
    "markdown_env_block_secret", "htpasswd_hash_lines", "yaml_configuration_secret",
    "yaml_configuration",
    # Diagnostic messages can echo unrecognized credential values; keep metadata only.
    "http_error_stack_trace",
})
# A known value shorter than this is too common to scrub or to test an excerpt for.
_MIN_SCRUBBED_VALUE_LENGTH = 4


def _withheld_notice(signature: ExposureSignature) -> str:
    notice = (
        f"[{signature.exposure_class} detected - content withheld; "
        f"{len(signature.secrets)} secret value(s) fingerprinted"
    )
    keys = list(dict.fromkeys(
        [item.key for item in signature.secrets] + list(signature.withheld_keys)
    ))
    if keys:
        shown = ", ".join(keys[:20]) + (f" (+{len(keys) - 20} more)" if len(keys) > 20 else "")
        notice += f"; secret-named keys: {shown}"
    return notice + "]"


def redacted_exposure_excerpt(body: bytes, signature: ExposureSignature) -> str:
    """Return a short, secret-redacted evidence excerpt around the match.

    The body of a secret-material class, of a configuration document (dotenv/properties,
    web.config, actuator property sources, JSON configuration, SQL dump), or of anything in
    which a secret was proven or a secret-named key carries a value is not excerpted at all:
    only the fact of disclosure, the key names and the fingerprints are recorded. That holds
    whatever the values' entropy -- ``DB_PASS=Winter2023!`` proves nothing but is never shown.
    Other excerpts pass through the shared redactor with every value this body is known to
    hold, then every secret-named assignment is masked; an excerpt that still contains a
    known value is withheld instead.
    """
    if signature.exposure_class == "listed_file":
        return "[File reachable; sensitivity not established; content withheld]"
    if signature.withholds_content:
        return _withheld_notice(signature)
    if body.startswith((_DS_STORE_MAGIC, *_ARCHIVE_MAGIC)):
        return f"[{signature.exposure_class} detected - binary content withheld]"
    full = _decode(body)
    text = full
    try:
        compiled = re.compile(signature.matched_pattern)
    except re.error:
        compiled = None
    found = compiled.search(text) if compiled is not None else None
    if found is not None:
        start = max(0, found.start() - 40)
        text = text[start:found.end() + 160]
    sample = " ".join(text.split())[:400]
    known = [item.value for item in selfevident_secret_evidence(full) if item.value]
    known.extend(text_assignment_values(full[:_PARSE_MAX_CHARS]))
    known = [value for value in known if len(value) >= _MIN_SCRUBBED_VALUE_LENGTH]
    sample = _shared_redact_text(sample, known_values=known)
    sample = redact_text_assignments(sample)
    sample = _SECRET_REDACT_RE.sub(lambda item: f"{item.group(1)}=[REDACTED]", sample)
    if any(value in sample for value in known):
        return _withheld_notice(signature)
    return sample


__all__ = [
    "DIRECTORY_FOLLOW_UP_FLOOR",
    "EXPOSURE_PROBE_MIN_START_SECONDS",
    "EXPOSURE_PROBE_TIMEOUT_CEILING_SECONDS",
    "EXPOSURE_PROBE_TIMEOUT_FLOOR_SECONDS",
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
    "exposure_probe_timeout",
    "is_never_requested",
    "is_sensitive_exposure_class",
    "redacted_exposure_excerpt",
]
