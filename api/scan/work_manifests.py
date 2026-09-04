"""Canonical, content-addressed work manifests shared by every Scan backend."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import heapq
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence
import urllib.parse
import uuid

try:
    from scanner_tools.url_redaction import redact_path
except ModuleNotFoundError:  # package import through api.scan
    from scanner.scanner_tools.url_redaction import redact_path


SCAN_WORK_MANIFEST_SCHEMA = "scan-work-manifest/v1"
SCAN_WORK_MANIFEST_REFERENCE_SCHEMA = "scan-work-manifest-reference/v1"
WORK_MANIFEST_CONTENT_SCHEMAS = MappingProxyType({
    "endpoint": "endpoint-manifest/v2",
    "candidate": "candidate-manifest/v1",
    "request_candidate": "request-candidate-manifest/v2",
    "request": "request-manifest/v2",
    "template": "template-manifest/v1",
})
CANONICAL_NUCLEI_TEMPLATE_BUNDLE_COMMIT = (
    "2935d63aebd1f5f4a3c8e87c6e7f5c47f689b115"
)
CANONICAL_NUCLEI_TEMPLATE_BUNDLE_SHA256 = (
    "20aff7085b5c1771a8f7a28624009359a1cedab924c9ad7836078ca07e28de39"
)
CANONICAL_NUCLEI_TEMPLATE_PACK_ID = "nuclei-safe-active-focused-v1"
CANONICAL_NUCLEI_TEMPLATE_SEVERITIES = ("high", "critical")
CANONICAL_NUCLEI_TEMPLATE_TAGS = (
    "exposure", "misconfig", "auth-bypass", "default-login",
)
CANONICAL_PASSIVE_NUCLEI_TEMPLATE_PACK_ID = "nuclei-passive-read-only-v1"
# Exact files reviewed from the pinned bundle above.  Every row is
# (template id, file sha256, maximum requests, severity, tags).  These
# templates contain HTTP GET requests only and no raw requests, payload
# expansion, scripting, mutation, or OOB interaction.
CANONICAL_PASSIVE_NUCLEI_TEMPLATES = (
    (
        "git-config",
        "bd8bdfa0b5ed5bf4d3712edb793adfd0987d9282e51c6f7d673bf14b9e4dd524",
        1,
        "medium",
        ("config", "git", "exposure", "vuln"),
    ),
    (
        "git-credentials-disclosure",
        "cd11b069ef6cddca723a38d44b932b9042d5f22a34a5d1bd8bb2423e9b85a9a4",
        1,
        "medium",
        ("exposure", "config", "vuln"),
    ),
    (
        "http-missing-security-headers",
        "7f45803f73ac6810b9b302df6be2c472a82d9164a7807328614efa83e6eac275",
        1,
        "info",
        ("misconfig", "headers", "generic"),
    ),
    (
        "openapi",
        "1a5541ec8f60d5a5fe56cc15a20b95e7609ebec177ec0ac910b99df8d114981b",
        1,
        "info",
        ("exposure", "api", "discovery"),
    ),
    (
        "server-status",
        "540d4cc923eb76f1291b5f2e33a4aabda9c2c1f44ad2c58576bcbd4cfe755950",
        1,
        "info",
        ("apache", "status", "exposure"),
    ),
    (
        "web-config",
        "5c1080c77d065d3eb5eeffeaad9ada85c619a15011f2da6c8f00c787aa7316b0",
        2,
        "info",
        ("config", "exposure"),
    ),
)
_MAX_ENTRIES = MappingProxyType({
    "endpoint": 100_000,
    "candidate": 20_000,
    "request_candidate": 2_000,
    "request": 2_000,
    "template": 20_000,
})
_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+:/{}-]{0,255}$")
_METHOD_RE = re.compile(r"^[A-Z]{3,12}$")
_SENSITIVE_KEYS = frozenset({
    "authorization", "cookie", "password", "secret", "token", "api_key",
    "private_key", "credential", "header_value", "body_value", "query_value",
})
REQUEST_CLASSES = frozenset({
    "safe_read", "safe_authentication", "confirmed_mutation", "forbidden",
})
# A manifest ENTRY carries request_class; the raw collection index row it was
# built from carries safe_method, which is popped during translation. Anything
# counting mutating work off an entry must use this, not the input field.
MUTATING_REQUEST_CLASSES = frozenset({"confirmed_mutation"})


def entry_is_mutating(entry: Mapping[str, Any]) -> bool:
    """True when a request manifest entry represents state-changing work."""
    return str(entry.get("request_class") or "") in MUTATING_REQUEST_CLASSES


class ScanWorkManifestError(ValueError):
    """A work manifest is unsafe, unbounded, or detached from Scan authority."""


class ScanWorkManifestKind(str, Enum):
    ENDPOINT = "endpoint"
    CANDIDATE = "candidate"
    REQUEST_CANDIDATE = "request_candidate"
    REQUEST = "request"
    TEMPLATE = "template"


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")).hexdigest()


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _hex(value: Any, *, name: str) -> str:
    normalized = str(value or "").strip().lower()
    if not _HEX_64_RE.fullmatch(normalized):
        raise ScanWorkManifestError(f"{name} must be a SHA-256 digest")
    return normalized


def _token(value: Any, *, name: str, optional: bool = False) -> str | None:
    normalized = str(value or "").strip()
    if optional and not normalized:
        return None
    if not _TOKEN_RE.fullmatch(normalized):
        raise ScanWorkManifestError(f"{name} is invalid")
    return normalized


def _uuid(value: Any, *, name: str) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ScanWorkManifestError(f"{name} must be a UUID") from exc


def _path(value: Any) -> str:
    path = str(value or "").strip()
    if not path.startswith("/") or "?" in path or "#" in path or len(path) > 4_096:
        raise ScanWorkManifestError("canonical_path must be a bounded path without query values")
    redacted = redact_path(path)
    if redacted != path:
        raise ScanWorkManifestError("canonical_path must not retain sensitive path material")
    return path


def _client_route_path(value: Any) -> str:
    path = str(value or "").strip()
    route_path = path[1:] if path.startswith("!/") else path
    if (
        not route_path.startswith("/") or route_path.startswith("//")
        or "?" in path or "#" in path or "\\" in path or len(path) > 2_000
        or any(ord(char) < 0x20 or ord(char) == 0x7f for char in path)
        or redact_path(route_path) != route_path
    ):
        raise ScanWorkManifestError(
            "browser_fragment_path must be a bounded value-free SPA route"
        )
    return path


def _string_list(value: Any, *, name: str, maximum: int) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > maximum:
        raise ScanWorkManifestError(f"{name} must be a bounded list")
    normalized = tuple(
        str(_token(item, name=f"{name} entry")) for item in value
    )
    if len(set(normalized)) != len(normalized):
        raise ScanWorkManifestError(f"{name} contains duplicates")
    return normalized


def _body_field_list(value: Any, *, name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > 128:
        raise ScanWorkManifestError(f"{name} must be a bounded list")
    rows: list[str] = []
    for item in value:
        field = str(item or "").strip()
        if (
            not field or len(field) > 300
            or any(ord(char) < 0x20 or ord(char) == 0x7f for char in field)
        ):
            raise ScanWorkManifestError(f"{name} contains an invalid field path")
        if field not in rows:
            rows.append(field)
    return tuple(rows)


def _integer(value: Any, *, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ScanWorkManifestError(f"{name} is outside its allowed range")
    return value


def _optional_integer(value: Any, *, name: str, minimum: int, maximum: int) -> int | None:
    if value is None:
        return None
    return _integer(value, name=name, minimum=minimum, maximum=maximum)


def _reject_sensitive_keys(value: Any, *, depth: int = 0) -> None:
    if depth > 8:
        raise ScanWorkManifestError("manifest entry nesting is too deep")
    if isinstance(value, Mapping):
        for raw_key, item in value.items():
            key = str(raw_key or "").strip().lower()
            if key in _SENSITIVE_KEYS or any(
                marker in key for marker in ("password", "secret", "private_key")
            ):
                raise ScanWorkManifestError("manifest entries cannot contain secret values")
            _reject_sensitive_keys(item, depth=depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_sensitive_keys(item, depth=depth + 1)


def route_id(
    *,
    target_binding_digest: str,
    method: str,
    scheme: str,
    host: str,
    port: int,
    canonical_path: str,
    query_parameter_names: Sequence[str],
    browser_fragment_path: str | None = None,
    browser_fragment_query_parameter_names: Sequence[str] = (),
) -> str:
    """Derive one stable, value-free route identity."""
    identity = {
        "target_binding_digest": _hex(
            target_binding_digest, name="target_binding_digest",
        ),
        "method": str(method or "").strip().upper(),
        "scheme": str(scheme or "").strip().lower(),
        "host": str(host or "").strip().lower().rstrip("."),
        "port": int(port),
        "canonical_path": _path(canonical_path),
        "query_parameter_names": sorted(str(item) for item in query_parameter_names),
    }
    fragment_names = sorted(
        str(item) for item in browser_fragment_query_parameter_names
    )
    if browser_fragment_path:
        identity.update({
            "browser_fragment_path": _client_route_path(browser_fragment_path),
            "browser_fragment_query_parameter_names": fragment_names,
        })
    elif fragment_names:
        raise ScanWorkManifestError(
            "browser fragment parameters require a browser fragment path"
        )
    return _digest(identity)


def _endpoint_entry(value: Mapping[str, Any], *, target_digest: str) -> dict[str, Any]:
    expected = {
        "route_id", "method", "scheme", "host", "port", "canonical_path",
        "query_parameter_names", "source_tool", "discovery_depth", "auth_lane",
        "selected_shard", "request_ref_ids",
    }
    # The declared request-body shape is optional so manifests written before endpoints carried it
    # still validate on read. An endpoint that declares a body needs its field NAMES recorded, not
    # only the content fingerprint: the fingerprint distinguishes two shapes but tells a later
    # stage nothing about what to test, which is why no body-bearing endpoint could become a
    # candidate. Values never appear here, only names.
    optional = {
        "content_type", "body_field_names", "browser_fragment_path",
        "browser_fragment_query_parameter_names",
    }
    keys = set(value)
    if not expected <= keys or not keys <= (expected | optional):
        raise ScanWorkManifestError("endpoint manifest entry fields are invalid")
    method = str(value["method"] or "").strip().upper()
    scheme = str(value["scheme"] or "").strip().lower()
    host = str(value["host"] or "").strip().lower().rstrip(".")
    if not _METHOD_RE.fullmatch(method) or scheme not in {"http", "https"} or not host:
        raise ScanWorkManifestError("endpoint protocol identity is invalid")
    port = _integer(value["port"], name="port", minimum=1, maximum=65_535)
    canonical_path = _path(value["canonical_path"])
    query_names = _string_list(
        value["query_parameter_names"], name="query_parameter_names", maximum=64,
    )
    fragment_path = (
        _client_route_path(value["browser_fragment_path"])
        if value.get("browser_fragment_path") else None
    )
    fragment_names = _string_list(
        value.get("browser_fragment_query_parameter_names") or [],
        name="browser_fragment_query_parameter_names", maximum=64,
    )
    if fragment_names and fragment_path is None:
        raise ScanWorkManifestError(
            "browser fragment parameters require a browser fragment path"
        )
    expected_route = route_id(
        target_binding_digest=target_digest,
        method=method,
        scheme=scheme,
        host=host,
        port=port,
        canonical_path=canonical_path,
        query_parameter_names=query_names,
        browser_fragment_path=fragment_path,
        browser_fragment_query_parameter_names=fragment_names,
    )
    if _hex(value["route_id"], name="route_id") != expected_route:
        raise ScanWorkManifestError("route_id does not match endpoint identity")
    lane = _token(value["auth_lane"], name="auth_lane", optional=True)
    if lane not in {None, "primary", "secondary", "service", "anonymous"}:
        raise ScanWorkManifestError("endpoint auth_lane is invalid")
    result = {
        "route_id": expected_route,
        "method": method,
        "scheme": scheme,
        "host": host,
        "port": port,
        "canonical_path": canonical_path,
        "query_parameter_names": list(query_names),
        "source_tool": _token(value["source_tool"], name="source_tool"),
        "discovery_depth": _integer(
            value["discovery_depth"], name="discovery_depth", minimum=0, maximum=64,
        ),
        "auth_lane": lane,
        "selected_shard": _optional_integer(
            value["selected_shard"], name="selected_shard", minimum=0, maximum=16_383,
        ),
        "request_ref_ids": list(_string_list(
            value["request_ref_ids"], name="request_ref_ids", maximum=64,
        )),
        "content_type": _token(
            value.get("content_type"), name="content_type", optional=True,
        ),
        "body_field_names": list(_string_list(
            value.get("body_field_names") or [], name="body_field_names", maximum=128,
        )),
    }
    if fragment_path:
        result.update({
            "browser_fragment_path": fragment_path,
            "browser_fragment_query_parameter_names": list(fragment_names),
        })
    return result


def _candidate_entry(value: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "candidate_id", "route_id", "method", "canonical_path", "parameter_name",
        "query_parameter_names", "body_field_names", "content_type",
        "family_hints", "source_tool", "source_observation_ref", "auth_lane",
        "selected_shard", "request_ref_id", "score", "ranking_rationale",
    }
    optional = {
        "browser_fragment_path", "browser_fragment_query_parameter_names",
        "parameter_location", "path_segment_index",
    }
    if not expected <= set(value) or not set(value) <= (expected | optional):
        raise ScanWorkManifestError("candidate manifest entry fields are invalid")
    method = str(value["method"] or "").strip().upper()
    if not _METHOD_RE.fullmatch(method):
        raise ScanWorkManifestError("candidate method is invalid")
    route = _hex(value["route_id"], name="route_id")
    parameter = str(_token(value["parameter_name"], name="parameter_name"))
    query_names = _string_list(
        value["query_parameter_names"],
        name="query_parameter_names",
        maximum=64,
    )
    body_names = _string_list(
        value["body_field_names"], name="body_field_names", maximum=128,
    )
    fragment_path = (
        _client_route_path(value["browser_fragment_path"])
        if value.get("browser_fragment_path") else None
    )
    fragment_names = _string_list(
        value.get("browser_fragment_query_parameter_names") or [],
        name="browser_fragment_query_parameter_names", maximum=64,
    )
    # A candidate names exactly one injection point, and it must exist where the entry says it is.
    # body_field_names being non-empty is what marks the candidate as testing a request body.
    in_body = bool(body_names)
    in_fragment = bool(fragment_names)
    in_path = value.get("parameter_location") == "path"
    if fragment_path is not None and not in_fragment:
        raise ScanWorkManifestError(
            "fragment candidate requires browser fragment parameters"
        )
    if sum((in_body, in_fragment, in_path)) > 1:
        raise ScanWorkManifestError("candidate has multiple injection locations")
    path_segment_index = None
    if in_path:
        raw_index = value.get("path_segment_index")
        if isinstance(raw_index, bool) or not isinstance(raw_index, int) or raw_index < 0:
            raise ScanWorkManifestError("path candidate segment index is invalid")
        path_segment_index = raw_index
        segments = str(value["canonical_path"]).split("/")
        if raw_index >= len(segments) or segments[raw_index] not in {"{int}", "{uuid}"}:
            raise ScanWorkManifestError(
                "path candidate segment is not a templated path segment"
            )
        if parameter != f"path_{raw_index}":
            raise ScanWorkManifestError(
                "path candidate parameter name must anchor its segment index"
            )
    elif in_body:
        if parameter not in body_names:
            raise ScanWorkManifestError(
                "candidate parameter is absent from body_field_names"
            )
    elif in_fragment:
        if fragment_path is None or parameter not in fragment_names:
            raise ScanWorkManifestError(
                "candidate parameter is absent from browser fragment parameters"
            )
    elif parameter not in query_names:
        raise ScanWorkManifestError(
            "candidate parameter is absent from query_parameter_names"
        )
    content_type = _token(
        value["content_type"], name="content_type", optional=True,
    )
    family_hints = _string_list(
        value["family_hints"], name="family_hints", maximum=8,
    )
    if not family_hints or not set(family_hints) <= {"xss", "sqli"}:
        raise ScanWorkManifestError("candidate family_hints are invalid")
    identity: dict[str, Any] = {
        "route_id": route, "method": method, "parameter_name": parameter,
    }
    if in_body:
        identity["location"] = "body"
    elif in_fragment:
        identity["location"] = "fragment"
    elif in_path:
        identity["location"] = "path"
        identity["path_segment_index"] = int(path_segment_index or 0)
    expected_id = _digest(identity)
    if _hex(value["candidate_id"], name="candidate_id") != expected_id:
        raise ScanWorkManifestError("candidate_id does not match candidate identity")
    lane = _token(value["auth_lane"], name="auth_lane", optional=True)
    if lane not in {None, "primary", "secondary", "service", "anonymous"}:
        raise ScanWorkManifestError("candidate auth_lane is invalid")
    result = {
        "candidate_id": expected_id,
        "route_id": route,
        "method": method,
        "canonical_path": _path(value["canonical_path"]),
        "parameter_name": parameter,
        "query_parameter_names": list(query_names),
        "body_field_names": list(body_names),
        "content_type": content_type,
        "family_hints": list(family_hints),
        "source_tool": _token(value["source_tool"], name="source_tool"),
        "source_observation_ref": _token(
            value["source_observation_ref"],
            name="source_observation_ref",
            optional=True,
        ),
        "auth_lane": lane,
        "selected_shard": _optional_integer(
            value["selected_shard"], name="selected_shard", minimum=0, maximum=16_383,
        ),
        "request_ref_id": _token(
            value["request_ref_id"], name="request_ref_id", optional=True,
        ),
        "score": _integer(value["score"], name="score", minimum=0, maximum=100),
        "ranking_rationale": list(_string_list(
            value["ranking_rationale"], name="ranking_rationale", maximum=16,
        )),
    }
    if in_fragment:
        result.update({
            "browser_fragment_path": fragment_path,
            "browser_fragment_query_parameter_names": list(fragment_names),
        })
    if in_path:
        result["parameter_location"] = "path"
        result["path_segment_index"] = int(path_segment_index or 0)
    return result


def _request_entry(value: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "request_ref_id", "route_id", "method", "auth_lane", "selected_shard",
        "request_class", "content_type", "body_field_names",
        "selection_digest", "body_schema_digest",
    }
    if set(value) != expected:
        raise ScanWorkManifestError("request manifest entry fields are invalid")
    method = str(value["method"] or "").strip().upper()
    request_class = str(value["request_class"] or "").strip().lower()
    if not _METHOD_RE.fullmatch(method) or request_class not in REQUEST_CLASSES:
        raise ScanWorkManifestError("request method contract is invalid")
    if method in {"GET", "HEAD", "OPTIONS"} and request_class != "safe_read":
        raise ScanWorkManifestError("safe HTTP methods must use safe_read")
    if method not in {"GET", "HEAD", "OPTIONS"} and request_class == "safe_read":
        raise ScanWorkManifestError("unsafe HTTP methods cannot use safe_read")
    lane = _token(value["auth_lane"], name="auth_lane", optional=True)
    if lane not in {None, "primary", "secondary", "service", "anonymous"}:
        raise ScanWorkManifestError("request auth_lane is invalid")
    body_digest = value["body_schema_digest"]
    return {
        "request_ref_id": _token(value["request_ref_id"], name="request_ref_id"),
        "route_id": _hex(value["route_id"], name="route_id"),
        "method": method,
        "auth_lane": lane,
        "selected_shard": _optional_integer(
            value["selected_shard"], name="selected_shard", minimum=0, maximum=16_383,
        ),
        "request_class": request_class,
        "content_type": _token(
            value["content_type"], name="content_type", optional=True,
        ),
        "body_field_names": list(_body_field_list(
            value["body_field_names"], name="body_field_names",
        )),
        "selection_digest": _hex(
            value["selection_digest"], name="selection_digest",
        ),
        "body_schema_digest": (
            _hex(body_digest, name="body_schema_digest") if body_digest is not None else None
        ),
    }


def _request_candidate_entry(value: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "candidate_id", "route_id", "request_ref_id", "method",
        "family_hints", "auth_lane", "selected_shard", "score",
        "ranking_rationale", "request_class", "content_type", "field_path",
        "selection_digest",
    }
    if set(value) != expected:
        raise ScanWorkManifestError(
            "request candidate manifest entry fields are invalid"
        )
    method = str(value["method"] or "").strip().upper()
    request_class = str(value["request_class"] or "").strip().lower()
    if (
        not _METHOD_RE.fullmatch(method) or method in {"GET", "HEAD", "OPTIONS"}
        or request_class not in {"safe_authentication", "confirmed_mutation"}
    ):
        raise ScanWorkManifestError(
            "request candidate requires a state-changing HTTP method"
        )
    route = _hex(value["route_id"], name="route_id")
    request_ref = str(_token(
        value["request_ref_id"], name="request_ref_id",
    ))
    family_hints = _string_list(
        value["family_hints"], name="family_hints", maximum=2,
    )
    if not family_hints or not set(family_hints) <= {"xss", "sqli"}:
        raise ScanWorkManifestError("request candidate family_hints are invalid")
    expected_id = _digest({
        "route_id": route,
        "request_ref_id": request_ref,
        "method": method,
        "field_path": str(value["field_path"]),
    })
    if _hex(value["candidate_id"], name="candidate_id") != expected_id:
        raise ScanWorkManifestError(
            "request candidate ID does not match its private request authority"
        )
    lane = _token(value["auth_lane"], name="auth_lane", optional=True)
    if lane not in {None, "primary", "secondary", "service", "anonymous"}:
        raise ScanWorkManifestError("request candidate auth_lane is invalid")
    return {
        "candidate_id": expected_id,
        "route_id": route,
        "request_ref_id": request_ref,
        "method": method,
        "request_class": request_class,
        "content_type": str(_token(value["content_type"], name="content_type")),
        "field_path": str(_body_field_list(
            [value["field_path"]], name="field_path",
        )[0]),
        "selection_digest": _hex(
            value["selection_digest"], name="selection_digest",
        ),
        "family_hints": list(family_hints),
        "auth_lane": lane,
        "selected_shard": _optional_integer(
            value["selected_shard"], name="selected_shard",
            minimum=0, maximum=16_383,
        ),
        "score": _integer(value["score"], name="score", minimum=0, maximum=100),
        "ranking_rationale": list(_string_list(
            value["ranking_rationale"],
            name="ranking_rationale",
            maximum=16,
        )),
    }


def _template_entry(value: Mapping[str, Any]) -> dict[str, Any]:
    expected = {"template_id", "template_digest", "batch_index", "risk", "tags"}
    if set(value) != expected:
        raise ScanWorkManifestError("template manifest entry fields are invalid")
    risk = str(value["risk"] or "").strip().lower()
    if risk not in {"passive", "safe_active", "intrusive"}:
        raise ScanWorkManifestError("template risk is invalid")
    return {
        "template_id": _token(value["template_id"], name="template_id"),
        "template_digest": _hex(value["template_digest"], name="template_digest"),
        "batch_index": _integer(
            value["batch_index"], name="batch_index", minimum=0, maximum=99_999,
        ),
        "risk": risk,
        "tags": list(_string_list(value["tags"], name="tags", maximum=64)),
    }


def _entry(kind: ScanWorkManifestKind, value: Mapping[str, Any], *, target_digest: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ScanWorkManifestError("manifest entry must be an object")
    _reject_sensitive_keys(value)
    if kind is ScanWorkManifestKind.ENDPOINT:
        return _endpoint_entry(value, target_digest=target_digest)
    if kind is ScanWorkManifestKind.CANDIDATE:
        return _candidate_entry(value)
    if kind is ScanWorkManifestKind.REQUEST_CANDIDATE:
        return _request_candidate_entry(value)
    if kind is ScanWorkManifestKind.REQUEST:
        return _request_entry(value)
    return _template_entry(value)


@dataclass(frozen=True)
class ScanWorkManifestReference:
    manifest_id: str
    kind: ScanWorkManifestKind | str
    content_schema: str
    manifest_digest: str
    entry_count: int
    status: str
    schema_version: str = SCAN_WORK_MANIFEST_REFERENCE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != SCAN_WORK_MANIFEST_REFERENCE_SCHEMA:
            raise ScanWorkManifestError("unsupported work manifest reference schema")
        kind = self.kind if isinstance(self.kind, ScanWorkManifestKind) else ScanWorkManifestKind(str(self.kind))
        if self.content_schema != WORK_MANIFEST_CONTENT_SCHEMAS[kind.value]:
            raise ScanWorkManifestError("work manifest reference content schema is invalid")
        if self.status not in {"complete", "partial", "cancelled"}:
            raise ScanWorkManifestError("work manifest reference status is invalid")
        object.__setattr__(self, "manifest_id", _uuid(self.manifest_id, name="manifest_id"))
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "manifest_digest", _hex(
            self.manifest_digest, name="manifest_digest",
        ))
        object.__setattr__(self, "entry_count", _integer(
            self.entry_count,
            name="entry_count",
            minimum=0,
            maximum=_MAX_ENTRIES[kind.value],
        ))

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "manifest_id": self.manifest_id,
            "kind": self.kind.value,
            "content_schema": self.content_schema,
            "manifest_digest": self.manifest_digest,
            "entry_count": self.entry_count,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ScanWorkManifestReference":
        expected = {
            "schema_version", "manifest_id", "kind", "content_schema",
            "manifest_digest", "entry_count", "status",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ScanWorkManifestError("work manifest reference fields are invalid")
        return cls(**dict(value))


def work_manifest_references_in(value: Any) -> tuple[ScanWorkManifestReference, ...]:
    """Extract canonical manifest references from immutable action arguments."""
    references: dict[tuple[str, ...], ScanWorkManifestReference] = {}

    def visit(item: Any) -> None:
        if isinstance(item, Mapping):
            try:
                reference = ScanWorkManifestReference.from_dict(item)
            except (ScanWorkManifestError, TypeError, ValueError):
                for nested in item.values():
                    visit(nested)
            else:
                key = tuple(
                    str(part) for part in reference.canonical_dict().values()
                )
                references[key] = reference
        elif isinstance(item, (list, tuple)):
            for nested in item:
                visit(nested)

    visit(value)
    return tuple(references[key] for key in sorted(references))


def unique_work_manifest_reference_dicts(
    values: Iterable[Any],
) -> tuple[dict[str, Any], ...]:
    """Return one stable public reference for each manifest used by a plan."""
    references: dict[tuple[str, ...], ScanWorkManifestReference] = {}
    for value in values:
        for reference in work_manifest_references_in(value):
            key = tuple(
                str(part) for part in reference.canonical_dict().values()
            )
            references[key] = reference
    return tuple(
        references[key].canonical_dict() for key in sorted(references)
    )


@dataclass(frozen=True)
class ScanWorkManifest:
    scan_id: str
    kind: ScanWorkManifestKind | str
    target_binding_digest: str
    source_action_ids: tuple[str, ...]
    entries: tuple[Mapping[str, Any], ...]
    status: str = "complete"
    reason_code: str | None = None
    schema_version: str = SCAN_WORK_MANIFEST_SCHEMA
    manifest_id: str | None = None
    manifest_digest: str | None = field(default=None, compare=True)

    def __post_init__(self) -> None:
        if self.schema_version != SCAN_WORK_MANIFEST_SCHEMA:
            raise ScanWorkManifestError("unsupported Scan work manifest schema")
        scan_id = _uuid(self.scan_id, name="scan_id")
        kind = self.kind if isinstance(self.kind, ScanWorkManifestKind) else ScanWorkManifestKind(str(self.kind))
        target_digest = _hex(self.target_binding_digest, name="target_binding_digest")
        source_ids = tuple(str(_token(item, name="source_action_id")) for item in self.source_action_ids)
        if not source_ids or len(source_ids) > 64 or len(set(source_ids)) != len(source_ids):
            raise ScanWorkManifestError("source_action_ids are missing, duplicated, or too large")
        if self.status not in {"complete", "partial", "cancelled"}:
            raise ScanWorkManifestError("work manifest status is invalid")
        reason = str(self.reason_code or "").strip() or None
        if self.status == "complete" and reason is not None:
            raise ScanWorkManifestError("complete work manifest cannot have a reason")
        if self.status != "complete" and reason is None:
            raise ScanWorkManifestError("partial/cancelled work manifest requires a reason")
        if len(self.entries) > _MAX_ENTRIES[kind.value]:
            raise ScanWorkManifestError("work manifest exceeds its bounded entry ceiling")
        normalized = tuple(
            _entry(kind, item, target_digest=target_digest) for item in self.entries
        )
        identities = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in normalized]
        if len(set(identities)) != len(identities):
            raise ScanWorkManifestError("work manifest contains duplicate entries")
        material = {
            "schema_version": self.schema_version,
            "scan_id": scan_id,
            "kind": kind.value,
            "content_schema": WORK_MANIFEST_CONTENT_SCHEMAS[kind.value],
            "target_binding_digest": target_digest,
            "source_action_ids": list(source_ids),
            "entries": list(normalized),
            "status": self.status,
            "reason_code": reason,
        }
        expected_digest = _digest(material)
        if self.manifest_digest is not None and _hex(
            self.manifest_digest, name="manifest_digest",
        ) != expected_digest:
            raise ScanWorkManifestError("manifest_digest does not match canonical content")
        expected_id = str(uuid.uuid5(uuid.UUID(scan_id), f"{kind.value}:{expected_digest}"))
        if self.manifest_id is not None and _uuid(
            self.manifest_id, name="manifest_id",
        ) != expected_id:
            raise ScanWorkManifestError("manifest_id does not match content address")
        object.__setattr__(self, "scan_id", scan_id)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "target_binding_digest", target_digest)
        object.__setattr__(self, "source_action_ids", source_ids)
        object.__setattr__(self, "entries", tuple(_freeze(item) for item in normalized))
        object.__setattr__(self, "reason_code", reason)
        object.__setattr__(self, "manifest_digest", expected_digest)
        object.__setattr__(self, "manifest_id", expected_id)

    @property
    def content_schema(self) -> str:
        return WORK_MANIFEST_CONTENT_SCHEMAS[self.kind.value]

    def digest_material(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "scan_id": self.scan_id,
            "kind": self.kind.value,
            "content_schema": self.content_schema,
            "target_binding_digest": self.target_binding_digest,
            "source_action_ids": list(self.source_action_ids),
            "entries": [_thaw(item) for item in self.entries],
            "status": self.status,
            "reason_code": self.reason_code,
        }

    def canonical_dict(self) -> dict[str, Any]:
        return {
            **self.digest_material(),
            "manifest_id": self.manifest_id,
            "manifest_digest": self.manifest_digest,
        }

    def reference(self) -> ScanWorkManifestReference:
        return ScanWorkManifestReference(
            manifest_id=str(self.manifest_id),
            kind=self.kind,
            content_schema=self.content_schema,
            manifest_digest=str(self.manifest_digest),
            entry_count=len(self.entries),
            status=self.status,
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ScanWorkManifest":
        expected = {
            "schema_version", "scan_id", "kind", "content_schema",
            "target_binding_digest", "source_action_ids", "entries", "status",
            "reason_code", "manifest_id", "manifest_digest",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ScanWorkManifestError("Scan work manifest fields are invalid")
        kind = ScanWorkManifestKind(str(value["kind"]))
        if value["content_schema"] != WORK_MANIFEST_CONTENT_SCHEMAS[kind.value]:
            raise ScanWorkManifestError("Scan work manifest content schema is invalid")
        return cls(**{
            key: item for key, item in dict(value).items() if key != "content_schema"
        })


def endpoint_entry_from_public_record(
    record: Mapping[str, Any],
    *,
    target_binding_digest: str,
    source_tool: str | None = None,
    discovery_depth: int = 0,
    auth_lane: str | None = None,
    selected_shard: int | None = None,
    request_ref_ids: Sequence[str] = (),
) -> dict[str, Any]:
    method = str(record.get("method") or "GET").upper()
    scheme = str(record.get("scheme") or "").lower()
    host = str(record.get("host") or "").lower().rstrip(".")
    port = int(record.get("port") or (443 if scheme == "https" else 80))
    path = str(record.get("normalized_path") or record.get("concrete_path") or "/")
    query_names = sorted(str(item) for item in record.get("query_keys") or ())
    fragment_path = (
        str(record.get("browser_fragment_path"))
        if record.get("browser_fragment_path") else None
    )
    fragment_names = sorted(
        str(item) for item in record.get("browser_fragment_query_keys") or ()
    )
    entry = {
        "route_id": route_id(
            target_binding_digest=target_binding_digest,
            method=method,
            scheme=scheme,
            host=host,
            port=port,
            canonical_path=path,
            query_parameter_names=query_names,
            browser_fragment_path=fragment_path,
            browser_fragment_query_parameter_names=fragment_names,
        ),
        "method": method,
        "scheme": scheme,
        "host": host,
        "port": port,
        "canonical_path": path,
        "query_parameter_names": query_names,
        "content_type": (str(record.get("content_type")) if record.get("content_type") else None),
        "body_field_names": sorted(str(item) for item in record.get("body_field_names") or ()),
        "source_tool": source_tool or str(record.get("source") or "unknown"),
        "discovery_depth": int(discovery_depth),
        "auth_lane": auth_lane,
        "selected_shard": selected_shard,
        "request_ref_ids": list(request_ref_ids),
    }
    if fragment_path:
        entry.update({
            "browser_fragment_path": fragment_path,
            "browser_fragment_query_parameter_names": fragment_names,
        })
    return entry


def build_endpoint_manifest(
    *,
    scan_id: str,
    target_binding_digest: str,
    surface_manifest: Mapping[str, Any],
    source_action_ids: Sequence[str],
    auth_lane: str | None = "anonymous",
    selected_shard: int | None = None,
    request_ref_ids_by_route: Mapping[str, Sequence[str]] | None = None,
    auth_lane_by_route: Mapping[str, str] | None = None,
) -> ScanWorkManifest:
    """Upgrade normalized discovery output into the canonical durable endpoint form."""
    if str(surface_manifest.get("schema_version") or "") not in {
        "endpoint-manifest/v1", "endpoint-manifest/v2",
    }:
        raise ScanWorkManifestError("surface manifest schema is unsupported")
    status = str(surface_manifest.get("status") or "partial").strip().lower()
    if status not in {"complete", "partial", "cancelled"}:
        status = "partial"
    reason = str(surface_manifest.get("reason") or "").strip() or None
    if status != "complete" and reason is None:
        reason = "surface_manifest_incomplete"
    request_refs = dict(request_ref_ids_by_route or {})
    auth_lanes = dict(auth_lane_by_route or {})
    depth_by_source = {
        "seed": 0,
        "known_endpoints": 0,
        "collections.replay": 0,
        "web.probe": 0,
        "web.crawl": 1,
        "web.content_discover": 1,
        # A published API description is a first-party declaration of the surface, not a route
        # inferred from a fetched page, so it is depth 0 like a seeded endpoint.
        "web.spec_ingest": 0,
        "subdomains.discover": 1,
    }
    entries: list[dict[str, Any]] = []
    excluded_sensitive_paths = 0
    for raw in surface_manifest.get("endpoints") or ():
        if not isinstance(raw, Mapping):
            raise ScanWorkManifestError("surface manifest endpoint must be an object")
        # Public discovery surfaces intentionally redact secret-like path
        # segments.  A redacted display path is never executable authority.
        if raw.get("sensitive_path_redacted") is True:
            excluded_sensitive_paths += 1
            continue
        source = str(raw.get("source") or "unknown")
        base = endpoint_entry_from_public_record(
            raw,
            target_binding_digest=target_binding_digest,
            source_tool=source,
            discovery_depth=depth_by_source.get(source, 1),
            auth_lane=auth_lane,
            selected_shard=selected_shard,
        )
        base["auth_lane"] = auth_lanes.get(base["route_id"], auth_lane)
        base["request_ref_ids"] = list(request_refs.get(base["route_id"], ()))
        entries.append(base)
    entries.sort(key=lambda item: item["route_id"])
    if excluded_sensitive_paths:
        status = "partial" if status != "cancelled" else status
        exclusion_reason = (
            f"sensitive_paths_excluded:{excluded_sensitive_paths}"
        )
        reason = ";".join(
            item for item in (reason, exclusion_reason) if item
        )[:200]
    return ScanWorkManifest(
        scan_id=scan_id,
        kind=ScanWorkManifestKind.ENDPOINT,
        target_binding_digest=target_binding_digest,
        source_action_ids=tuple(source_action_ids),
        entries=tuple(entries),
        status=status,
        reason_code=reason,
    )


def _body_field_rank(name: str) -> int:
    """Rank one body field by how likely it is to be the injectable one.

    Only decides which field anchors a body candidate's identity and ranking; every declared field
    is tested regardless, so a wrong guess here costs nothing but a less representative label.
    """
    normalized = str(name).lower().replace("-", "_")
    if normalized in {"email", "username", "user", "login", "mail", "id"}:
        return 2
    if normalized.endswith("_id") or normalized in {"password", "passwd", "search", "query", "q"}:
        return 1
    return 0


# Client-library transport endpoints: socket.io / engine.io long-poll handshakes, SockJS,
# and dev-server hot-reload channels. Their query strings are protocol state, not inputs.
_TRANSPORT_PLUMBING_ROUTE_RE = re.compile(
    r"(?:^|/)(?:socket\.io|engine\.io|sockjs(?:-node)?|__webpack_hmr|webpack-hmr|hot-update)(?:/|$)",
    re.IGNORECASE,
)
# Parameters that carry a nonce, a timestamp, or transport negotiation rather than a value the
# application interprets. ``t`` and ``_`` are the jQuery/socket.io cache-busters.
_CACHE_BUSTER_PARAMETERS = frozenset({
    "t", "_", "ts", "timestamp", "cb", "cachebust", "cache_bust", "nocache", "no_cache",
    "rand", "random", "nonce", "eio", "transport", "sid",
})


def build_candidate_manifest(
    endpoint_manifest: ScanWorkManifest,
    *,
    source_action_ids: Sequence[str],
    maximum: int,
    allow_state_changing_http: bool = False,
) -> ScanWorkManifest:
    """Rank every candidate and freeze the deterministic bounded top set.

    Body fields are injection points too -- for most modern APIs the only ones -- but reaching them
    needs a state-changing request, so they are admitted only when the scan holds that authority.
    The default is closed: a caller that does not state its authority gets the query-only surface.
    """
    if endpoint_manifest.kind is not ScanWorkManifestKind.ENDPOINT:
        raise ScanWorkManifestError("candidate source must be an endpoint manifest")
    limit = _integer(maximum, name="candidate maximum", minimum=1, maximum=20_000)

    xss_names = frozenset({
        "callback", "comment", "description", "html", "keyword", "message",
        "name", "next", "q", "query", "redirect", "return", "search",
        "text", "title", "url",
    })
    sqli_names = frozenset({
        "account", "category", "customer", "filter", "id", "item", "order",
        "page", "product", "record", "search", "sort", "user", "username",
        # The authentication query is the canonical SQL injection site, and these are its canonical
        # field names. `username` was already here while `email` -- its modern equivalent -- and
        # `password` were not, so a login body ranked below transport plumbing like a socket.io
        # `transport` parameter and was the first work a constrained budget dropped.
        "email", "password", "passwd", "login", "mail",
    })
    source_points = {
        "collections.replay": (18, "exact_request_source"),
        "known_endpoints": (14, "admission_declared_source"),
        # A request the application itself issued at run time is stronger
        # evidence than a route parsed out of its source: the parameters are the
        # ones the client actually sends, not ones inferred from a string.
        "web.browser_crawl": (16, "browser_observed_source"),
        "web.crawl": (12, "crawler_observed_source"),
        "web.content_discover": (8, "content_discovery_source"),
        # The application's own spec is authoritative about what a route accepts, on a par with an
        # operator-declared known endpoint.
        "web.spec_ingest": (14, "api_specification_source"),
        "web.probe": (6, "probe_observed_source"),
        "seed": (4, "seed_source"),
    }

    def ranked_candidate(
        endpoint: Mapping[str, Any], parameter: str, *, location: str = "query",
        path_segment_index: int | None = None,
    ) -> dict[str, Any]:
        in_body = location == "body"
        in_fragment = location == "fragment"
        in_path = location == "path"
        normalized_name = parameter.lower().replace("-", "_")
        score = 30
        rationale = [f"parameterized_{location}"]
        source_score, source_reason = source_points.get(
            str(endpoint["source_tool"]), (2, "other_admitted_source"),
        )
        score += source_score
        rationale.append(source_reason)
        if endpoint["method"] == "GET":
            score += 8
            rationale.append("synthetic_get_supported")
        elif in_body:
            # A body field is a first-class injection point -- most modern APIs have no other --
            # but reaching it requires a state-changing request, so it ranks below an equivalent
            # query parameter rather than above it.
            score += 4
            rationale.append("state_changing_request_required")
        elif in_path:
            # A templated path segment is a value the application substitutes into a query and is
            # read with a GET, so it needs no state-changing authority; it ranks with a query
            # parameter as a first-class SQL injection site.
            score += 8
            rationale.append("path_parameter")
        if endpoint["request_ref_ids"]:
            score += 18
            rationale.append("exact_request_reference")
        if endpoint["auth_lane"] not in {None, "anonymous"}:
            score += 8
            rationale.append("authenticated_lane")
        if normalized_name in xss_names:
            score += 10
            rationale.append("xss_semantic_parameter")
        if normalized_name in sqli_names or normalized_name.endswith("_id"):
            score += 10
            rationale.append("sqli_semantic_parameter")
        if in_path:
            score += 10
            rationale.append("path_id_injection_point")
        # Library transport plumbing and cache-busters are parameters the application never
        # reads as input. A thorough scan spent its SQL injection verifier on
        # ``/socket.io/?t=1`` -- the websocket long-poll handshake with its timestamp
        # nonce -- ahead of the login body, because both scored as an observed GET query. Rank
        # them below every real parameter instead of dropping them: they stay in the manifest
        # and still run when the budget reaches them, so nothing is silently excluded.
        if _TRANSPORT_PLUMBING_ROUTE_RE.search(str(endpoint["canonical_path"] or "")):
            score -= 20
            rationale.append("transport_plumbing_route")
        if normalized_name in _CACHE_BUSTER_PARAMETERS:
            score -= 12
            rationale.append("cache_buster_parameter")
        identity: dict[str, Any] = {
            "route_id": endpoint["route_id"],
            "method": endpoint["method"],
            "parameter_name": parameter,
        }
        if in_body:
            # Only a body candidate carries the location, so a query candidate's id is byte-identical
            # to what earlier builds produced and stored manifests still validate.
            identity["location"] = "body"
        elif in_fragment:
            identity["location"] = "fragment"
        elif in_path:
            identity["location"] = "path"
            identity["path_segment_index"] = int(path_segment_index or 0)
        candidate_id = _digest(identity)
        candidate = {
            "candidate_id": candidate_id,
            "route_id": endpoint["route_id"],
            "method": endpoint["method"],
            "canonical_path": endpoint["canonical_path"],
            "parameter_name": parameter,
            "query_parameter_names": list(endpoint["query_parameter_names"]),
            "body_field_names": (
                list(endpoint.get("body_field_names") or ()) if in_body else []
            ),
            "content_type": (
                (str(endpoint.get("content_type")) if endpoint.get("content_type") else None)
                if in_body else None
            ),
            # URL fragments never reach the server, so SQL injection is not a meaningful family;
            # a path segment reaches the query engine but never reflects into HTML, so it is a
            # SQL-injection site only.
            "family_hints": (
                ["sqli"] if in_path else ["xss"] if in_fragment else ["xss", "sqli"]
            ),
            "source_tool": endpoint["source_tool"],
            "source_observation_ref": None,
            "auth_lane": endpoint["auth_lane"],
            "selected_shard": endpoint["selected_shard"],
            "request_ref_id": (
                endpoint["request_ref_ids"][0]
                if endpoint["request_ref_ids"] else None
            ),
            "score": min(100, score),
            "ranking_rationale": rationale,
        }
        if in_path:
            candidate["parameter_location"] = "path"
            candidate["path_segment_index"] = int(path_segment_index or 0)
        if in_fragment:
            candidate.update({
                "browser_fragment_path": endpoint["browser_fragment_path"],
                "browser_fragment_query_parameter_names": list(
                    endpoint["browser_fragment_query_parameter_names"]
                ),
            })
        return candidate

    # Keep only the best bounded set while visiting potentially large endpoint
    # manifests.  The heap key makes a higher score and, on ties, a lower
    # content-addressed candidate ID better.  Observation order is irrelevant.
    selected: list[tuple[tuple[int, int], dict[str, Any]]] = []
    candidate_count = 0
    unsupported_path_operations = False
    for endpoint in endpoint_manifest.entries:
        # A non-GET endpoint used to be skipped outright, so an application whose injectable
        # surface is a JSON body produced no candidates at all. Query parameters and declared body
        # fields are both injection points; the planner decides which it holds authority to test.
        locations: list[tuple[str, str]] = [
            (str(name), "query") for name in endpoint["query_parameter_names"]
        ]
        if endpoint["method"] == "GET":
            locations.extend(
                (str(name), "fragment")
                for name in endpoint.get("browser_fragment_query_parameter_names") or ()
            )
        # A templated path segment (/api/orders/{int}) is an injectable value the query never names.
        # The URL-only sqlmap path adapter can only test GET operations. Do not invent a
        # GET handler for a POST/PUT/DELETE route, even when mutation is authorized.
        path_segments = (
            _templated_path_segments(str(endpoint["canonical_path"]))
            if endpoint["method"] == "GET" else []
        )
        if endpoint["method"] != "GET" and _templated_path_segments(str(endpoint["canonical_path"])):
            unsupported_path_operations = True
        if endpoint["method"] != "GET":
            # ONE candidate for the whole declared body, not one per field. The verifier tests
            # every field in a single run and stops at the first vulnerable one, so per-field
            # candidates cost N runs for the coverage of one -- and when two fields tied on score,
            # which one got the budget came down to a digest comparison. Measured: testing both
            # fields of a login body costs the same 410 requests as testing either alone. The
            # highest-ranked field anchors the candidate's identity; the whole body is tested.
            body_fields = [str(name) for name in endpoint.get("body_field_names") or ()]
            locations = (
                [(max(body_fields, key=lambda name: (_body_field_rank(name), name)), "body")]
                if allow_state_changing_http and body_fields else []
            )
        path_candidates = [
            ranked_candidate(
                endpoint, f"path_{segment_index}", location="path",
                path_segment_index=segment_index,
            )
            for segment_index in path_segments
        ]
        for candidate in path_candidates:
            candidate_count += 1
            heap_key = (
                int(candidate["score"]),
                -int(str(candidate["candidate_id"]), 16),
            )
            row = (heap_key, candidate)
            if len(selected) < limit:
                heapq.heappush(selected, row)
            elif heap_key > selected[0][0]:
                heapq.heapreplace(selected, row)
        for parameter, location in locations:
            candidate = ranked_candidate(endpoint, parameter, location=location)
            candidate_count += 1
            heap_key = (
                int(candidate["score"]),
                -int(str(candidate["candidate_id"]), 16),
            )
            row = (heap_key, candidate)
            if len(selected) < limit:
                heapq.heappush(selected, row)
            elif heap_key > selected[0][0]:
                heapq.heapreplace(selected, row)
    entries = [row[1] for row in selected]
    entries.sort(key=lambda item: (-int(item["score"]), item["candidate_id"]))
    truncated = candidate_count > limit
    return ScanWorkManifest(
        scan_id=endpoint_manifest.scan_id,
        kind=ScanWorkManifestKind.CANDIDATE,
        target_binding_digest=endpoint_manifest.target_binding_digest,
        source_action_ids=tuple(source_action_ids),
        entries=tuple(entries),
        status="partial" if truncated or unsupported_path_operations or endpoint_manifest.status != "complete" else "complete",
        reason_code=(
            "candidate_limit_reached" if truncated
            else "path_operation_not_supported" if unsupported_path_operations
            else "endpoint_manifest_partial" if endpoint_manifest.status != "complete"
            else None
        ),
    )


def build_request_manifest(
    *,
    scan_id: str,
    target_binding_digest: str,
    source_action_ids: Sequence[str],
    requests: Sequence[Mapping[str, Any]],
    maximum: int = 2_000,
) -> ScanWorkManifest:
    """Freeze an admitted saved-request selection without any secret values."""
    limit = _integer(maximum, name="request maximum", minimum=1, maximum=2_000)
    selected = []
    for raw in requests[:limit]:
        item = dict(raw)
        if "request_class" not in item:
            item["request_class"] = (
                "safe_read" if bool(item.pop("safe_method", False))
                else "confirmed_mutation"
            )
        else:
            item.pop("safe_method", None)
        item.setdefault("content_type", None)
        item.setdefault("body_field_names", [])
        item.setdefault("selection_digest", _digest({
            "scan_id": scan_id,
            "request_ref_id": item.get("request_ref_id"),
            "source_action_ids": list(source_action_ids),
        }))
        selected.append(item)
    truncated = len(requests) > limit
    return ScanWorkManifest(
        scan_id=scan_id,
        kind=ScanWorkManifestKind.REQUEST,
        target_binding_digest=target_binding_digest,
        source_action_ids=tuple(source_action_ids),
        entries=tuple(selected),
        status="partial" if truncated else "complete",
        reason_code="request_limit_reached" if truncated else None,
    )


def build_request_candidate_manifest(
    request_manifests: Sequence[ScanWorkManifest],
    *,
    source_action_ids: Sequence[str],
    maximum: int,
) -> ScanWorkManifest:
    """Freeze exact private body-field candidates without body values.

    The manifest authorizes only an opaque request reference. The executing
    worker must resolve and validate the encrypted request, then select bounded
    JSON/form fields in private memory. A public or redacted URL is deliberately
    absent from this contract.
    """
    if not request_manifests:
        raise ScanWorkManifestError(
            "request candidates require at least one request manifest"
        )
    first = request_manifests[0]
    if any(
        manifest.kind is not ScanWorkManifestKind.REQUEST
        or manifest.scan_id != first.scan_id
        or manifest.target_binding_digest != first.target_binding_digest
        for manifest in request_manifests
    ):
        raise ScanWorkManifestError(
            "request candidate sources must share one Scan target authority"
        )
    limit = _integer(
        maximum, name="request candidate maximum", minimum=1, maximum=2_000,
    )
    candidates: dict[str, dict[str, Any]] = {}
    for manifest in request_manifests:
        for request in manifest.entries:
            request_class = str(request["request_class"])
            if request_class not in {"safe_authentication", "confirmed_mutation"}:
                continue
            request_ref = str(request["request_ref_id"])
            method = str(request["method"])
            route = str(request["route_id"])
            for field_path in request["body_field_names"]:
                candidate_id = _digest({
                    "route_id": route,
                    "request_ref_id": request_ref,
                    "method": method,
                    "field_path": str(field_path),
                })
                score = 82 if request_class == "safe_authentication" else 76
                rationale = [
                    "exact_private_request_reference",
                    request_class,
                    "worker_private_body_required",
                ]
                if request["auth_lane"] not in {None, "anonymous"}:
                    score += 12
                    rationale.append("authenticated_lane")
                candidates[candidate_id] = {
                    "candidate_id": candidate_id,
                    "route_id": route,
                    "request_ref_id": request_ref,
                    "method": method,
                    "request_class": request_class,
                    "content_type": request["content_type"],
                    "field_path": field_path,
                    "selection_digest": request["selection_digest"],
                    "family_hints": ["xss", "sqli"],
                    "auth_lane": request["auth_lane"],
                    "selected_shard": request["selected_shard"],
                    "score": min(100, score),
                    "ranking_rationale": rationale,
                }
    ranked = sorted(
        candidates.values(), key=lambda item: (-int(item["score"]), item["candidate_id"]),
    )
    truncated = len(ranked) > limit
    return ScanWorkManifest(
        scan_id=first.scan_id,
        kind=ScanWorkManifestKind.REQUEST_CANDIDATE,
        target_binding_digest=first.target_binding_digest,
        source_action_ids=tuple(source_action_ids),
        entries=tuple(ranked[:limit]),
        status=(
            "partial"
            if truncated or any(item.status != "complete" for item in request_manifests)
            else "complete"
        ),
        reason_code=(
            "request_candidate_limit_reached" if truncated
            else "request_manifest_partial"
            if any(item.status != "complete" for item in request_manifests)
            else None
        ),
    )


def build_template_manifest(
    *,
    scan_id: str,
    target_binding_digest: str,
    source_action_ids: Sequence[str],
    templates: Iterable[Mapping[str, Any]],
    batch_size: int,
    maximum: int = 20_000,
) -> ScanWorkManifest:
    """Freeze every admitted template and its deterministic execution batch."""
    bounded_batch = _integer(
        batch_size, name="template batch_size", minimum=1, maximum=5_000,
    )
    limit = _integer(maximum, name="template maximum", minimum=1, maximum=20_000)
    normalized: list[dict[str, Any]] = []
    for raw in templates:
        if not isinstance(raw, Mapping):
            raise ScanWorkManifestError("template selection must contain objects")
        normalized.append({
            "template_id": raw.get("template_id"),
            "template_digest": raw.get("template_digest"),
            "batch_index": 0,
            "risk": raw.get("risk"),
            "tags": list(raw.get("tags") or ()),
        })
    normalized.sort(key=lambda item: (str(item["template_id"]), str(item["template_digest"])))
    truncated = len(normalized) > limit
    normalized = normalized[:limit]
    for index, item in enumerate(normalized):
        item["batch_index"] = index // bounded_batch
    return ScanWorkManifest(
        scan_id=scan_id,
        kind=ScanWorkManifestKind.TEMPLATE,
        target_binding_digest=target_binding_digest,
        source_action_ids=tuple(source_action_ids),
        entries=tuple(normalized),
        status="partial" if truncated else "complete",
        reason_code="template_limit_reached" if truncated else None,
    )


def canonical_nuclei_template_pack_digest() -> str:
    """Identify the exact immutable bundle filter used by canonical Scan."""
    return _digest({
        "schema_version": "canonical-nuclei-template-pack/v1",
        "template_bundle_commit": CANONICAL_NUCLEI_TEMPLATE_BUNDLE_COMMIT,
        "template_bundle_sha256": CANONICAL_NUCLEI_TEMPLATE_BUNDLE_SHA256,
        "template_pack_id": CANONICAL_NUCLEI_TEMPLATE_PACK_ID,
        "severities": list(CANONICAL_NUCLEI_TEMPLATE_SEVERITIES),
        "tags": list(CANONICAL_NUCLEI_TEMPLATE_TAGS),
        "protocol_types": ["http"],
        "risk": "safe_active",
        "interactsh": False,
    })


def canonical_passive_nuclei_template_pack_digest() -> str:
    """Identify the exact reviewed GET-only template allowlist."""
    return _digest({
        "schema_version": "canonical-passive-nuclei-template-pack/v1",
        "template_bundle_commit": CANONICAL_NUCLEI_TEMPLATE_BUNDLE_COMMIT,
        "template_bundle_sha256": CANONICAL_NUCLEI_TEMPLATE_BUNDLE_SHA256,
        "template_pack_id": CANONICAL_PASSIVE_NUCLEI_TEMPLATE_PACK_ID,
        "protocol_types": ["http"],
        "methods": ["GET"],
        "interactsh": False,
        "redirects": False,
        "templates": [
            {
                "template_id": template_id,
                "template_digest": template_digest,
                "max_requests": max_requests,
                "severity": severity,
                "tags": list(tags),
            }
            for template_id, template_digest, max_requests, severity, tags
            in CANONICAL_PASSIVE_NUCLEI_TEMPLATES
        ],
    })


def canonical_passive_nuclei_request_upper_bound() -> int:
    return sum(
        max_requests
        for _template_id, _digest_value, max_requests, _severity, _tags
        in CANONICAL_PASSIVE_NUCLEI_TEMPLATES
    )


def _canonical_passive_nuclei_manifest_rows() -> tuple[dict[str, Any], ...]:
    return tuple({
        "template_id": template_id,
        "template_digest": template_digest,
        "risk": "passive",
        # Template manifest v1 has a bounded tag vocabulary.  Preserve the
        # reviewed method and request-cost metadata in that signed material.
        "tags": [
            *tags,
            "read-only",
            "method-get",
            f"max-requests-{max_requests}",
        ],
    } for template_id, template_digest, max_requests, _severity, tags in (
        CANONICAL_PASSIVE_NUCLEI_TEMPLATES
    ))


def build_canonical_passive_nuclei_template_manifest(
    *,
    scan_id: str,
    target_binding_digest: str,
) -> ScanWorkManifest:
    """Freeze the reviewed passive allowlist for one target binding."""
    return build_template_manifest(
        scan_id=scan_id,
        target_binding_digest=target_binding_digest,
        source_action_ids=("passive.templates",),
        templates=_canonical_passive_nuclei_manifest_rows(),
        batch_size=len(CANONICAL_PASSIVE_NUCLEI_TEMPLATES),
        maximum=len(CANONICAL_PASSIVE_NUCLEI_TEMPLATES),
    )


def build_canonical_scan_nuclei_template_manifest(
    *,
    scan_id: str,
    target_binding_digest: str,
    include_active: bool,
) -> ScanWorkManifest:
    """Freeze the passive pack and, when authorized, the active pack together."""
    templates: list[Mapping[str, Any]] = list(
        _canonical_passive_nuclei_manifest_rows()
    )
    source_action_ids = ["passive.templates"]
    if include_active:
        templates.append({
            "template_id": CANONICAL_NUCLEI_TEMPLATE_PACK_ID,
            "template_digest": canonical_nuclei_template_pack_digest(),
            "risk": "safe_active",
            "tags": list(CANONICAL_NUCLEI_TEMPLATE_TAGS),
        })
        source_action_ids.append("active.templates")
    return build_template_manifest(
        scan_id=scan_id,
        target_binding_digest=target_binding_digest,
        source_action_ids=tuple(source_action_ids),
        templates=templates,
        batch_size=max(1, len(templates)),
        maximum=len(templates),
    )


def build_canonical_nuclei_template_manifest(
    *,
    scan_id: str,
    target_binding_digest: str,
) -> ScanWorkManifest:
    """Freeze the one reviewed Nuclei pack selected from the pinned image bundle."""
    return build_template_manifest(
        scan_id=scan_id,
        target_binding_digest=target_binding_digest,
        source_action_ids=("active.templates",),
        templates=({
            "template_id": CANONICAL_NUCLEI_TEMPLATE_PACK_ID,
            "template_digest": canonical_nuclei_template_pack_digest(),
            "risk": "safe_active",
            "tags": list(CANONICAL_NUCLEI_TEMPLATE_TAGS),
        },),
        batch_size=1,
        maximum=1,
    )


def canonical_nuclei_options_for_manifest(
    manifest: ScanWorkManifest,
    *,
    action_id: str,
) -> dict[str, Any]:
    """Resolve fixed Nuclei options only from the reviewed immutable pack."""
    if (
        manifest.kind is not ScanWorkManifestKind.TEMPLATE
        or manifest.status != "complete"
        or not manifest.entries
    ):
        raise ScanWorkManifestError(
            "canonical Nuclei execution requires one complete template pack"
        )
    normalized_action_id = str(action_id or "").strip()
    if not any(
        normalized_action_id == source
        or normalized_action_id.startswith(f"{source}.")
        for source in manifest.source_action_ids
    ):
        raise ScanWorkManifestError(
            "template manifest does not authorize this Nuclei action"
        )
    entries_by_id = {
        str(entry.get("template_id") or ""): entry for entry in manifest.entries
    }
    passive_rows = _canonical_passive_nuclei_manifest_rows()
    expected_passive = {
        str(row["template_id"]): row for row in passive_rows
    }
    allowed_ids = {
        *expected_passive,
        CANONICAL_NUCLEI_TEMPLATE_PACK_ID,
    }
    if set(entries_by_id) - allowed_ids:
        raise ScanWorkManifestError(
            "template manifest contains an unreviewed Nuclei selection"
        )

    if normalized_action_id == "passive.templates" or normalized_action_id.startswith(
        "passive.templates."
    ):
        for template_id, expected in expected_passive.items():
            entry = entries_by_id.get(template_id)
            if (
                entry is None
                or entry.get("template_digest") != expected["template_digest"]
                or entry.get("batch_index") != 0
                or entry.get("risk") != "passive"
                or tuple(entry.get("tags") or ()) != tuple(expected["tags"])
            ):
                raise ScanWorkManifestError(
                    "template manifest is not the reviewed passive Nuclei pack"
                )
        return {
            "severity": "critical,high,medium,low,info",
            "template_ids": ",".join(sorted(expected_passive)),
            "template_pack_digest": canonical_passive_nuclei_template_pack_digest(),
            "template_request_cost_upper_bound": (
                canonical_passive_nuclei_request_upper_bound()
            ),
        }

    entry = entries_by_id.get(CANONICAL_NUCLEI_TEMPLATE_PACK_ID)
    if (
        entry is None
        or entry.get("template_digest") != canonical_nuclei_template_pack_digest()
        or entry.get("batch_index") != 0
        or entry.get("risk") != "safe_active"
        or tuple(entry.get("tags") or ()) != CANONICAL_NUCLEI_TEMPLATE_TAGS
    ):
        raise ScanWorkManifestError(
            "template manifest is not the reviewed canonical Nuclei pack"
        )
    return {
        "severity": ",".join(CANONICAL_NUCLEI_TEMPLATE_SEVERITIES),
        "tags": ",".join(CANONICAL_NUCLEI_TEMPLATE_TAGS),
        "template_pack_digest": canonical_nuclei_template_pack_digest(),
    }


def _templated_path_segments(canonical_path: str) -> list[int]:
    """Indices of the ``{int}``/``{uuid}`` segments in a normalized path.

    Only a templated segment carries a value the application substitutes into a query, so only
    those are injectable; a literal segment is part of the route, not an input.
    """
    return [
        index for index, segment in enumerate(str(canonical_path or "").split("/"))
        if segment in {"{int}", "{uuid}"}
    ]


def execution_url_for_endpoint(
    entry: Mapping[str, Any], *, parameter_name: str | None = None,
    parameter_location: str = "query",
    path_injection_segment: int | None = None,
) -> str:
    """Materialize a value-free execution URL from canonical manifest fields.

    With ``path_injection_segment`` the value at that path segment carries a trailing ``*``, the
    sqlmap custom-injection marker, so a path parameter can be tested where the endpoint declares
    no query or body input.
    """
    scheme = str(entry["scheme"])
    host = str(entry["host"])
    port = int(entry["port"])
    authority_host = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    authority = authority_host if port == default_port else f"{authority_host}:{port}"
    names = list(entry.get("query_parameter_names") or ())
    fragment_names = list(
        entry.get("browser_fragment_query_parameter_names") or ()
    )
    if path_injection_segment is not None:
        # The injection point is the path segment; the query is not part of this candidate, and
        # sqlmap's ``*`` marker overrides auto-detection, so a bare marked path is the exact test.
        names = []
        fragment_names = []
    elif parameter_name is not None:
        if parameter_location not in {"query", "fragment"}:
            raise ScanWorkManifestError("candidate parameter location is invalid")
        names = [parameter_name] if parameter_location == "query" else []
        fragment_names = [parameter_name] if parameter_location == "fragment" else []
    canonical = str(entry["canonical_path"])
    if path_injection_segment is None:
        path = canonical.replace("{int}", "1").replace(
            "{uuid}", "00000000-0000-4000-8000-000000000000",
        )
    else:
        rendered_segments: list[str] = []
        for index, segment in enumerate(canonical.split("/")):
            value = (
                "1" if segment == "{int}"
                else "00000000-0000-4000-8000-000000000000" if segment == "{uuid}"
                else segment
            )
            if index == path_injection_segment and segment in {"{int}", "{uuid}"}:
                value = f"{value}*"
            rendered_segments.append(value)
        path = "/".join(rendered_segments) or "/"
    query = urllib.parse.urlencode([(name, "1") for name in names])
    fragment_path = str(entry.get("browser_fragment_path") or "")
    fragment_query = urllib.parse.urlencode([
        (name, "1") for name in fragment_names
    ])
    fragment = (
        f"{fragment_path}{'?' + fragment_query if fragment_query else ''}"
        if fragment_path else ""
    )
    return urllib.parse.urlunsplit((scheme, authority, path, query, fragment))


def execution_url_for_manifest_endpoint(
    manifest: ScanWorkManifest, index: int,
) -> str:
    """Select one exact endpoint from immutable manifest authority."""
    if manifest.kind is not ScanWorkManifestKind.ENDPOINT:
        raise ScanWorkManifestError("execution target requires an endpoint manifest")
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        raise ScanWorkManifestError("endpoint manifest index is invalid")
    try:
        endpoint = manifest.entries[index]
    except IndexError as exc:
        raise ScanWorkManifestError(
            "endpoint manifest index is outside immutable content"
        ) from exc
    return execution_url_for_endpoint(endpoint)


def execution_routes_for_endpoint_manifest(
    manifest: ScanWorkManifest,
    *,
    method: str = "GET",
    maximum: int = 50,
) -> tuple[str, ...]:
    """Materialize a bounded route inventory only from immutable endpoints."""
    if manifest.kind is not ScanWorkManifestKind.ENDPOINT:
        raise ScanWorkManifestError("route inventory requires an endpoint manifest")
    normalized_method = str(method or "").strip().upper()
    if not _METHOD_RE.fullmatch(normalized_method):
        raise ScanWorkManifestError("route inventory method is invalid")
    limit = _integer(maximum, name="route inventory maximum", minimum=1, maximum=50)
    routes: list[str] = []
    for entry in manifest.entries:
        if entry["method"] != normalized_method:
            continue
        route = execution_url_for_endpoint(entry)
        if route not in routes:
            routes.append(route)
        if len(routes) >= limit:
            break
    return tuple(routes)


def execution_url_for_manifest_candidate(
    endpoint_manifest: ScanWorkManifest,
    candidate_manifest: ScanWorkManifest,
    index: int,
) -> str:
    """Join one candidate to its exact endpoint without rediscovery or values."""
    if (
        endpoint_manifest.kind is not ScanWorkManifestKind.ENDPOINT
        or candidate_manifest.kind is not ScanWorkManifestKind.CANDIDATE
    ):
        raise ScanWorkManifestError(
            "candidate execution requires endpoint and candidate manifests"
        )
    if (
        endpoint_manifest.target_binding_digest
        != candidate_manifest.target_binding_digest
    ):
        raise ScanWorkManifestError("candidate and endpoint target authority differs")
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        raise ScanWorkManifestError("candidate manifest index is invalid")
    try:
        candidate = candidate_manifest.entries[index]
    except IndexError as exc:
        raise ScanWorkManifestError(
            "candidate manifest index is outside immutable content"
        ) from exc
    endpoint = next(
        (
            item for item in endpoint_manifest.entries
            if item["route_id"] == candidate["route_id"]
        ),
        None,
    )
    if endpoint is None:
        raise ScanWorkManifestError(
            "candidate route is absent from its endpoint manifest"
        )
    if candidate.get("parameter_location") == "path":
        segment_index = int(candidate.get("path_segment_index") or 0)
        if (
            endpoint["method"] != "GET" or candidate["method"] != "GET"
            or endpoint["canonical_path"] != candidate["canonical_path"]
            or segment_index not in _templated_path_segments(
                str(endpoint["canonical_path"])
            )
        ):
            raise ScanWorkManifestError(
                "candidate identity conflicts with its endpoint manifest"
            )
        return execution_url_for_endpoint(
            endpoint, path_injection_segment=segment_index,
        )
    fragment_names = list(
        candidate.get("browser_fragment_query_parameter_names") or ()
    )
    in_fragment = bool(fragment_names)
    if (
        endpoint["method"] != candidate["method"]
        or endpoint["canonical_path"] != candidate["canonical_path"]
        or (
            str(candidate["parameter_name"])
            not in (
                endpoint.get("browser_fragment_query_parameter_names") or ()
                if in_fragment else endpoint["query_parameter_names"]
            )
        )
        or (
            in_fragment
            and (
                candidate.get("browser_fragment_path")
                != endpoint.get("browser_fragment_path")
                or sorted(fragment_names) != sorted(
                    endpoint.get("browser_fragment_query_parameter_names") or ()
                )
            )
        )
    ):
        raise ScanWorkManifestError(
            "candidate identity conflicts with its endpoint manifest"
        )
    return execution_url_for_endpoint(
        endpoint, parameter_name=str(candidate["parameter_name"]),
        parameter_location="fragment" if in_fragment else "query",
    )


def execution_request_for_manifest_candidate(
    endpoint_manifest: ScanWorkManifest,
    candidate_manifest: ScanWorkManifest,
    index: int,
) -> dict[str, Any]:
    """Resolve one candidate into the exact request that tests it.

    A query candidate is fully described by a URL, which is why the older resolver returns one. A
    body candidate is not: the field lives in a request body, so the caller needs the method, the
    content type and the field set as well. Both are resolved here against the immutable endpoint
    manifest, so a candidate can never name a field its own endpoint does not declare.
    """
    if (
        endpoint_manifest.kind is not ScanWorkManifestKind.ENDPOINT
        or candidate_manifest.kind is not ScanWorkManifestKind.CANDIDATE
    ):
        raise ScanWorkManifestError(
            "candidate execution requires endpoint and candidate manifests"
        )
    if (
        endpoint_manifest.target_binding_digest
        != candidate_manifest.target_binding_digest
    ):
        raise ScanWorkManifestError("candidate and endpoint target authority differs")
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        raise ScanWorkManifestError("candidate manifest index is invalid")
    try:
        candidate = candidate_manifest.entries[index]
    except IndexError as exc:
        raise ScanWorkManifestError(
            "candidate manifest index is outside immutable content"
        ) from exc
    if candidate.get("parameter_location") == "path":
        if candidate.get("method") != "GET":
            raise ScanWorkManifestError("path injection requires a GET operation")
        # A path candidate is a GET whose URL carries the sqlmap ``*`` marker at the segment; it
        # has no body and needs no state-changing authority.
        return {
            "method": "GET",
            "url": execution_url_for_manifest_candidate(
                endpoint_manifest, candidate_manifest, index,
            ),
            "content_type": None,
            "field_name": str(candidate["parameter_name"]),
            "body_field_names": [],
            "path_injection": True,
        }
    body_fields = list(candidate.get("body_field_names") or ())
    if not body_fields:
        return {
            "method": "GET",
            "url": execution_url_for_manifest_candidate(
                endpoint_manifest, candidate_manifest, index,
            ),
            "content_type": None,
            "field_name": str(candidate["parameter_name"]),
            "body_field_names": [],
        }
    endpoint = next(
        (
            item for item in endpoint_manifest.entries
            if item["route_id"] == candidate["route_id"]
        ),
        None,
    )
    if endpoint is None:
        raise ScanWorkManifestError(
            "candidate route is absent from its endpoint manifest"
        )
    declared = list(endpoint.get("body_field_names") or ())
    if (
        endpoint["method"] != candidate["method"]
        or endpoint["canonical_path"] != candidate["canonical_path"]
        or str(candidate["parameter_name"]) not in declared
        or sorted(body_fields) != sorted(declared)
    ):
        raise ScanWorkManifestError(
            "candidate identity conflicts with its endpoint manifest"
        )
    return {
        "method": str(endpoint["method"]),
        "url": execution_url_for_endpoint(endpoint, parameter_name=None),
        "content_type": (
            str(candidate["content_type"]) if candidate.get("content_type") else None
        ),
        "field_name": str(candidate["parameter_name"]),
        "body_field_names": sorted(declared),
    }
