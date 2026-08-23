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
    "request": "request-manifest/v1",
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
_MAX_ENTRIES = MappingProxyType({
    "endpoint": 100_000,
    "candidate": 20_000,
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


class ScanWorkManifestError(ValueError):
    """A work manifest is unsafe, unbounded, or detached from Scan authority."""


class ScanWorkManifestKind(str, Enum):
    ENDPOINT = "endpoint"
    CANDIDATE = "candidate"
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


def _string_list(value: Any, *, name: str, maximum: int) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > maximum:
        raise ScanWorkManifestError(f"{name} must be a bounded list")
    normalized = tuple(
        str(_token(item, name=f"{name} entry")) for item in value
    )
    if len(set(normalized)) != len(normalized):
        raise ScanWorkManifestError(f"{name} contains duplicates")
    return normalized


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
) -> str:
    """Derive one stable, value-free route identity."""
    return _digest({
        "target_binding_digest": _hex(
            target_binding_digest, name="target_binding_digest",
        ),
        "method": str(method or "").strip().upper(),
        "scheme": str(scheme or "").strip().lower(),
        "host": str(host or "").strip().lower().rstrip("."),
        "port": int(port),
        "canonical_path": _path(canonical_path),
        "query_parameter_names": sorted(str(item) for item in query_parameter_names),
    })


def _endpoint_entry(value: Mapping[str, Any], *, target_digest: str) -> dict[str, Any]:
    expected = {
        "route_id", "method", "scheme", "host", "port", "canonical_path",
        "query_parameter_names", "source_tool", "discovery_depth", "auth_lane",
        "selected_shard", "request_ref_ids",
    }
    if set(value) != expected:
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
    expected_route = route_id(
        target_binding_digest=target_digest,
        method=method,
        scheme=scheme,
        host=host,
        port=port,
        canonical_path=canonical_path,
        query_parameter_names=query_names,
    )
    if _hex(value["route_id"], name="route_id") != expected_route:
        raise ScanWorkManifestError("route_id does not match endpoint identity")
    lane = _token(value["auth_lane"], name="auth_lane", optional=True)
    if lane not in {None, "primary", "secondary", "service", "anonymous"}:
        raise ScanWorkManifestError("endpoint auth_lane is invalid")
    return {
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
    }


def _candidate_entry(value: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "candidate_id", "route_id", "method", "canonical_path", "parameter_name",
        "query_parameter_names", "body_field_names", "content_type",
        "family_hints", "source_tool", "source_observation_ref", "auth_lane",
        "selected_shard", "request_ref_id", "score", "ranking_rationale",
    }
    if set(value) != expected:
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
    if parameter not in query_names:
        raise ScanWorkManifestError(
            "candidate parameter is absent from query_parameter_names"
        )
    body_names = _string_list(
        value["body_field_names"], name="body_field_names", maximum=128,
    )
    content_type = _token(
        value["content_type"], name="content_type", optional=True,
    )
    family_hints = _string_list(
        value["family_hints"], name="family_hints", maximum=8,
    )
    if not family_hints or not set(family_hints) <= {"xss", "sqli"}:
        raise ScanWorkManifestError("candidate family_hints are invalid")
    expected_id = _digest({"route_id": route, "method": method, "parameter_name": parameter})
    if _hex(value["candidate_id"], name="candidate_id") != expected_id:
        raise ScanWorkManifestError("candidate_id does not match candidate identity")
    lane = _token(value["auth_lane"], name="auth_lane", optional=True)
    if lane not in {None, "primary", "secondary", "service", "anonymous"}:
        raise ScanWorkManifestError("candidate auth_lane is invalid")
    return {
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


def _request_entry(value: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "request_ref_id", "route_id", "method", "auth_lane", "selected_shard",
        "safe_method", "body_schema_digest",
    }
    if set(value) != expected:
        raise ScanWorkManifestError("request manifest entry fields are invalid")
    method = str(value["method"] or "").strip().upper()
    if not _METHOD_RE.fullmatch(method) or not isinstance(value["safe_method"], bool):
        raise ScanWorkManifestError("request method contract is invalid")
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
        "safe_method": value["safe_method"],
        "body_schema_digest": (
            _hex(body_digest, name="body_schema_digest") if body_digest is not None else None
        ),
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
    return {
        "route_id": route_id(
            target_binding_digest=target_binding_digest,
            method=method,
            scheme=scheme,
            host=host,
            port=port,
            canonical_path=path,
            query_parameter_names=query_names,
        ),
        "method": method,
        "scheme": scheme,
        "host": host,
        "port": port,
        "canonical_path": path,
        "query_parameter_names": query_names,
        "source_tool": source_tool or str(record.get("source") or "unknown"),
        "discovery_depth": int(discovery_depth),
        "auth_lane": auth_lane,
        "selected_shard": selected_shard,
        "request_ref_ids": list(request_ref_ids),
    }


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


def build_candidate_manifest(
    endpoint_manifest: ScanWorkManifest,
    *,
    source_action_ids: Sequence[str],
    maximum: int,
) -> ScanWorkManifest:
    """Rank every query candidate and freeze the deterministic bounded top set."""
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
    })
    source_points = {
        "collections.replay": (18, "exact_request_source"),
        "known_endpoints": (14, "admission_declared_source"),
        "web.crawl": (12, "crawler_observed_source"),
        "web.content_discover": (8, "content_discovery_source"),
        "web.probe": (6, "probe_observed_source"),
        "seed": (4, "seed_source"),
    }

    def ranked_candidate(
        endpoint: Mapping[str, Any], parameter: str,
    ) -> dict[str, Any]:
        normalized_name = parameter.lower().replace("-", "_")
        score = 30
        rationale = ["parameterized_query"]
        source_score, source_reason = source_points.get(
            str(endpoint["source_tool"]), (2, "other_admitted_source"),
        )
        score += source_score
        rationale.append(source_reason)
        if endpoint["method"] == "GET":
            score += 8
            rationale.append("synthetic_get_supported")
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
        candidate_id = _digest({
            "route_id": endpoint["route_id"],
            "method": endpoint["method"],
            "parameter_name": parameter,
        })
        return {
            "candidate_id": candidate_id,
            "route_id": endpoint["route_id"],
            "method": endpoint["method"],
            "canonical_path": endpoint["canonical_path"],
            "parameter_name": parameter,
            "query_parameter_names": list(endpoint["query_parameter_names"]),
            "body_field_names": [],
            "content_type": None,
            "family_hints": ["xss", "sqli"],
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

    # Keep only the best bounded set while visiting potentially large endpoint
    # manifests.  The heap key makes a higher score and, on ties, a lower
    # content-addressed candidate ID better.  Observation order is irrelevant.
    selected: list[tuple[tuple[int, int], dict[str, Any]]] = []
    candidate_count = 0
    for endpoint in endpoint_manifest.entries:
        if endpoint["method"] != "GET":
            continue
        for parameter in endpoint["query_parameter_names"]:
            candidate = ranked_candidate(endpoint, str(parameter))
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
        status="partial" if truncated or endpoint_manifest.status != "complete" else "complete",
        reason_code=(
            "candidate_limit_reached" if truncated
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
    selected = list(requests[:limit])
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
) -> dict[str, str]:
    """Resolve fixed Nuclei options only from the reviewed immutable pack."""
    if (
        manifest.kind is not ScanWorkManifestKind.TEMPLATE
        or manifest.status != "complete"
        or len(manifest.entries) != 1
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
    entry = manifest.entries[0]
    if (
        entry.get("template_id") != CANONICAL_NUCLEI_TEMPLATE_PACK_ID
        or entry.get("template_digest")
        != canonical_nuclei_template_pack_digest()
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


def execution_url_for_endpoint(
    entry: Mapping[str, Any], *, parameter_name: str | None = None,
) -> str:
    """Materialize a value-free execution URL from canonical manifest fields."""
    scheme = str(entry["scheme"])
    host = str(entry["host"])
    port = int(entry["port"])
    authority_host = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    authority = authority_host if port == default_port else f"{authority_host}:{port}"
    names = list(entry.get("query_parameter_names") or ())
    if parameter_name is not None:
        names = [parameter_name]
    path = str(entry["canonical_path"])
    path = path.replace("{int}", "1").replace(
        "{uuid}", "00000000-0000-4000-8000-000000000000",
    )
    query = urllib.parse.urlencode([(name, "1") for name in names])
    return urllib.parse.urlunsplit((scheme, authority, path, query, ""))


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
    if (
        endpoint["method"] != candidate["method"]
        or endpoint["canonical_path"] != candidate["canonical_path"]
        or candidate["parameter_name"] not in endpoint["query_parameter_names"]
    ):
        raise ScanWorkManifestError(
            "candidate identity conflicts with its endpoint manifest"
        )
    return execution_url_for_endpoint(
        endpoint, parameter_name=str(candidate["parameter_name"]),
    )
