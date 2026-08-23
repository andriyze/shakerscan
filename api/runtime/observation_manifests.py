"""Content-free references to bounded, worker-private capability observations."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re
from typing import Any, Mapping
import uuid


OBSERVATION_MANIFEST_SCHEMA = "capability-observation-manifest/v1"
OBSERVATION_MANIFEST_REFERENCE_SCHEMA = "observation-manifest-reference/v1"
_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+:/-]{0,199}$")
_MAX_OBSERVATIONS = 100_000
_MAX_CONTENT_BYTES = 64 * 1024 * 1024


class ObservationManifestError(ValueError):
    """Observation manifest metadata is unsafe or fails digest validation."""


def _hex_digest(value: Any, *, name: str) -> str:
    normalized = str(value or "").strip().lower()
    if not _HEX_64_RE.fullmatch(normalized):
        raise ObservationManifestError(f"{name} must be 64 lowercase hex characters")
    return normalized


def _token(value: Any, *, name: str) -> str:
    normalized = str(value or "").strip()
    if not _TOKEN_RE.fullmatch(normalized):
        raise ObservationManifestError(f"{name} is invalid")
    return normalized


def _bounded_integer(value: Any, *, name: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ObservationManifestError(f"{name} is outside its allowed range")
    return value


def _object_key(value: Any) -> str:
    normalized = str(value or "").strip()
    if (
        not normalized
        or len(normalized.encode("utf-8")) > 1_024
        or normalized.startswith(("/", "\\"))
        or "://" in normalized
        or "\x00" in normalized
        or any(part in {"", ".", ".."} for part in normalized.replace("\\", "/").split("/"))
    ):
        raise ObservationManifestError("object_key must be a private relative object key")
    return normalized


def _manifest_digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        dict(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class ObservationManifestReference:
    manifest_id: str
    sha256: str
    count: int
    size_bytes: int
    object_key: str
    manifest_digest: str
    schema_version: str = OBSERVATION_MANIFEST_REFERENCE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != OBSERVATION_MANIFEST_REFERENCE_SCHEMA:
            raise ObservationManifestError("unsupported observation manifest reference schema")
        try:
            manifest_id = str(uuid.UUID(str(self.manifest_id)))
        except (TypeError, ValueError, AttributeError) as exc:
            raise ObservationManifestError("manifest_id must be a UUID") from exc
        object.__setattr__(self, "manifest_id", manifest_id)
        object.__setattr__(self, "sha256", _hex_digest(self.sha256, name="sha256"))
        object.__setattr__(self, "count", _bounded_integer(
            self.count, name="count", maximum=_MAX_OBSERVATIONS,
        ))
        object.__setattr__(self, "size_bytes", _bounded_integer(
            self.size_bytes, name="size_bytes", maximum=_MAX_CONTENT_BYTES,
        ))
        object.__setattr__(self, "object_key", _object_key(self.object_key))
        object.__setattr__(self, "manifest_digest", _hex_digest(
            self.manifest_digest, name="manifest_digest",
        ))
        if self.count and not self.size_bytes:
            raise ObservationManifestError("non-empty manifest cannot have an empty object")

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "manifest_id": self.manifest_id,
            "sha256": self.sha256,
            "count": self.count,
            "size_bytes": self.size_bytes,
            "object_key": self.object_key,
            "manifest_digest": self.manifest_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ObservationManifestReference":
        expected = {
            "schema_version", "manifest_id", "sha256", "count", "size_bytes",
            "object_key", "manifest_digest",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ObservationManifestError("observation manifest reference fields are invalid")
        return cls(**dict(value))


@dataclass(frozen=True)
class ObservationManifest:
    owner_id: str
    action_id: str
    capability_name: str
    output_schema: str
    observation_count: int
    content_sha256: str
    size_bytes: int
    object_key: str
    manifest_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    owner_kind: str = "scan"
    redaction_profile: str = "public-observation-v2"
    schema_version: str = OBSERVATION_MANIFEST_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != OBSERVATION_MANIFEST_SCHEMA:
            raise ObservationManifestError("unsupported observation manifest schema")
        if self.owner_kind != "scan":
            raise ObservationManifestError("capability observation manifest must belong to Scan")
        try:
            manifest_id = str(uuid.UUID(str(self.manifest_id)))
            owner_id = str(uuid.UUID(str(self.owner_id)))
        except (TypeError, ValueError, AttributeError) as exc:
            raise ObservationManifestError("manifest_id and owner_id must be UUIDs") from exc
        object.__setattr__(self, "manifest_id", manifest_id)
        object.__setattr__(self, "owner_id", owner_id)
        object.__setattr__(self, "action_id", _token(self.action_id, name="action_id"))
        object.__setattr__(self, "capability_name", _token(
            self.capability_name, name="capability_name",
        ))
        object.__setattr__(self, "output_schema", _token(
            self.output_schema, name="output_schema",
        ))
        object.__setattr__(self, "redaction_profile", _token(
            self.redaction_profile, name="redaction_profile",
        ))
        object.__setattr__(self, "observation_count", _bounded_integer(
            self.observation_count, name="observation_count", maximum=_MAX_OBSERVATIONS,
        ))
        object.__setattr__(self, "content_sha256", _hex_digest(
            self.content_sha256, name="content_sha256",
        ))
        object.__setattr__(self, "size_bytes", _bounded_integer(
            self.size_bytes, name="size_bytes", maximum=_MAX_CONTENT_BYTES,
        ))
        object.__setattr__(self, "object_key", _object_key(self.object_key))
        if self.observation_count and not self.size_bytes:
            raise ObservationManifestError("non-empty manifest cannot have an empty object")

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "manifest_id": self.manifest_id,
            "owner_kind": self.owner_kind,
            "owner_id": self.owner_id,
            "action_id": self.action_id,
            "capability_name": self.capability_name,
            "output_schema": self.output_schema,
            "observation_count": self.observation_count,
            "content_sha256": self.content_sha256,
            "size_bytes": self.size_bytes,
            "object_key": self.object_key,
            "redaction_profile": self.redaction_profile,
        }

    @property
    def manifest_digest(self) -> str:
        return _manifest_digest(self.canonical_dict())

    def reference(self) -> ObservationManifestReference:
        return ObservationManifestReference(
            manifest_id=self.manifest_id,
            sha256=self.content_sha256,
            count=self.observation_count,
            size_bytes=self.size_bytes,
            object_key=self.object_key,
            manifest_digest=self.manifest_digest,
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ObservationManifest":
        expected = {
            "schema_version", "manifest_id", "owner_kind", "owner_id", "action_id",
            "capability_name", "output_schema", "observation_count", "content_sha256",
            "size_bytes", "object_key", "redaction_profile",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ObservationManifestError("observation manifest fields are invalid")
        return cls(**dict(value))


def validate_observation_manifest_reference(
    reference: ObservationManifestReference,
    manifest: ObservationManifest,
) -> None:
    """Fail closed unless a reference identifies this exact manifest and object."""
    expected = manifest.reference()
    if reference != expected:
        raise ObservationManifestError(
            "observation manifest reference does not match manifest metadata"
        )
