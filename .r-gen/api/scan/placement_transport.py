"""Private, digest-checked bridge for legacy report-finalizer placements."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any, Mapping, MutableMapping


PLACEMENT_BUNDLE_SCHEMA = "canonical-scan-placements/v1"
PLACEMENT_FILE_ENV = "SHAKERSCAN_CANONICAL_PLACEMENTS_FILE"
PLACEMENT_DIGEST_ENV = "SHAKERSCAN_CANONICAL_PLACEMENTS_SHA256"
MAX_PLACEMENT_BUNDLE_BYTES = 8 * 1024 * 1024
MAX_PLACED_CAPABILITIES = 64
_DIRECTORY_PREFIX = "shakerscan-placements-"
_FILE_NAME = "placements.json"


class PlacementTransportError(ValueError):
    """A private placement bundle failed authority or filesystem validation."""


def _canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    try:
        encoded = json.dumps(
            dict(payload),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PlacementTransportError("placement bundle is not canonical JSON") from exc
    if not encoded or len(encoded) > MAX_PLACEMENT_BUNDLE_BYTES:
        raise PlacementTransportError("placement bundle exceeds its size limit")
    return encoded


def _validate_payload_shape(
    payload: Mapping[str, Any],
    *,
    execution_plan_digest: str | None = None,
    target_binding_digest: str | None = None,
) -> dict[str, Any]:
    if not isinstance(payload, Mapping) or set(payload) != {
        "schema_version", "execution_plan_digest", "target_binding_digest", "capabilities",
    }:
        raise PlacementTransportError("canonical Scan placement fields are invalid")
    if payload.get("schema_version") != PLACEMENT_BUNDLE_SCHEMA:
        raise PlacementTransportError("canonical Scan placement schema is invalid")
    if execution_plan_digest is not None and (
        payload.get("execution_plan_digest") != execution_plan_digest
    ):
        raise PlacementTransportError("canonical Scan placements do not match this execution")
    if target_binding_digest is not None and (
        payload.get("target_binding_digest") != target_binding_digest
    ):
        raise PlacementTransportError("canonical Scan placements do not match this execution")
    capabilities = payload.get("capabilities")
    if (
        not isinstance(capabilities, Mapping)
        or len(capabilities) > MAX_PLACED_CAPABILITIES
        or any(
            not isinstance(name, str)
            or not name
            or len(name) > 128
            or not isinstance(summary, Mapping)
            for name, summary in capabilities.items()
        )
    ):
        raise PlacementTransportError("canonical Scan placement capabilities are invalid")
    return {
        "schema_version": PLACEMENT_BUNDLE_SCHEMA,
        "execution_plan_digest": str(payload["execution_plan_digest"]),
        "target_binding_digest": str(payload["target_binding_digest"]),
        "capabilities": {
            str(name): dict(summary) for name, summary in capabilities.items()
        },
    }


@dataclass(frozen=True)
class PrivatePlacementBundle:
    path: Path
    sha256: str
    size_bytes: int

    def environment(self) -> dict[str, str]:
        return {
            PLACEMENT_FILE_ENV: str(self.path),
            PLACEMENT_DIGEST_ENV: self.sha256,
        }

    def cleanup(self) -> None:
        try:
            self.path.unlink(missing_ok=True)
        finally:
            try:
                self.path.parent.rmdir()
            except OSError:
                pass


def write_private_placement_bundle(
    payload: Mapping[str, Any],
    *,
    parent_directory: str | os.PathLike[str] | None = None,
) -> PrivatePlacementBundle:
    """Write canonical JSON to an owner-only directory and regular file."""
    normalized = _validate_payload_shape(payload)
    encoded = _canonical_bytes(normalized)
    directory = Path(tempfile.mkdtemp(
        prefix=_DIRECTORY_PREFIX,
        dir=str(parent_directory) if parent_directory is not None else None,
    ))
    path = directory / _FILE_NAME
    try:
        os.chmod(directory, 0o700)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=True) as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        return PrivatePlacementBundle(
            path=path,
            sha256=hashlib.sha256(encoded).hexdigest(),
            size_bytes=len(encoded),
        )
    except BaseException:
        try:
            path.unlink(missing_ok=True)
        finally:
            try:
                directory.rmdir()
            except OSError:
                pass
        raise


def _read_private_file(path: Path, expected_digest: str) -> bytes:
    if not path.is_absolute() or path.name != _FILE_NAME:
        raise PlacementTransportError("placement path is not an absolute private bundle path")
    directory = path.parent
    if not directory.name.startswith(_DIRECTORY_PREFIX):
        raise PlacementTransportError("placement directory identity is invalid")
    try:
        directory_stat = directory.lstat()
        path_stat = path.lstat()
    except OSError as exc:
        raise PlacementTransportError("placement bundle is unavailable") from exc
    current_uid = os.geteuid()
    if (
        not stat.S_ISDIR(directory_stat.st_mode)
        or stat.S_ISLNK(directory_stat.st_mode)
        or directory_stat.st_uid != current_uid
        or stat.S_IMODE(directory_stat.st_mode) != 0o700
    ):
        raise PlacementTransportError("placement directory is not owner-only")
    if (
        not stat.S_ISREG(path_stat.st_mode)
        or stat.S_ISLNK(path_stat.st_mode)
        or path_stat.st_uid != current_uid
        or stat.S_IMODE(path_stat.st_mode) != 0o600
        or not 0 < path_stat.st_size <= MAX_PLACEMENT_BUNDLE_BYTES
    ):
        raise PlacementTransportError("placement file is not a bounded owner-only regular file")
    digest = str(expected_digest or "").strip().lower()
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise PlacementTransportError("placement digest is invalid")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise PlacementTransportError("placement file could not be opened safely") from exc
    try:
        opened = os.fstat(fd)
        if (
            opened.st_dev != path_stat.st_dev
            or opened.st_ino != path_stat.st_ino
            or not stat.S_ISREG(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_uid != current_uid
        ):
            raise PlacementTransportError("placement file changed during validation")
        with os.fdopen(fd, "rb", closefd=True) as stream:
            raw = stream.read(MAX_PLACEMENT_BUNDLE_BYTES + 1)
        fd = -1
    finally:
        if fd >= 0:
            os.close(fd)
    if len(raw) != path_stat.st_size or hashlib.sha256(raw).hexdigest() != digest:
        raise PlacementTransportError("placement file digest or size mismatch")
    return raw


def load_private_placement_bundle(
    execution: Mapping[str, Any] | None,
    *,
    environ: MutableMapping[str, str] | None = None,
) -> dict[str, Any]:
    """Load once, validate against execution authority, then delete the bridge."""
    environment = os.environ if environ is None else environ
    raw_path = str(environment.pop(PLACEMENT_FILE_ENV, "") or "").strip()
    expected_digest = str(environment.pop(PLACEMENT_DIGEST_ENV, "") or "").strip()
    if not raw_path and not expected_digest:
        return {}
    if not raw_path or not expected_digest:
        raise PlacementTransportError("placement file and digest must be supplied together")
    if execution is None:
        raise PlacementTransportError(
            "canonical Scan placements require a validated execution envelope"
        )
    path = Path(raw_path)
    try:
        raw = _read_private_file(path, expected_digest)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PlacementTransportError("placement bundle is invalid JSON") from exc
        normalized = _validate_payload_shape(
            payload,
            execution_plan_digest=str(execution.get("execution_plan_digest") or ""),
            target_binding_digest=str(execution.get("target_binding_digest") or ""),
        )
        if _canonical_bytes(normalized) != raw:
            raise PlacementTransportError("placement bundle is not canonical JSON")
        return normalized
    finally:
        try:
            path.unlink(missing_ok=True)
        finally:
            try:
                path.parent.rmdir()
            except OSError:
                pass
