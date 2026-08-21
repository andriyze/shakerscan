"""Incremental endpoint manifests and timeout-recovery checkpoints.

Discovery producers stream normalized endpoint records into an in-memory manifest. When the
scanner worker provides ``SCAN_CHECKPOINT_FILE``, the manifest also maintains a secret-free
recovery checkpoint that the existing worker timeout path can return as a partial scan result.
A richer scanner checkpoint always wins and is never overwritten by this module.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import time
from typing import Any
import urllib.parse


_UUID_SEGMENT = re.compile(r"^[0-9a-f]{8}-[0-9a-f-]{20,}$", re.I)
_INTEGER_SEGMENT = re.compile(r"^\d+$")
_SAFE_RECOVERY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_RECOVERY_CHECKPOINT_KIND = "endpoint_manifest_recovery/v1"


@dataclass(frozen=True)
class DiscoveryDeadlines:
    soft_seconds: float = 180.0
    flush_grace_seconds: float = 30.0
    hard_seconds: float = 240.0

    def __post_init__(self) -> None:
        if self.soft_seconds <= 0 or self.flush_grace_seconds < 0:
            raise ValueError("discovery deadlines must be positive")
        if self.hard_seconds < self.soft_seconds + self.flush_grace_seconds:
            raise ValueError("hard deadline must include the soft deadline and flush grace")


@dataclass(frozen=True)
class EndpointRecord:
    method: str
    scheme: str
    host: str
    port: int
    normalized_path: str
    concrete_path: str
    query_keys: tuple[str, ...] = ()
    content_fingerprint: str | None = None
    source: str = "unknown"

    @property
    def identity(self) -> str:
        return "|".join((
            self.method,
            self.scheme,
            self.host,
            str(self.port),
            self.normalized_path,
            ",".join(self.query_keys),
            self.content_fingerprint or "",
        ))

    @property
    def safe_for_recovery_fanout(self) -> bool:
        return self.method in _SAFE_RECOVERY_METHODS

    @property
    def redacted_query(self) -> str:
        return urllib.parse.urlencode([(key, "1") for key in self.query_keys])

    @property
    def work_item(self) -> str:
        suffix = f"?{self.redacted_query}" if self.redacted_query else ""
        return f"{self.method} {self.concrete_path}{suffix}"

    @property
    def redacted_url(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        default_port = 443 if self.scheme == "https" else 80
        authority = host if self.port == default_port else f"{host}:{self.port}"
        suffix = f"?{self.redacted_query}" if self.redacted_query else ""
        return f"{self.scheme}://{authority}{self.concrete_path}{suffix}"


def normalize_endpoint(
    *, method: str, url: str, source: str, content_type: str | None = None,
    body_schema: Any = None,
) -> EndpointRecord:
    method = str(method or "GET").strip().upper()
    if not re.fullmatch(r"[A-Z]{3,12}", method):
        raise ValueError("endpoint method is invalid")
    parsed = urllib.parse.urlsplit(str(url or "").strip())
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().rstrip(".")
    if scheme not in {"http", "https"} or not host or parsed.username:
        raise ValueError("endpoint URL must be an absolute HTTP(S) URL without userinfo")
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("endpoint URL contains an invalid port") from exc
    concrete = parsed.path or "/"
    normalized_segments = []
    for segment in concrete.split("/"):
        decoded = urllib.parse.unquote(segment)
        if _INTEGER_SEGMENT.fullmatch(decoded):
            normalized_segments.append("{int}")
        elif _UUID_SEGMENT.fullmatch(decoded):
            normalized_segments.append("{uuid}")
        else:
            normalized_segments.append(segment)
    normalized = "/".join(normalized_segments) or "/"
    query_keys = tuple(sorted({
        str(key).strip()[:200]
        for key, _value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if str(key).strip()
    }))[:64]
    content_fingerprint = None
    if content_type or body_schema is not None:
        encoded = json.dumps(
            {"content_type": str(content_type or "").lower(), "schema": body_schema},
            sort_keys=True, separators=(",", ":"), default=str,
        ).encode()
        content_fingerprint = hashlib.sha256(encoded).hexdigest()
    return EndpointRecord(
        method,
        scheme,
        host,
        port,
        normalized,
        concrete,
        query_keys,
        content_fingerprint,
        str(source or "unknown")[:80],
    )


@dataclass
class ProducerState:
    status: str = "running"
    count: int = 0
    reason: str | None = None
    timed_out: bool = False


def _atomic_write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


class AtomicManifestSink:
    def __init__(
        self, path: str | os.PathLike[str], *, flush_seconds: float = 5.0,
        flush_new_endpoints: int = 50,
    ) -> None:
        self.path = Path(path)
        self.flush_seconds = float(flush_seconds)
        self.flush_new_endpoints = int(flush_new_endpoints)
        self._last_flush = 0.0
        self._last_count = 0

    def should_flush(self, count: int, *, force: bool = False) -> bool:
        if force:
            return True
        now = time.monotonic()
        enough_rows = count - self._last_count >= self.flush_new_endpoints
        enough_time = now - self._last_flush >= self.flush_seconds
        return enough_rows or enough_time

    def write_payload(self, payload: Any, *, count: int) -> None:
        _atomic_write_json(self.path, payload)
        self._last_flush = time.monotonic()
        self._last_count = count

    def maybe_flush(self, manifest: "EndpointManifest", *, force: bool = False) -> bool:
        payload = manifest.to_dict()
        count = int(payload["endpoint_count"])
        if not self.should_flush(count, force=force):
            return False
        self.write_payload(payload, count=count)
        return True


class DiscoveryRecoverySink:
    """Persist a sidecar manifest and a worker-compatible minimal checkpoint."""

    def __init__(
        self,
        *,
        manifest_path: str | os.PathLike[str] | None,
        checkpoint_path: str | os.PathLike[str] | None,
        flush_seconds: float = 5.0,
        flush_new_endpoints: int = 50,
    ) -> None:
        self.manifest_sink = (
            AtomicManifestSink(
                manifest_path,
                flush_seconds=flush_seconds,
                flush_new_endpoints=flush_new_endpoints,
            )
            if manifest_path else None
        )
        self.checkpoint_path = Path(checkpoint_path) if checkpoint_path else None
        self.flush_seconds = float(flush_seconds)
        self.flush_new_endpoints = int(flush_new_endpoints)
        self._last_flush = 0.0
        self._last_count = 0

    @classmethod
    def from_environment(cls) -> "DiscoveryRecoverySink | None":
        disabled = str(os.environ.get("SHAKERSCAN_DISABLE_DISCOVERY_RECOVERY") or "").lower()
        if disabled in {"1", "true", "yes", "on"}:
            return None
        checkpoint = str(os.environ.get("SCAN_CHECKPOINT_FILE") or "").strip() or None
        manifest = str(os.environ.get("SHAKERSCAN_ENDPOINT_MANIFEST_FILE") or "").strip() or None
        if manifest is None and checkpoint:
            manifest = checkpoint + ".endpoint-manifest.json"
        if not checkpoint and not manifest:
            return None
        return cls(manifest_path=manifest, checkpoint_path=checkpoint)

    def _checkpoint_is_available(self) -> bool:
        if self.checkpoint_path is None or not self.checkpoint_path.exists():
            return True
        try:
            existing = json.loads(self.checkpoint_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return False
        return isinstance(existing, dict) and existing.get("checkpoint_kind") == _RECOVERY_CHECKPOINT_KIND

    @staticmethod
    def _recovery_checkpoint(manifest: "EndpointManifest") -> dict[str, Any]:
        payload = manifest.to_dict()
        cancelled = payload["status"] == "cancelled"
        endpoints = list(manifest.endpoints)
        fanout = [] if cancelled else [
            item for item in endpoints if item.safe_for_recovery_fanout
        ]
        excluded_unsafe = 0 if cancelled else len(endpoints) - len(fanout)
        target = (fanout[0].redacted_url if fanout else endpoints[0].redacted_url) if endpoints else None
        timed_out = any(state.timed_out for state in manifest.producers.values())
        report = {
            "target": target,
            "findings": [],
            "result": {"score": None, "grade": None},
            "active_checks": {"active_worklist": [item.work_item for item in fanout]},
            "discovery": {
                "endpoint_manifest": payload,
                "katana_sample": [item.redacted_url for item in fanout[:500]],
            },
            "scan_metadata": {
                "status": "cancelled" if cancelled else "partial",
                "partial": not cancelled,
                "timed_out": timed_out,
                "coverage_status": payload["status"],
                "recovery_source": _RECOVERY_CHECKPOINT_KIND,
                "unsafe_methods_excluded_from_fanout": excluded_unsafe,
            },
        }
        return {
            "checkpoint_kind": _RECOVERY_CHECKPOINT_KIND,
            "phase": "discovery",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "partial": not cancelled,
            "report": report,
        }

    def maybe_flush(self, manifest: "EndpointManifest", *, force: bool = False) -> bool:
        count = len(manifest.endpoints)
        now = time.monotonic()
        if not force:
            enough_rows = count - self._last_count >= self.flush_new_endpoints
            enough_time = now - self._last_flush >= self.flush_seconds
            if not enough_rows and not enough_time:
                return False
        wrote = False
        if self.manifest_sink is not None:
            self.manifest_sink.maybe_flush(manifest, force=True)
            wrote = True
        if self.checkpoint_path is not None and self._checkpoint_is_available():
            _atomic_write_json(self.checkpoint_path, self._recovery_checkpoint(manifest))
            wrote = True
        if wrote:
            self._last_flush = now
            self._last_count = count
        return wrote


class EndpointManifest:
    schema_version = "endpoint-manifest/v1"

    def __init__(
        self, *, recovery_sink: DiscoveryRecoverySink | None = None,
        auto_persist: bool = True,
    ) -> None:
        self._endpoints: dict[str, EndpointRecord] = {}
        self.producers: dict[str, ProducerState] = {}
        self.status = "running"
        self.reason: str | None = None
        self.persistence_errors: list[str] = []
        self._recovery_sink = (
            recovery_sink if recovery_sink is not None
            else DiscoveryRecoverySink.from_environment() if auto_persist
            else None
        )

    @property
    def endpoints(self) -> tuple[EndpointRecord, ...]:
        return tuple(self._endpoints.values())

    def _flush(self, *, force: bool = False) -> None:
        if self._recovery_sink is None:
            return
        try:
            self._recovery_sink.maybe_flush(self, force=force)
        except (OSError, UnicodeError, ValueError, TypeError) as exc:
            marker = f"{type(exc).__name__}:{str(exc)[:200]}"
            if marker not in self.persistence_errors:
                self.persistence_errors.append(marker)
                del self.persistence_errors[20:]

    def start_producer(self, name: str) -> None:
        if name in self.producers and self.producers[name].status == "running":
            raise ValueError(f"producer already running: {name}")
        self.producers[name] = ProducerState()

    def add(self, producer: str, endpoint: EndpointRecord) -> bool:
        state = self.producers.get(producer)
        if not state or state.status != "running":
            raise ValueError("producer must be running before adding endpoints")
        accepted = endpoint.identity not in self._endpoints
        if accepted:
            self._endpoints[endpoint.identity] = endpoint
            state.count += 1
            self._flush()
        return accepted

    def finish_producer(
        self, name: str, *, status: str = "complete", reason: str | None = None
    ) -> None:
        if status not in {"complete", "partial", "timed_out", "failed", "cancelled"}:
            raise ValueError("invalid producer status")
        state = self.producers.setdefault(name, ProducerState())
        state.status = status
        state.reason = reason
        state.timed_out = status == "timed_out"
        self._flush(force=True)

    def finalize(self, *, cancelled: bool = False) -> None:
        if cancelled:
            self.status, self.reason = "cancelled", "user_cancelled"
            self._flush(force=True)
            return
        degraded = [
            name for name, state in self.producers.items()
            if state.status in {"partial", "timed_out", "failed"}
        ]
        self.status = "partial" if degraded else "complete"
        self.reason = "producer_degraded:" + ",".join(sorted(degraded)) if degraded else None
        self._flush(force=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "reason": self.reason,
            "endpoint_count": len(self._endpoints),
            "endpoints": [asdict(item) for item in self._endpoints.values()],
            "producers": {name: asdict(state) for name, state in self.producers.items()},
            "persistence_errors": list(self.persistence_errors),
        }
