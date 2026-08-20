"""Incremental endpoint-manifest/v1 normalization and atomic persistence."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import time
from typing import Any, Mapping
import urllib.parse


_UUID_SEGMENT = re.compile(r"^[0-9a-f]{8}-[0-9a-f-]{20,}$", re.I)
_INTEGER_SEGMENT = re.compile(r"^\d+$")


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
    content_fingerprint: str | None = None
    source: str = "unknown"

    @property
    def identity(self) -> str:
        return "|".join((
            self.method, self.scheme, self.host, str(self.port), self.normalized_path,
            self.content_fingerprint or "",
        ))


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
    port = parsed.port or (443 if scheme == "https" else 80)
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
    content_fingerprint = None
    if content_type or body_schema is not None:
        encoded = json.dumps(
            {"content_type": str(content_type or "").lower(), "schema": body_schema},
            sort_keys=True, separators=(",", ":"), default=str,
        ).encode()
        content_fingerprint = hashlib.sha256(encoded).hexdigest()
    return EndpointRecord(
        method, scheme, host, port, normalized, concrete, content_fingerprint,
        str(source or "unknown")[:80],
    )


@dataclass
class ProducerState:
    status: str = "running"
    count: int = 0
    reason: str | None = None
    timed_out: bool = False


class EndpointManifest:
    schema_version = "endpoint-manifest/v1"

    def __init__(self) -> None:
        self._endpoints: dict[str, EndpointRecord] = {}
        self.producers: dict[str, ProducerState] = {}
        self.status = "running"
        self.reason: str | None = None

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

    def finalize(self, *, cancelled: bool = False) -> None:
        if cancelled:
            self.status, self.reason = "cancelled", "user_cancelled"
            return
        degraded = [
            name for name, state in self.producers.items()
            if state.status in {"partial", "timed_out", "failed"}
        ]
        self.status = "partial" if degraded else "complete"
        self.reason = "producer_degraded:" + ",".join(sorted(degraded)) if degraded else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "reason": self.reason,
            "endpoint_count": len(self._endpoints),
            "endpoints": [asdict(item) for item in self._endpoints.values()],
            "producers": {name: asdict(state) for name, state in self.producers.items()},
        }


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

    def maybe_flush(self, manifest: EndpointManifest, *, force: bool = False) -> bool:
        payload = manifest.to_dict()
        count = int(payload["endpoint_count"])
        now = time.monotonic()
        if not force:
            enough_rows = count - self._last_count >= self.flush_new_endpoints
            enough_time = now - self._last_flush >= self.flush_seconds
            if not enough_rows and not enough_time:
                return False
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=self.path.name + ".", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self.path)
        finally:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass
        self._last_flush = now
        self._last_count = count
        return True
