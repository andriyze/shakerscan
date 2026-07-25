"""Reliable Redis Stream queue primitives with legacy-list upgrade compatibility.

Producers write one JSON payload field to a stream. Workers consume through one
consumer group, explicitly acknowledge completed work, refresh pending-message
idle time while running, and reclaim abandoned deliveries after the visibility
timeout. Legacy Redis-list entries are still readable during an upgrade, but no
new production enqueue uses the list path.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Iterable


CONSUMER_GROUP = os.environ.get("SHAKERSCAN_QUEUE_CONSUMER_GROUP", "shakerscan-workers")
STREAM_SUFFIX = ":leased"
PAYLOAD_FIELD = "payload"


@dataclass(frozen=True)
class QueueLease:
    queue_name: str
    payload: str
    stream_key: str | None = None
    message_id: str | None = None
    delivery_attempts: int = 1
    reclaimed: bool = False

    @property
    def legacy(self) -> bool:
        return self.message_id is None


def stream_key(queue_name: str) -> str:
    return f"{queue_name}{STREAM_SUFFIX}"


def _text(value: Any) -> str:
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)


def _has_streams(redis_client: Any) -> bool:
    # Narrow test doubles from older queue tests intentionally exercise the
    # upgrade fallback. Real redis-py clients always expose these methods.
    return callable(getattr(redis_client, "xadd", None)) and callable(
        getattr(redis_client, "xreadgroup", None)
    )


def ensure_consumer_group(redis_client: Any, queue_name: str) -> None:
    if not _has_streams(redis_client):
        return
    try:
        redis_client.xgroup_create(stream_key(queue_name), CONSUMER_GROUP, id="0-0", mkstream=True)
    except Exception as exc:
        if "BUSYGROUP" not in str(exc):
            raise


def enqueue_job(redis_client: Any, queue_name: str, payload: str | dict[str, Any]) -> str:
    encoded = payload if isinstance(payload, str) else json.dumps(payload)
    if not _has_streams(redis_client):
        redis_client.rpush(queue_name, encoded)
        return "legacy-list"
    ensure_consumer_group(redis_client, queue_name)
    return _text(redis_client.xadd(stream_key(queue_name), {PAYLOAD_FIELD: encoded}))


def _decode_messages(response: Any) -> list[tuple[str, str, str]]:
    decoded: list[tuple[str, str, str]] = []
    for raw_stream, raw_messages in response or []:
        for raw_id, raw_fields in raw_messages or []:
            fields = {
                _text(key): _text(value)
                for key, value in (raw_fields or {}).items()
            }
            payload = fields.get(PAYLOAD_FIELD, "")
            if payload:
                decoded.append((_text(raw_stream), _text(raw_id), payload))
    return decoded


def _delivery_attempts(redis_client: Any, key: str, message_id: str) -> int:
    try:
        rows = redis_client.xpending_range(
            key,
            CONSUMER_GROUP,
            min=message_id,
            max=message_id,
            count=1,
        )
        if rows:
            row = rows[0]
            return max(1, int(row.get("times_delivered") or row.get(b"times_delivered") or 1))
    except Exception:
        pass
    return 1


def lease_job(
    redis_client: Any,
    queue_names: Iterable[str],
    *,
    consumer_name: str,
    block_ms: int,
    visibility_timeout_ms: int,
) -> QueueLease | None:
    queues = list(dict.fromkeys(queue_names))
    if not queues:
        return None
    if not _has_streams(redis_client):
        result = redis_client.blpop(queues, timeout=max(1, block_ms // 1000))
        if not result:
            return None
        queue_name, payload = result
        return QueueLease(queue_name=_text(queue_name), payload=_text(payload))

    for queue_name in queues:
        ensure_consumer_group(redis_client, queue_name)

    # Reclaim one abandoned delivery before accepting fresh work. XAUTOCLAIM is
    # atomic and increments Redis' delivery counter for bounded retry policy.
    for queue_name in queues:
        key = stream_key(queue_name)
        claimed = redis_client.xautoclaim(
            key,
            CONSUMER_GROUP,
            consumer_name,
            min_idle_time=visibility_timeout_ms,
            start_id="0-0",
            count=1,
        )
        raw_messages = claimed[1] if claimed and len(claimed) > 1 else []
        messages = _decode_messages([(key, raw_messages)])
        if messages:
            _, message_id, payload = messages[0]
            return QueueLease(
                queue_name=queue_name,
                payload=payload,
                stream_key=key,
                message_id=message_id,
                delivery_attempts=_delivery_attempts(redis_client, key, message_id),
                reclaimed=True,
            )

    response = redis_client.xreadgroup(
        CONSUMER_GROUP,
        consumer_name,
        {stream_key(queue_name): ">" for queue_name in queues},
        count=1,
        block=max(1, block_ms),
    )
    messages = _decode_messages(response)
    if not messages:
        # Drain pre-upgrade list jobs without letting the blocking legacy read
        # delay stream heartbeats or watchdog work.
        result = redis_client.blpop(queues, timeout=1)
        if not result:
            return None
        queue_name, payload = result
        return QueueLease(queue_name=_text(queue_name), payload=_text(payload))
    key, message_id, payload = messages[0]
    queue_name = next((name for name in queues if stream_key(name) == key), queues[0])
    return QueueLease(
        queue_name=queue_name,
        payload=payload,
        stream_key=key,
        message_id=message_id,
        delivery_attempts=_delivery_attempts(redis_client, key, message_id),
    )


def heartbeat_lease(redis_client: Any, lease: QueueLease, consumer_name: str) -> bool:
    if lease.legacy or not lease.stream_key or not lease.message_id:
        return True
    claimed = redis_client.xclaim(
        lease.stream_key,
        CONSUMER_GROUP,
        consumer_name,
        min_idle_time=0,
        message_ids=[lease.message_id],
        idle=0,
        justid=True,
    )
    return lease.message_id in {_text(item) for item in (claimed or [])}


def acknowledge_lease(redis_client: Any, lease: QueueLease) -> bool:
    if lease.legacy or not lease.stream_key or not lease.message_id:
        return True
    acknowledged = int(redis_client.xack(lease.stream_key, CONSUMER_GROUP, lease.message_id) or 0)
    if acknowledged:
        redis_client.xdel(lease.stream_key, lease.message_id)
    return bool(acknowledged)


def queue_payloads(redis_client: Any, queue_name: str, *, include_leased: bool = True) -> list[str]:
    payloads: list[str] = []
    if _has_streams(redis_client):
        key = stream_key(queue_name)
        try:
            rows = redis_client.xrange(key, min="-", max="+") or []
        except Exception:
            rows = []
        if rows and not include_leased:
            pending_rows = redis_client.xpending_range(
                key,
                CONSUMER_GROUP,
                min="-",
                max="+",
                count=max(1, len(rows)),
            )
            leased_ids = {
                _text(row.get("message_id") or row.get(b"message_id"))
                for row in pending_rows
            }
            rows = [row for row in rows if _text(row[0]) not in leased_ids]
        payloads.extend(payload for _, _, payload in _decode_messages([(key, rows)]))
    try:
        payloads.extend(_text(value) for value in (redis_client.lrange(queue_name, 0, -1) or []))
    except Exception:
        pass
    return payloads


def pending_depth(redis_client: Any, queue_name: str) -> int:
    """Return work not yet leased, including pre-upgrade list entries."""
    legacy = int(redis_client.llen(queue_name) or 0)
    if not _has_streams(redis_client):
        return legacy
    key = stream_key(queue_name)
    try:
        total = int(redis_client.xlen(key) or 0)
        pending = redis_client.xpending(key, CONSUMER_GROUP)
        leased = int((pending or {}).get("pending") or (pending or {}).get(b"pending") or 0)
        return legacy + max(0, total - leased)
    except Exception:
        return legacy


def clear_unleased(redis_client: Any, queue_name: str) -> list[str]:
    """Delete pending-but-not-leased work and return its JSON payloads."""
    deleted: list[str] = []
    if _has_streams(redis_client):
        key = stream_key(queue_name)
        try:
            rows = redis_client.xrange(key, min="-", max="+") or []
            pending_rows = redis_client.xpending_range(
                key,
                CONSUMER_GROUP,
                min="-",
                max="+",
                count=max(1, len(rows)),
            ) if rows else []
            leased_ids = {
                _text(row.get("message_id") or row.get(b"message_id"))
                for row in pending_rows
            }
            for message_id, fields in rows:
                normalized_id = _text(message_id)
                if normalized_id in leased_ids:
                    continue
                payload = {_text(k): _text(v) for k, v in fields.items()}.get(PAYLOAD_FIELD)
                if payload and redis_client.xdel(key, normalized_id):
                    deleted.append(payload)
        except Exception:
            raise
    legacy_payloads = [_text(value) for value in (redis_client.lrange(queue_name, 0, -1) or [])]
    if legacy_payloads:
        redis_client.delete(queue_name)
        deleted.extend(legacy_payloads)
    return deleted
