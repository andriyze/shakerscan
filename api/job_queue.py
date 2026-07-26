"""Reliable Redis Stream queue primitives with legacy-list upgrade compatibility.

Producers write one JSON payload field to a stream. Workers consume through one
consumer group, explicitly acknowledge completed work, refresh pending-message
idle time while running, and reclaim abandoned deliveries after the visibility
timeout. Legacy Redis-list entries are still readable during an upgrade, but no
new production enqueue uses the list path.
"""

from __future__ import annotations

import json
import hashlib
import os
from dataclasses import dataclass
from typing import Any, Iterable


CONSUMER_GROUP = os.environ.get("SHAKERSCAN_QUEUE_CONSUMER_GROUP", "shakerscan-workers")
STREAM_SUFFIX = ":leased"
PAYLOAD_FIELD = "payload"
ROUTE_SET_PREFIX = "shakerscan:queue-routes:"
ROUTE_REQUIREMENTS_PREFIX = "shakerscan:queue-route-requirements:"
DEFAULT_ROUTE_REGISTRY_MAX = 512
PLACEMENT_SCALAR_KEYS = {
    "region",
    "egress_group",
    "network",
    "scan_tier",
    "tier",
    "data_residency",
    "node_id",
}
DEFAULT_WORKER_TOOL_COMMANDS = {
    "nuclei": "nuclei",
    "playwright": "node",
    "sqlmap": "sqlmap",
    "nmap": "nmap",
    "subfinder": "subfinder",
}

_HEARTBEAT_LEASE_LUA = """
-- shakerscan:heartbeat-owned-lease
local rows = redis.call('XPENDING', KEYS[1], ARGV[1], ARGV[2], ARGV[2], 1)
if #rows ~= 1 or tostring(rows[1][2]) ~= ARGV[3] then
  return 0
end
local claimed = redis.call('XCLAIM', KEYS[1], ARGV[1], ARGV[3], 0, ARGV[2], 'IDLE', 0, 'JUSTID')
if #claimed == 1 and tostring(claimed[1]) == ARGV[2] then
  return 1
end
return 0
"""

_ACK_DELETE_LUA = """
-- shakerscan:ack-delete
local acknowledged = redis.call('XACK', KEYS[1], ARGV[1], ARGV[2])
if acknowledged ~= 1 then
  return 0
end
redis.call('XDEL', KEYS[1], ARGV[2])
if #KEYS == 4 and redis.call('XLEN', KEYS[1]) == 0 and redis.call('LLEN', KEYS[4]) == 0 then
  redis.call('SREM', KEYS[2], ARGV[3])
  redis.call('DEL', KEYS[3])
  redis.call('DEL', KEYS[1])
end
return 1
"""

_ROUTED_ENQUEUE_LUA = """
-- shakerscan:routed-enqueue
if redis.call('SISMEMBER', KEYS[1], ARGV[1]) == 0 then
  if redis.call('SCARD', KEYS[1]) >= tonumber(ARGV[4]) then
    return redis.error_reply('SHAKERSCAN_ROUTE_CAPACITY_EXCEEDED')
  end
  redis.call('SADD', KEYS[1], ARGV[1])
end
redis.call('SET', KEYS[2], ARGV[2])
return redis.call('XADD', KEYS[3], '*', 'payload', ARGV[3])
"""

_PRUNE_EMPTY_ROUTE_LUA = """
-- shakerscan:prune-empty-route
if redis.call('XLEN', KEYS[1]) ~= 0 or redis.call('LLEN', KEYS[4]) ~= 0 then
  return 0
end
redis.call('SREM', KEYS[2], ARGV[1])
redis.call('DEL', KEYS[3])
redis.call('DEL', KEYS[1])
return 1
"""

_CLEAN_ORPHANED_ROUTE_STREAM_LUA = """
-- shakerscan:clean-orphaned-route-stream
if redis.call('SISMEMBER', KEYS[1], ARGV[1]) == 1 then
  return 1
end
if redis.call('XLEN', KEYS[2]) == 0 then
  redis.call('DEL', KEYS[2])
end
return 0
"""


class RouteCapacityExceeded(RuntimeError):
    def __init__(self, queue_name: str, limit: int):
        super().__init__(f"route registry for {queue_name} reached its {limit}-route capacity")
        self.queue_name = queue_name
        self.limit = limit


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


def normalize_placement(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    normalized: dict[str, Any] = {}
    for key in sorted(PLACEMENT_SCALAR_KEYS):
        raw = value.get(key)
        if raw is None:
            continue
        text = str(raw).strip().lower()
        if text:
            normalized[key] = text[:128]
    requires = value.get("requires")
    if isinstance(requires, str):
        requires = [requires]
    if isinstance(requires, list):
        clean = sorted({str(item).strip().lower()[:64] for item in requires if str(item).strip()})
        if clean:
            normalized["requires"] = clean[:32]
    return normalized


def placement_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    direct = payload.get("placement")
    options = payload.get("options") if isinstance(payload.get("options"), dict) else {}
    return normalize_placement(direct if isinstance(direct, dict) else options.get("placement"))


def route_set_key(queue_name: str) -> str:
    return f"{ROUTE_SET_PREFIX}{queue_name}"


def route_requirements_key(routed_queue: str) -> str:
    return f"{ROUTE_REQUIREMENTS_PREFIX}{routed_queue}"


def route_registry_max() -> int:
    try:
        configured = int(os.environ.get("SHAKERSCAN_QUEUE_ROUTE_MAX", DEFAULT_ROUTE_REGISTRY_MAX))
    except (TypeError, ValueError):
        configured = DEFAULT_ROUTE_REGISTRY_MAX
    return max(16, min(configured, 4096))


def _route_base(queue_name: str) -> str | None:
    base, separator, _digest = queue_name.partition(":route:")
    return base if separator and base else None


def _prune_empty_route(redis_client: Any, routed_queue: str) -> bool:
    base = _route_base(routed_queue)
    if not base:
        return False
    evaluator = getattr(redis_client, "eval", None)
    if not callable(evaluator):
        return False
    return bool(evaluator(
        _PRUNE_EMPTY_ROUTE_LUA,
        4,
        stream_key(routed_queue),
        route_set_key(base),
        route_requirements_key(routed_queue),
        routed_queue,
        routed_queue,
    ))


def routed_queue_name(queue_name: str, placement: dict[str, Any]) -> str:
    canonical = json.dumps(normalize_placement(placement), sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
    return f"{queue_name}:route:{digest}"


def worker_matches_placement(worker: dict[str, Any], placement: dict[str, Any]) -> bool:
    labels = {str(key): value for key, value in (worker or {}).items()}
    for key in PLACEMENT_SCALAR_KEYS:
        required = placement.get(key)
        if not required:
            continue
        worker_key = "scan_tiers" if key in {"scan_tier", "tier"} else key
        actual = labels.get(worker_key)
        if isinstance(actual, (list, tuple, set)):
            if str(required).lower() not in {str(item).lower() for item in actual}:
                return False
        elif str(actual or "").strip().lower() != str(required).lower():
            return False
    required_tools = {str(item).lower() for item in placement.get("requires") or []}
    tools = labels.get("tools") or labels.get("capabilities") or []
    if isinstance(tools, str):
        tools = [tools]
    return required_tools.issubset({str(item).lower() for item in tools})


def qualified_route_queues(
    redis_client: Any,
    queue_names: Iterable[str],
    *,
    worker_labels: dict[str, Any],
) -> list[str]:
    qualified: list[str] = []
    if not callable(getattr(redis_client, "smembers", None)):
        return qualified
    for base in queue_names:
        try:
            routes = redis_client.smembers(route_set_key(base)) or []
        except Exception:
            continue
        for raw_route in routes:
            route = _text(raw_route)
            try:
                raw = redis_client.get(route_requirements_key(route))
                placement = normalize_placement(json.loads(_text(raw))) if raw else {}
            except Exception:
                continue
            if placement and worker_matches_placement(worker_labels, placement):
                qualified.append(route)
    return list(dict.fromkeys(qualified))


def _known_routes(redis_client: Any, queue_name: str) -> list[str]:
    if ":route:" in queue_name or not callable(getattr(redis_client, "smembers", None)):
        return []
    try:
        routes = [_text(item) for item in (redis_client.smembers(route_set_key(queue_name)) or [])]
        return [route for route in routes if not _prune_empty_route(redis_client, route)]
    except Exception:
        return []


def _prune_route_registry_at_capacity(redis_client: Any, queue_name: str) -> None:
    if not callable(getattr(redis_client, "smembers", None)):
        return
    try:
        routes = [_text(item) for item in (redis_client.smembers(route_set_key(queue_name)) or [])]
    except Exception:
        return
    if len(routes) < route_registry_max():
        return
    for route in routes:
        _prune_empty_route(redis_client, route)


def _text(value: Any) -> str:
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)


def _has_streams(redis_client: Any) -> bool:
    # Narrow test doubles from older queue tests intentionally exercise the
    # upgrade fallback. Real redis-py clients always expose these methods.
    return callable(getattr(redis_client, "xadd", None)) and callable(
        getattr(redis_client, "xreadgroup", None)
    )


def ensure_consumer_group(redis_client: Any, queue_name: str) -> bool:
    if not _has_streams(redis_client):
        return True
    try:
        redis_client.xgroup_create(stream_key(queue_name), CONSUMER_GROUP, id="0-0", mkstream=True)
    except Exception as exc:
        if "BUSYGROUP" not in str(exc):
            raise
    base = _route_base(queue_name)
    if not base:
        return True
    evaluator = getattr(redis_client, "eval", None)
    if callable(evaluator):
        return bool(evaluator(
            _CLEAN_ORPHANED_ROUTE_STREAM_LUA,
            2,
            route_set_key(base),
            stream_key(queue_name),
            queue_name,
        ))
    try:
        registered = queue_name in {
            _text(item) for item in (redis_client.smembers(route_set_key(base)) or [])
        }
        if not registered and int(redis_client.xlen(stream_key(queue_name)) or 0) == 0:
            redis_client.delete(stream_key(queue_name))
        return registered
    except Exception:
        return False


def enqueue_job(redis_client: Any, queue_name: str, payload: str | dict[str, Any]) -> str:
    routed_queue = queue_name
    normalized_payload: str | dict[str, Any] = payload
    if isinstance(payload, dict):
        placement = placement_from_payload(payload)
        if placement and callable(getattr(redis_client, "sadd", None)):
            _prune_route_registry_at_capacity(redis_client, queue_name)
            routed_queue = routed_queue_name(queue_name, placement)
            normalized_payload = dict(payload)
            normalized_payload["placement"] = placement
            normalized_payload["_base_queue_name"] = queue_name
            canonical = json.dumps(placement, sort_keys=True, separators=(",", ":"))
            if not _has_streams(redis_client) or not callable(getattr(redis_client, "eval", None)):
                routes = {
                    _text(item) for item in (redis_client.smembers(route_set_key(queue_name)) or [])
                }
                existing = routed_queue in routes
                if not existing and len(routes) >= route_registry_max():
                    raise RouteCapacityExceeded(queue_name, route_registry_max())
                redis_client.sadd(route_set_key(queue_name), routed_queue)
                redis_client.set(route_requirements_key(routed_queue), canonical)
    encoded = normalized_payload if isinstance(normalized_payload, str) else json.dumps(normalized_payload)
    if not _has_streams(redis_client):
        redis_client.rpush(routed_queue, encoded)
        return "legacy-list"
    if routed_queue != queue_name and callable(getattr(redis_client, "eval", None)):
        try:
            message_id = redis_client.eval(
                _ROUTED_ENQUEUE_LUA,
                3,
                route_set_key(queue_name),
                route_requirements_key(routed_queue),
                stream_key(routed_queue),
                routed_queue,
                canonical,
                encoded,
                route_registry_max(),
            )
        except Exception as exc:
            if "SHAKERSCAN_ROUTE_CAPACITY_EXCEEDED" in str(exc):
                raise RouteCapacityExceeded(queue_name, route_registry_max()) from exc
            raise
        ensure_consumer_group(redis_client, routed_queue)
        return _text(message_id)
    ensure_consumer_group(redis_client, routed_queue)
    return _text(redis_client.xadd(stream_key(routed_queue), {PAYLOAD_FIELD: encoded}))


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

    queues = [queue_name for queue_name in queues if ensure_consumer_group(redis_client, queue_name)]
    if not queues:
        return None

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
    evaluator = getattr(redis_client, "eval", None)
    if callable(evaluator):
        return bool(evaluator(
            _HEARTBEAT_LEASE_LUA,
            1,
            lease.stream_key,
            CONSUMER_GROUP,
            lease.message_id,
            consumer_name,
        ))
    rows = redis_client.xpending_range(
        lease.stream_key,
        CONSUMER_GROUP,
        min=lease.message_id,
        max=lease.message_id,
        count=1,
    )
    if not rows or _text(rows[0].get("consumer") or rows[0].get(b"consumer")) != consumer_name:
        return False
    claimed = redis_client.xclaim(
        lease.stream_key, CONSUMER_GROUP, consumer_name,
        min_idle_time=0, message_ids=[lease.message_id], idle=0, justid=True,
    )
    return lease.message_id in {_text(item) for item in (claimed or [])}


def acknowledge_lease(redis_client: Any, lease: QueueLease) -> bool:
    if lease.legacy or not lease.stream_key or not lease.message_id:
        return True
    evaluator = getattr(redis_client, "eval", None)
    base = _route_base(lease.queue_name)
    if callable(evaluator):
        keys = [lease.stream_key]
        arguments = [CONSUMER_GROUP, lease.message_id, lease.queue_name]
        if base:
            keys.extend([route_set_key(base), route_requirements_key(lease.queue_name), lease.queue_name])
        return bool(evaluator(_ACK_DELETE_LUA, len(keys), *keys, *arguments))
    acknowledged = int(redis_client.xack(lease.stream_key, CONSUMER_GROUP, lease.message_id) or 0)
    if acknowledged:
        redis_client.xdel(lease.stream_key, lease.message_id)
    return bool(acknowledged)


def queue_payloads(redis_client: Any, queue_name: str, *, include_leased: bool = True) -> list[str]:
    payloads: list[str] = []
    variants = [queue_name, *_known_routes(redis_client, queue_name)]
    for variant in variants:
        payloads.extend(_queue_payloads_one(redis_client, variant, include_leased=include_leased))
    return payloads


def _queue_payloads_one(redis_client: Any, queue_name: str, *, include_leased: bool) -> list[str]:
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
    return sum(_pending_depth_one(redis_client, name) for name in [queue_name, *_known_routes(redis_client, queue_name)])


def _pending_depth_one(redis_client: Any, queue_name: str) -> int:
    try:
        legacy = int(redis_client.llen(queue_name) or 0)
    except Exception:
        legacy = 0
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
    variants = [queue_name, *_known_routes(redis_client, queue_name)]
    for variant in variants:
        deleted.extend(_clear_unleased_one(redis_client, variant))
        _prune_empty_route(redis_client, variant)
    return deleted


def _clear_unleased_one(redis_client: Any, queue_name: str) -> list[str]:
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
