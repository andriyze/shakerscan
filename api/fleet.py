"""Owned-fleet enrollment and node identity primitives.

This module deliberately contains no WireGuard or Docker mutation.  It provides the
durable, fail-closed trust foundation used by the Phase-1 fleet API; host networking
and worker startup remain explicit later milestones.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import secrets
import urllib.parse
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping


OVERLAY_ALLOCATION_LOCK = 8_675_310
MAX_OVERLAY_ADDRESSES = 65_536
MAX_WORKERS_PER_NODE = 128


class FleetConfigurationError(ValueError):
    """Fleet configuration is absent or unsafe."""


class FleetEnrollmentError(ValueError):
    """Enrollment material is invalid, expired, or already consumed."""


class FleetAuthenticationError(ValueError):
    """A node credential is missing or invalid."""


class FleetConflictError(ValueError):
    """The requested fleet lifecycle transition cannot be completed."""


@dataclass(frozen=True)
class FleetBootstrapConfig:
    overlay_cidr: str
    control_plane_overlay_url: str
    control_plane_wireguard_public_key: str
    control_plane_wireguard_endpoint: str
    worker_image_digest: str
    desired_worker_count: int = 1

    def validated(self) -> "FleetBootstrapConfig":
        network = parse_overlay_network(self.overlay_cidr)
        if network.num_addresses < 4:
            raise FleetConfigurationError("FLEET_OVERLAY_CIDR must provide worker addresses")
        overlay_url = urllib.parse.urlparse(self.control_plane_overlay_url)
        if overlay_url.scheme != "https" or not overlay_url.hostname or overlay_url.username or overlay_url.password:
            raise FleetConfigurationError("FLEET_CONTROL_PLANE_OVERLAY_URL must use HTTPS")
        validate_wireguard_public_key(self.control_plane_wireguard_public_key)
        if not self.control_plane_wireguard_endpoint.strip():
            raise FleetConfigurationError("FLEET_WIREGUARD_ENDPOINT is required")
        image_name, separator, digest = self.worker_image_digest.rpartition("@sha256:")
        if not separator or not image_name or len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest.lower()):
            raise FleetConfigurationError("FLEET_WORKER_IMAGE_DIGEST must be digest-pinned")
        if not 1 <= int(self.desired_worker_count) <= 128:
            raise FleetConfigurationError("FLEET_DESIRED_WORKER_COUNT must be between 1 and 128")
        return self


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def generate_secret(prefix: str) -> str:
    return f"{prefix}{secrets.token_urlsafe(32)}"


def hash_secret(secret: str, purpose: str) -> str:
    """Hash a high-entropy secret with domain separation; raw values are never stored."""
    if not secret or not isinstance(secret, str):
        raise ValueError("secret is required")
    material = f"shakerscan:{purpose}:v1\0{secret}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def validate_wireguard_public_key(value: str) -> str:
    candidate = str(value or "").strip()
    try:
        decoded = base64.b64decode(candidate, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise FleetEnrollmentError("wireguard_public_key must be valid base64") from exc
    if len(decoded) != 32:
        raise FleetEnrollmentError("wireguard_public_key must encode exactly 32 bytes")
    return candidate


def parse_overlay_network(value: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(str(value or ""), strict=True)
    except ValueError as exc:
        raise FleetConfigurationError("FLEET_OVERLAY_CIDR must be a canonical IPv4 CIDR") from exc
    if not isinstance(network, ipaddress.IPv4Network):
        raise FleetConfigurationError("Phase-1 fleet overlay must use IPv4")
    if network.num_addresses > MAX_OVERLAY_ADDRESSES:
        raise FleetConfigurationError("FLEET_OVERLAY_CIDR may contain at most 65536 addresses")
    return network


def normalize_json_object(value: Mapping[str, Any] | None, *, max_bytes: int, field: str) -> dict[str, Any]:
    result = dict(value or {})
    encoded = json.dumps(result, separators=(",", ":"), sort_keys=True)
    if len(encoded.encode("utf-8")) > max_bytes:
        raise FleetEnrollmentError(f"{field} exceeds {max_bytes} bytes")
    return result


def distribute_worker_count(
    nodes: list[Mapping[str, Any]],
    desired_worker_count: int,
) -> dict[str, int]:
    """Distribute a fleet worker target proportionally and deterministically.

    CPU count is the default capacity weight. Operators can report a positive
    ``worker_weight`` and a bounded ``max_workers`` in node capacity when CPU
    count is not a useful proxy (for example memory-heavy browser nodes).
    D'Hondt allocation provides stable integer shares and naturally redistributes
    around per-node caps.
    """
    desired = int(desired_worker_count)
    if desired < 0:
        raise FleetEnrollmentError("desired_worker_count must be non-negative")
    entries: list[tuple[str, float, int]] = []
    for node in nodes:
        node_id = str(node.get("id") or "").strip()
        if not node_id:
            raise FleetEnrollmentError("fleet scale candidate is missing node identity")
        capacity = node.get("capacity") or {}
        if isinstance(capacity, str):
            try:
                capacity = json.loads(capacity)
            except json.JSONDecodeError:
                capacity = {}
        if not isinstance(capacity, Mapping):
            capacity = {}
        try:
            weight = float(capacity.get("worker_weight") or capacity.get("cpu_count") or 1)
        except (TypeError, ValueError):
            weight = 1.0
        if weight <= 0 or weight != weight:
            weight = 1.0
        weight = min(weight, 4096.0)
        try:
            cap = int(capacity.get("max_workers", MAX_WORKERS_PER_NODE))
        except (TypeError, ValueError):
            cap = MAX_WORKERS_PER_NODE
        cap = max(0, min(MAX_WORKERS_PER_NODE, cap))
        entries.append((node_id, weight, cap))
    allocations = {node_id: 0 for node_id, _weight, _cap in entries}
    total_capacity = sum(cap for _node_id, _weight, cap in entries)
    if desired > total_capacity:
        raise FleetConflictError(
            f"requested {desired} workers exceeds eligible fleet capacity {total_capacity}"
        )
    # Give each usable node one worker before proportional expansion whenever
    # the target is large enough. This avoids permanently starving small nodes
    # while still choosing the largest-capacity nodes first for tiny totals.
    remaining = desired
    for node_id, _weight, cap in sorted(entries, key=lambda item: (-item[1], item[0])):
        if remaining <= 0:
            break
        if cap > 0:
            allocations[node_id] = 1
            remaining -= 1
    # Highest quotient wins each integer worker. Stable node identity is the
    # final tie-break, so repeated plans over the same inputs are identical.
    for _ in range(remaining):
        candidates = [
            (weight / (allocations[node_id] + 1), node_id)
            for node_id, weight, cap in entries
            if allocations[node_id] < cap
        ]
        if not candidates:
            raise FleetConflictError("eligible fleet capacity was exhausted")
        _quotient, selected = max(candidates, key=lambda item: (item[0], item[1]))
        allocations[selected] += 1
    return allocations


async def record_node_event(
    conn: Any,
    *,
    node_id: str | uuid.UUID | None,
    event_type: str,
    actor_type: str,
    details: Mapping[str, Any] | None = None,
    severity: str = "info",
) -> None:
    """Persist a bounded, credential-free fleet lifecycle event."""
    clean_event = str(event_type or "").strip().lower()
    clean_actor = str(actor_type or "").strip().lower()
    clean_severity = str(severity or "info").strip().lower()
    if not clean_event or len(clean_event) > 80:
        raise FleetEnrollmentError("fleet event type is invalid")
    if clean_actor not in {"operator", "node", "system", "broker"}:
        raise FleetEnrollmentError("fleet event actor type is invalid")
    if clean_severity not in {"info", "warning", "error"}:
        raise FleetEnrollmentError("fleet event severity is invalid")
    safe_details = normalize_json_object(details, max_bytes=16_384, field="fleet event details")
    parsed_node_id = uuid.UUID(str(node_id)) if node_id is not None else None
    await conn.execute(
        """
        INSERT INTO fleet_node_events (node_id, event_type, actor_type, severity, details)
        VALUES ($1,$2,$3,$4,$5::jsonb)
        """,
        parsed_node_id,
        clean_event,
        clean_actor,
        clean_severity,
        json.dumps(safe_details, sort_keys=True, separators=(",", ":"), default=str),
    )


def socket_peer_is_overlay(peer_host: str | None, overlay_cidr: str) -> bool:
    if not peer_host:
        return False
    try:
        peer = ipaddress.ip_address(peer_host)
    except ValueError:
        return False
    return peer in parse_overlay_network(overlay_cidr)


async def create_join_token(conn: Any, *, role: str = "worker", ttl_seconds: int = 3600) -> dict[str, Any]:
    if role != "worker":
        raise FleetEnrollmentError("only worker join tokens are supported")
    if not 60 <= int(ttl_seconds) <= 604_800:
        raise FleetEnrollmentError("join token TTL must be between 60 seconds and 7 days")
    raw_token = generate_secret("ssj_")
    expires_at = utcnow() + timedelta(seconds=int(ttl_seconds))
    await conn.execute(
        """
        INSERT INTO node_join_tokens (token_hash, role, expires_at)
        VALUES ($1, $2, $3)
        """,
        hash_secret(raw_token, "join-token"),
        role,
        expires_at,
    )
    return {"token": raw_token, "role": role, "expires_at": expires_at}


async def _allocate_overlay_ip(conn: Any, overlay_cidr: str) -> str:
    network = parse_overlay_network(overlay_cidr)
    await conn.execute("SELECT pg_advisory_xact_lock($1)", OVERLAY_ALLOCATION_LOCK)
    rows = await conn.fetch("SELECT overlay_ip::text AS overlay_ip FROM nodes WHERE overlay_ip IS NOT NULL")
    used = {str(row["overlay_ip"]).split("/")[0] for row in rows}
    hosts = network.hosts()
    next(hosts, None)  # reserve the first usable address for the control plane
    for candidate in hosts:
        text = str(candidate)
        if text not in used:
            return text
    raise FleetConflictError("fleet overlay address pool is exhausted")


async def enroll_node(
    conn: Any,
    *,
    token: str,
    name: str,
    hostname: str | None,
    region: str | None,
    wireguard_public_key: str | None,
    labels: Mapping[str, Any] | None,
    capacity: Mapping[str, Any] | None,
    build_fingerprint: str | None,
    config: FleetBootstrapConfig,
    transport: str = "overlay",
) -> dict[str, Any]:
    normalized_transport = str(transport or "overlay").strip().lower()
    if normalized_transport not in {"overlay", "broker"}:
        raise FleetEnrollmentError("transport must be overlay or broker")
    if normalized_transport == "overlay":
        config.validated()
    else:
        image_name, separator, digest = str(config.worker_image_digest or "").rpartition("@sha256:")
        if not separator or not image_name or len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest.lower()):
            raise FleetConfigurationError("FLEET_WORKER_IMAGE_DIGEST must be digest-pinned")
        if not 1 <= int(config.desired_worker_count) <= 128:
            raise FleetConfigurationError("FLEET_DESIRED_WORKER_COUNT must be between 1 and 128")
    public_key = (
        validate_wireguard_public_key(str(wireguard_public_key or ""))
        if normalized_transport == "overlay"
        else None
    )
    safe_labels = normalize_json_object(labels, max_bytes=8192, field="labels")
    safe_labels["transport"] = normalized_transport
    safe_capacity = normalize_json_object(capacity, max_bytes=8192, field="capacity")
    clean_name = str(name or "").strip()
    if not clean_name or len(clean_name) > 128:
        raise FleetEnrollmentError("name must contain 1 to 128 characters")

    token_row = await conn.fetchrow(
        """
        UPDATE node_join_tokens
        SET consumed_at = NOW()
        WHERE token_hash = $1
          AND consumed_at IS NULL
          AND expires_at > NOW()
        RETURNING role
        """,
        hash_secret(token, "join-token"),
    )
    if not token_row:
        raise FleetEnrollmentError("join token is invalid, expired, or already consumed")

    overlay_ip = (
        await _allocate_overlay_ip(conn, config.overlay_cidr)
        if normalized_transport == "overlay"
        else None
    )
    node_id = uuid.uuid4()
    raw_credential = generate_secret("ssn_")
    try:
        await conn.execute(
            """
            INSERT INTO nodes (
                id, name, hostname, role, overlay_ip, wireguard_public_key,
                region, labels, capacity, build_fingerprint, worker_image_digest,
                desired_worker_count, status
            ) VALUES ($1, $2, $3, $4, $5::inet, $6, $7, $8::jsonb, $9::jsonb, $10, $11, $12, 'joining')
            """,
            node_id,
            clean_name,
            str(hostname or "").strip() or None,
            str(token_row["role"]),
            overlay_ip,
            public_key,
            str(region or "").strip()[:128] or None,
            json.dumps(safe_labels),
            json.dumps(safe_capacity),
            str(build_fingerprint or "").strip() or None,
            config.worker_image_digest,
            int(config.desired_worker_count),
        )
    except Exception as exc:
        # The surrounding transaction rolls token consumption back too.
        if getattr(exc, "constraint_name", None) == "nodes_wireguard_public_key_key":
            raise FleetConflictError("wireguard_public_key is already enrolled") from exc
        raise

    await conn.execute(
        """
        INSERT INTO node_credentials (node_id, credential_hash, credential_version)
        VALUES ($1, $2, 1)
        """,
        node_id,
        hash_secret(raw_credential, "node-credential"),
    )
    await record_node_event(
        conn,
        node_id=node_id,
        event_type="node_joined",
        actor_type="node",
        details={
            "transport": normalized_transport,
            "region": str(region or "").strip()[:128] or None,
            "desired_worker_count": int(config.desired_worker_count),
            "worker_image_digest": config.worker_image_digest,
        },
    )
    return {
        "node_id": str(node_id),
        "transport": normalized_transport,
        "control_plane_overlay_url": config.control_plane_overlay_url,
        "wireguard_overlay_cidr": config.overlay_cidr,
        "worker_image_digest": config.worker_image_digest,
        "desired_worker_count": int(config.desired_worker_count),
        "labels": safe_labels,
        "wireguard_peer_ip": overlay_ip,
        "wireguard_control_plane_public_key": config.control_plane_wireguard_public_key,
        "wireguard_control_plane_endpoint": config.control_plane_wireguard_endpoint,
        "node_credential": raw_credential,
    }


async def authenticate_node(conn: Any, *, node_id: str, credential: str) -> dict[str, Any]:
    try:
        parsed_id = uuid.UUID(str(node_id))
    except ValueError as exc:
        raise FleetAuthenticationError("invalid node identity") from exc
    row = await conn.fetchrow(
        """
        SELECT n.*, c.id AS credential_id, c.credential_version
        FROM nodes n
        JOIN node_credentials c ON c.node_id = n.id
        WHERE n.id = $1
          AND c.credential_hash = $2
          AND c.revoked_at IS NULL
          AND (c.expires_at IS NULL OR c.expires_at > NOW())
          AND n.status <> 'disabled'
        ORDER BY c.credential_version DESC
        LIMIT 1
        """,
        parsed_id,
        hash_secret(credential, "node-credential"),
    )
    if not row:
        raise FleetAuthenticationError("invalid or revoked node credential")
    await conn.execute("UPDATE node_credentials SET last_used_at = NOW() WHERE id = $1", row["credential_id"])
    return dict(row)


async def record_heartbeat(
    conn: Any,
    *,
    node_id: str,
    active_worker_count: int,
    capacity: Mapping[str, Any] | None,
    build_fingerprint: str | None,
    active_worker_image_digest: str | None,
    agent_version: str | None,
    applied_state_version: int,
    last_error: str | None,
    egress_ip: str | None,
) -> dict[str, Any]:
    safe_capacity = normalize_json_object(capacity, max_bytes=8192, field="capacity")
    if not 0 <= int(active_worker_count) <= 128:
        raise FleetEnrollmentError("active_worker_count must be between 0 and 128")
    if not 0 <= int(applied_state_version) <= 2_147_483_647:
        raise FleetEnrollmentError("applied_state_version is invalid")
    if egress_ip:
        try:
            ipaddress.ip_address(egress_ip)
        except ValueError as exc:
            raise FleetEnrollmentError("egress_ip must be an IP address") from exc
    row = await conn.fetchrow(
        """
        UPDATE nodes
        SET active_worker_count = $2::integer,
            capacity = $3::jsonb,
            build_fingerprint = COALESCE($4::text, build_fingerprint),
            active_worker_image_digest = COALESCE($5::text, active_worker_image_digest),
            agent_version = COALESCE($6::text, agent_version),
            applied_state_version = $7::integer,
            last_error = $8::text,
            egress_ip = COALESCE($9::inet, egress_ip),
            status = CASE
                WHEN drain THEN 'draining'
                WHEN $8::text IS NOT NULL OR $7::integer < desired_state_version THEN 'joining'
                ELSE 'healthy'
            END,
            last_heartbeat_at = NOW(),
            updated_at = NOW()
        WHERE id = $1 AND status <> 'disabled'
        RETURNING id, status, desired_worker_count, last_heartbeat_at
        """,
        uuid.UUID(str(node_id)),
        int(active_worker_count),
        json.dumps(safe_capacity),
        str(build_fingerprint or "").strip() or None,
        str(active_worker_image_digest or "").strip() or None,
        str(agent_version or "").strip()[:64] or None,
        int(applied_state_version),
        str(last_error or "").strip()[:2000] or None,
        egress_ip,
    )
    if not row:
        raise FleetConflictError("node is disabled or no longer exists")
    return dict(row)


async def consume_connection_bundle(conn: Any, *, node_id: str) -> None:
    row = await conn.fetchrow(
        """
        UPDATE nodes
        SET connection_bundle_delivered_at = NOW(), updated_at = NOW()
        WHERE id = $1
          AND status <> 'disabled'
          AND connection_bundle_delivered_at IS NULL
        RETURNING id
        """,
        uuid.UUID(str(node_id)),
    )
    if not row:
        raise FleetConflictError("connection bundle was already delivered or node is disabled")


def public_node(row: Mapping[str, Any], *, stale_after_seconds: int) -> dict[str, Any]:
    public_fields = {
        "id", "name", "hostname", "role", "overlay_ip", "wireguard_public_key",
        "egress_ip", "region", "labels", "build_fingerprint", "worker_image_digest",
        "active_worker_image_digest", "agent_version", "desired_state_version",
        "applied_state_version", "last_error", "desired_worker_count",
        "active_worker_count", "capacity", "status", "drain", "rollout_in_progress",
        "last_heartbeat_at", "connection_bundle_delivered_at", "created_at", "updated_at",
    }
    result = {key: value for key, value in dict(row).items() if key in public_fields}
    last_heartbeat = result.get("last_heartbeat_at")
    status = str(result.get("status") or "joining")
    now = utcnow()
    if last_heartbeat and getattr(last_heartbeat, "tzinfo", None) is None:
        last_heartbeat = last_heartbeat.replace(tzinfo=timezone.utc)
    if status not in {"disabled", "draining"} and (
        last_heartbeat is None or (now - last_heartbeat).total_seconds() > stale_after_seconds
    ):
        status = "stale"
    elif status not in {"disabled", "draining"} and result.get("last_error"):
        # Keep the durable schema's convergence state compact, but do not present
        # a reliably heartbeating reconciliation failure as ordinary "joining".
        status = "unhealthy"
    result["status"] = status
    desired_version = int(result.get("desired_state_version") or 1)
    applied_version = int(result.get("applied_state_version") or 0)
    result["state_current"] = applied_version >= desired_version and not bool(result.get("last_error"))
    desired_image = str(result.get("worker_image_digest") or "").strip()
    active_image = str(result.get("active_worker_image_digest") or "").strip()
    result["image_current"] = bool(desired_image and active_image and desired_image == active_image)
    result["id"] = str(result["id"])
    for key in ("labels", "capacity"):
        if isinstance(result.get(key), str):
            try:
                result[key] = json.loads(result[key])
            except json.JSONDecodeError:
                result[key] = {}
    labels = result.get("labels") if isinstance(result.get("labels"), dict) else {}
    transport = str(labels.get("transport") or ("overlay" if result.get("overlay_ip") else "broker"))
    result["wireguard_connection_pending"] = bool(
        transport == "overlay"
        and status != "disabled"
        and result.get("last_heartbeat_at") is None
        and result.get("connection_bundle_delivered_at") is None
    )
    result.pop("connection_bundle_delivered_at", None)
    for key, value in list(result.items()):
        if isinstance(value, (datetime, ipaddress.IPv4Address, ipaddress.IPv6Address)):
            result[key] = value.isoformat() if isinstance(value, datetime) else str(value)
    return result
