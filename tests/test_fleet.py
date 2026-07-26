import base64
import asyncio
import json
import os
import sys
import uuid
from datetime import timedelta

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from fleet import (  # noqa: E402
    FleetBootstrapConfig,
    FleetConflictError,
    FleetEnrollmentError,
    consume_connection_bundle,
    create_join_token,
    distribute_worker_count,
    enroll_node,
    hash_secret,
    public_node,
    record_heartbeat,
    revoke_join_token,
    socket_peer_is_overlay,
    utcnow,
    validate_wireguard_public_key,
)

sys.path.pop(0)


WG_KEY = base64.b64encode(b"w" * 32).decode()
WG_KEY_2 = base64.b64encode(b"x" * 32).decode()


def bootstrap_config() -> FleetBootstrapConfig:
    return FleetBootstrapConfig(
        overlay_cidr="10.77.0.0/29",
        control_plane_overlay_url="https://10.77.0.1:8080",
        control_plane_wireguard_public_key=WG_KEY,
        control_plane_wireguard_endpoint="fleet.example.test:51820",
        worker_image_digest="ghcr.io/example/shakerscan@sha256:" + "a" * 64,
        desired_worker_count=3,
    )


class FakeFleetConnection:
    def __init__(self):
        self.join_tokens = {}
        self.nodes = []
        self.credentials = []
        self.calls = []

    async def execute(self, sql, *args):
        compact = " ".join(sql.split())
        self.calls.append((compact, args))
        if "INSERT INTO node_join_tokens" in compact:
            self.join_tokens[args[0]] = {
                "token_id": args[1],
                "role": args[2],
                "transport": args[3],
                "expires_at": args[4],
                "max_uses": args[5],
                "use_count": 0,
                "revoked": False,
            }
        elif "SET revoked_at" in compact:
            for token in self.join_tokens.values():
                if token["token_id"] == args[0] and not token["revoked"] and token["use_count"] < token["max_uses"]:
                    token["revoked"] = True
                    return "UPDATE 1"
            return "UPDATE 0"
        elif "INSERT INTO nodes" in compact:
            self.nodes.append(
                {
                    "id": args[0],
                    "name": args[1],
                    "overlay_ip": args[4],
                    "wireguard_public_key": args[5],
                    "labels": json.loads(args[7]),
                    "capacity": json.loads(args[8]),
                    "connection_bundle_delivered_at": None,
                }
            )
        elif "INSERT INTO node_credentials" in compact:
            self.credentials.append({"node_id": args[0], "credential_hash": args[1], "version": 1})
        return "OK"

    async def fetch(self, sql, *args):
        compact = " ".join(sql.split())
        self.calls.append((compact, args))
        if "SELECT overlay_ip::text" in compact:
            return [{"overlay_ip": node["overlay_ip"]} for node in self.nodes]
        return []

    async def fetchrow(self, sql, *args):
        compact = " ".join(sql.split())
        self.calls.append((compact, args))
        if "UPDATE node_join_tokens" in compact:
            token = self.join_tokens.get(args[0])
            if (
                not token
                or token["revoked"]
                or token["transport"] != args[1]
                or token["use_count"] >= token["max_uses"]
                or token["expires_at"] <= utcnow()
            ):
                return None
            token["use_count"] += 1
            return {
                "role": token["role"],
                "transport": token["transport"],
                "token_id": token["token_id"],
                "use_count": token["use_count"],
                "max_uses": token["max_uses"],
            }
        if "connection_bundle_delivered_at = NOW()" in compact:
            for node in self.nodes:
                if node["id"] == args[0] and node["connection_bundle_delivered_at"] is None:
                    node["connection_bundle_delivered_at"] = utcnow()
                    return {"id": node["id"]}
            return None
        return None


def test_hashes_are_domain_separated_and_wireguard_keys_are_strict():
    assert hash_secret("same-secret", "join-token") != hash_secret("same-secret", "node-credential")
    assert validate_wireguard_public_key(WG_KEY) == WG_KEY
    with pytest.raises(FleetEnrollmentError):
        validate_wireguard_public_key(base64.b64encode(b"short").decode())
    with pytest.raises(FleetEnrollmentError):
        validate_wireguard_public_key("not-base64!")


def test_fleet_worker_distribution_is_capacity_weighted_deterministic_and_capped():
    nodes = [
        {"id": "a", "capacity": {"cpu_count": 8}},
        {"id": "b", "capacity": {"cpu_count": 4}},
        {"id": "c", "capacity": {"worker_weight": 1, "max_workers": 1}},
    ]
    first = distribute_worker_count(nodes, 10)
    assert first == distribute_worker_count(nodes, 10)
    assert sum(first.values()) == 10
    assert first["a"] > first["b"] > first["c"]
    assert first["c"] == 1


def test_fleet_worker_distribution_rejects_capacity_overflow():
    with pytest.raises(FleetConflictError, match="exceeds eligible fleet capacity"):
        distribute_worker_count([{"id": "a", "capacity": {"max_workers": 2}}], 3)


def test_join_token_is_single_use_and_raw_secrets_are_never_stored():
    asyncio.run(_test_join_token_is_single_use_and_raw_secrets_are_never_stored())


def test_broker_node_enrollment_allocates_no_overlay_or_wireguard_identity():
    async def run():
        conn = FakeFleetConnection()
        token = (await create_join_token(conn, ttl_seconds=600, transport="broker"))["token"]
        joined = await enroll_node(
            conn,
            token=token,
            name="broker-a",
            hostname="broker-a.internal",
            region="eu-test",
            wireguard_public_key=None,
            transport="broker",
            labels={"network": "customer-vpc"},
            capacity={"cpu_count": 8},
            build_fingerprint=None,
            config=bootstrap_config(),
        )
        assert joined["transport"] == "broker"
        assert joined["wireguard_peer_ip"] is None
        assert conn.nodes[0]["overlay_ip"] is None
        assert conn.nodes[0]["wireguard_public_key"] is None
        assert conn.nodes[0]["labels"]["transport"] == "broker"

    asyncio.run(run())


def test_enrollment_maps_only_the_exact_wireguard_unique_constraint():
    class WireGuardConflict(Exception):
        constraint_name = "nodes_wireguard_public_key_key"

    class ConflictConnection(FakeFleetConnection):
        async def execute(self, sql, *args):
            if "INSERT INTO nodes" in sql:
                raise WireGuardConflict("localized database message")
            return await super().execute(sql, *args)

    async def run():
        conn = ConflictConnection()
        token = (await create_join_token(conn, ttl_seconds=600))["token"]
        with pytest.raises(FleetConflictError, match="already enrolled"):
            await enroll_node(
                conn,
                token=token,
                name="worker-conflict",
                hostname=None,
                region=None,
                wireguard_public_key=WG_KEY_2,
                labels={},
                capacity={},
                build_fingerprint=None,
                config=bootstrap_config(),
            )

    asyncio.run(run())


async def _test_join_token_is_single_use_and_raw_secrets_are_never_stored():
    conn = FakeFleetConnection()
    token_result = await create_join_token(conn, ttl_seconds=600)
    raw_token = token_result["token"]

    joined = await enroll_node(
        conn,
        token=raw_token,
        name="worker-a",
        hostname="worker-a.internal",
        region="us-test-1",
        wireguard_public_key=WG_KEY_2,
        labels={"network": "lab"},
        capacity={"cpu_count": 4},
        build_fingerprint="build-123",
        config=bootstrap_config(),
    )

    assert joined["wireguard_peer_ip"] == "10.77.0.2"  # .1 is reserved for control plane
    assert joined["node_credential"].startswith("ssn_")
    assert joined["desired_worker_count"] == 3
    assert conn.credentials[0]["credential_hash"] != joined["node_credential"]
    stored_call_text = repr(conn.calls)
    assert raw_token not in stored_call_text
    assert joined["node_credential"] not in stored_call_text

    with pytest.raises(FleetEnrollmentError, match="exhausted"):
        await enroll_node(
            conn,
            token=raw_token,
            name="worker-b",
            hostname=None,
            region=None,
            wireguard_public_key=base64.b64encode(b"y" * 32).decode(),
            labels={},
            capacity={},
            build_fingerprint=None,
            config=bootstrap_config(),
        )


def test_join_token_can_be_bounded_to_multiple_workers_and_then_exhausts():
    async def run():
        conn = FakeFleetConnection()
        created = await create_join_token(conn, ttl_seconds=600, max_uses=3, transport="broker")
        assert created["max_uses"] == 3
        assert created["uses_remaining"] == 3
        assert uuid.UUID(created["token_id"])

        for index in range(3):
            await enroll_node(
                conn,
                token=created["token"],
                name=f"broker-{index}",
                hostname=None,
                region=None,
                wireguard_public_key=None,
                transport="broker",
                labels={},
                capacity={},
                build_fingerprint=None,
                config=bootstrap_config(),
            )

        with pytest.raises(FleetEnrollmentError, match="exhausted"):
            await enroll_node(
                conn,
                token=created["token"],
                name="broker-over-limit",
                hostname=None,
                region=None,
                wireguard_public_key=None,
                transport="broker",
                labels={},
                capacity={},
                build_fingerprint=None,
                config=bootstrap_config(),
            )

    asyncio.run(run())


def test_join_token_is_bound_to_its_enrollment_transport():
    async def run():
        conn = FakeFleetConnection()
        created = await create_join_token(conn, ttl_seconds=600, max_uses=2, transport="broker")
        with pytest.raises(FleetEnrollmentError, match="invalid"):
            await enroll_node(
                conn,
                token=created["token"],
                name="wrong-transport",
                hostname=None,
                region=None,
                wireguard_public_key=WG_KEY_2,
                transport="overlay",
                labels={},
                capacity={},
                build_fingerprint=None,
                config=bootstrap_config(),
            )
        assert next(iter(conn.join_tokens.values()))["use_count"] == 0

    asyncio.run(run())


def test_join_token_rejects_unbounded_use_counts():
    conn = FakeFleetConnection()
    with pytest.raises(FleetEnrollmentError, match="between 1 and 128"):
        asyncio.run(create_join_token(conn, ttl_seconds=600, max_uses=129))


def test_join_token_revocation_blocks_remaining_uses_without_raw_secret():
    async def run():
        conn = FakeFleetConnection()
        created = await create_join_token(conn, ttl_seconds=600, max_uses=3)
        assert await revoke_join_token(conn, token_id=created["token_id"]) is True
        assert await revoke_join_token(conn, token_id=created["token_id"]) is False

        with pytest.raises(FleetEnrollmentError, match="revoked"):
            await enroll_node(
                conn,
                token=created["token"],
                name="broker-revoked",
                hostname=None,
                region=None,
                wireguard_public_key=None,
                transport="broker",
                labels={},
                capacity={},
                build_fingerprint=None,
                config=bootstrap_config(),
            )

    asyncio.run(run())


def test_connection_bundle_consumption_is_one_time():
    asyncio.run(_test_connection_bundle_consumption_is_one_time())


async def _test_connection_bundle_consumption_is_one_time():
    conn = FakeFleetConnection()
    node_id = uuid.uuid4()
    conn.nodes.append(
        {
            "id": node_id,
            "overlay_ip": "10.77.0.2",
            "connection_bundle_delivered_at": None,
        }
    )
    await consume_connection_bundle(conn, node_id=str(node_id))
    with pytest.raises(FleetConflictError, match="already delivered"):
        await consume_connection_bundle(conn, node_id=str(node_id))


def test_overlay_peer_check_does_not_accept_outside_or_spoofable_values():
    assert socket_peer_is_overlay("10.77.0.2", "10.77.0.0/29") is True
    assert socket_peer_is_overlay("203.0.113.20", "10.77.0.0/29") is False
    assert socket_peer_is_overlay("10.77.0.2, 203.0.113.20", "10.77.0.0/29") is False
    assert socket_peer_is_overlay(None, "10.77.0.0/29") is False


def test_public_node_derives_stale_without_overwriting_durable_state():
    node_id = uuid.uuid4()
    row = {
        "id": node_id,
        "status": "healthy",
        "labels": '{"region":"test"}',
        "capacity": '{"cpu_count":2}',
        "last_heartbeat_at": utcnow() - timedelta(minutes=10),
    }
    result = public_node(row, stale_after_seconds=60)
    assert result["id"] == str(node_id)
    assert result["status"] == "stale"
    assert result["state_current"] is False
    assert result["image_current"] is False
    assert result["labels"] == {"region": "test"}
    assert row["status"] == "healthy"


def test_public_node_derives_state_and_image_currency():
    digest = "registry/shakerscan@sha256:" + "a" * 64
    result = public_node(
        {
            "id": uuid.uuid4(),
            "status": "healthy",
            "last_heartbeat_at": utcnow(),
            "desired_state_version": 4,
            "applied_state_version": 4,
            "worker_image_digest": digest,
            "active_worker_image_digest": digest,
            "last_error": None,
        },
        stale_after_seconds=60,
    )
    assert result["state_current"] is True
    assert result["image_current"] is True
    assert result["local_build_active"] is False


def test_public_node_exposes_supported_local_build_without_hiding_image_drift():
    digest = "registry/shakerscan@sha256:" + "a" * 64
    result = public_node(
        {
            "id": uuid.uuid4(),
            "status": "healthy",
            "last_heartbeat_at": utcnow(),
            "desired_state_version": 1,
            "applied_state_version": 1,
            "worker_image_digest": digest,
            "active_worker_image_digest": "shakerscan-fleet-local:03a2178f01b9",
            "last_error": None,
        },
        stale_after_seconds=60,
    )
    assert result["state_current"] is True
    assert result["image_current"] is False
    assert result["local_build_active"] is True


def test_public_node_uses_an_explicit_allow_list():
    result = public_node(
        {
            "id": uuid.uuid4(),
            "status": "joining",
            "credential_id": uuid.uuid4(),
            "future_private_material": "must-never-leak",
        },
        stale_after_seconds=60,
    )
    assert "credential_id" not in result
    assert "future_private_material" not in result


def test_public_node_marks_wireguard_peer_awaiting_first_connection():
    result = public_node(
        {
            "id": uuid.uuid4(),
            "status": "joining",
            "overlay_ip": "10.77.0.2",
            "labels": {"transport": "overlay"},
            "last_heartbeat_at": None,
            "connection_bundle_delivered_at": None,
        },
        stale_after_seconds=60,
    )
    assert result["wireguard_connection_pending"] is True
    assert "connection_bundle_delivered_at" not in result


def test_public_node_surfaces_heartbeating_reconciliation_error_as_unhealthy():
    result = public_node(
        {
            "id": uuid.uuid4(),
            "status": "joining",
            "last_error": "worker image pull failed",
            "last_heartbeat_at": utcnow(),
        },
        stale_after_seconds=60,
    )
    assert result["status"] == "unhealthy"
    assert result["state_current"] is False


def test_heartbeat_query_explicitly_types_nullable_status_parameters():
    class HeartbeatConnection:
        def __init__(self):
            self.sql = ""
            self.args = ()

        async def fetchrow(self, sql, *args):
            self.sql = " ".join(sql.split())
            self.args = args
            return {
                "id": args[0],
                "status": "healthy",
                "desired_worker_count": 1,
                "last_heartbeat_at": utcnow(),
            }

    async def run():
        conn = HeartbeatConnection()
        node_id = uuid.uuid4()
        result = await record_heartbeat(
            conn,
            node_id=str(node_id),
            active_worker_count=1,
            capacity={"cpu_count": 2},
            build_fingerprint=None,
            active_worker_image_digest=None,
            agent_version=None,
            applied_state_version=1,
            last_error=None,
            egress_ip=None,
        )

        assert result["status"] == "healthy"
        assert "last_error = $8::text" in conn.sql
        assert "WHEN $8::text IS NOT NULL" in conn.sql
        assert conn.args[7] is None

    asyncio.run(run())
