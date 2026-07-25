import base64
import json
import os
import sys
import types
from pathlib import Path

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import fleet_cli  # noqa: E402
sys.path.pop(0)


WG_KEY = base64.b64encode(b"w" * 32).decode()
NODE_ID = "11111111-1111-4111-8111-111111111111"
IMAGE = "registry.example/shakerscan@sha256:" + "a" * 64


def test_duration_and_endpoint_validation():
    assert fleet_cli.parse_duration("24h") == 86400
    assert fleet_cli.parse_duration("60") == 60
    with pytest.raises(fleet_cli.FleetCLIError):
        fleet_cli.parse_duration("8d")
    assert fleet_cli.validate_endpoint("fleet.example.test:51820") == ("fleet.example.test:51820", 51820)
    assert fleet_cli.validate_endpoint("[2001:db8::1]:51820") == ("[2001:db8::1]:51820", 51820)


def test_dotenv_update_preserves_unrelated_content_and_owner_only_mode(tmp_path):
    dotenv = tmp_path / ".env"
    dotenv.write_text("# user setting\nAI_MODEL=test\nFLEET_OVERLAY_CIDR=old\n", encoding="utf-8")
    fleet_cli.update_dotenv(
        dotenv,
        {"FLEET_OVERLAY_CIDR": "10.77.0.0/24", "FLEET_NETWORK_BACKEND": "wireguard"},
    )
    text = dotenv.read_text(encoding="utf-8")
    assert "# user setting" in text
    assert "AI_MODEL=test" in text
    assert text.count("FLEET_OVERLAY_CIDR=") == 1
    assert "FLEET_NETWORK_BACKEND=wireguard" in text
    assert dotenv.stat().st_mode & 0o777 == 0o600


def test_wireguard_rendering_is_deterministic_and_scoped():
    rendered = fleet_cli.render_control_wireguard(
        private_key=WG_KEY,
        control_ip="10.77.0.1",
        prefix_length=24,
        listen_port=51820,
        peers=[
            {"node_id": "b", "public_key": WG_KEY, "overlay_ip": "10.77.0.3"},
            {"node_id": "a", "public_key": WG_KEY, "overlay_ip": "10.77.0.2"},
        ],
    )
    assert rendered.index("10.77.0.2/32") < rendered.index("10.77.0.3/32")
    assert "AllowedIPs = 10.77.0.0/24" not in rendered

    worker = fleet_cli.render_worker_wireguard(
        private_key=WG_KEY,
        peer_ip="10.77.0.2",
        overlay_cidr="10.77.0.0/24",
        control_public_key=WG_KEY,
        endpoint="fleet.example.test:51820",
    )
    assert "Address = 10.77.0.2/24" in worker
    assert "AllowedIPs = 10.77.0.0/24" in worker
    assert "PersistentKeepalive = 25" in worker


def test_join_response_validation_requires_bound_identity():
    response = {
        "node_id": NODE_ID,
        "node_credential": "node-secret",
        "control_plane_overlay_url": "https://10.77.0.1:8443",
        "wireguard_overlay_cidr": "10.77.0.0/24",
        "wireguard_peer_ip": "10.77.0.2",
        "wireguard_control_plane_public_key": WG_KEY,
        "wireguard_control_plane_endpoint": "fleet.example.test:51820",
        "worker_image_digest": IMAGE,
        "fleet_ca_certificate_pem": "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n",
    }
    assert fleet_cli._validated_join_response(response.copy())["node_id"] == NODE_ID
    response["wireguard_peer_ip"] = "10.88.0.2"
    with pytest.raises(fleet_cli.FleetCLIError, match="outside the overlay"):
        fleet_cli._validated_join_response(response)


def test_worker_environment_is_allowlisted_and_owner_only(tmp_path):
    output = tmp_path / "worker.env"
    fleet_cli._write_worker_environment(
        output,
        {
            "redis_url": "redis://10.77.0.1:6379",
            "database_url": "postgresql://scanner:scanner@10.77.0.1:5432/scanner",
            "worker_environment": {"EVIDENCE_STORAGE_BACKEND": "s3"},
        },
    )
    assert "REDIS_URL=redis://10.77.0.1:6379" in output.read_text(encoding="utf-8")
    assert output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(fleet_cli.FleetCLIError, match="unsafe"):
        fleet_cli._write_worker_environment(
            output,
            {
                "redis_url": "redis://10.77.0.1:6379",
                "database_url": "postgresql://scanner:scanner@10.77.0.1/scanner",
                "worker_environment": {"BAD-KEY": "value"},
            },
        )


def test_connection_bundle_is_written_as_json_not_dotenv_secret(tmp_path):
    bundle = fleet_cli._connection_bundle(
        "10.77.0.1",
        {"EVIDENCE_S3_SECRET_ACCESS_KEY": "secret$with#compose-characters"},
    )
    destination = tmp_path / "bundle.json"
    fleet_cli.atomic_write(destination, json.dumps(bundle), 0o600)
    loaded = json.loads(destination.read_text(encoding="utf-8"))
    assert loaded["worker_environment"]["EVIDENCE_S3_SECRET_ACCESS_KEY"] == "secret$with#compose-characters"
    assert destination.stat().st_mode & 0o777 == 0o600


def test_parser_exposes_documented_commands():
    parser = fleet_cli.build_parser()
    assert parser.parse_args(["join-token"]).command == "join-token"
    assert parser.parse_args(["reconcile"]).command == "reconcile"
    args = parser.parse_args([
        "init",
        "--endpoint",
        "fleet.example.test:51820",
        "--public-url",
        "https://fleet.example.test",
        "--worker-image",
        IMAGE,
    ])
    assert args.command == "init"


def test_join_persists_one_time_bundle_before_starting_runtime(tmp_path, monkeypatch):
    paths = fleet_cli.RuntimePaths(tmp_path)
    paths.worker_compose.write_text("services: {}\n", encoding="utf-8")
    response = {
        "node_id": NODE_ID,
        "node_credential": "node-secret",
        "control_plane_overlay_url": "https://10.77.0.1:8443",
        "wireguard_overlay_cidr": "10.77.0.0/24",
        "wireguard_peer_ip": "10.77.0.2",
        "wireguard_control_plane_public_key": WG_KEY,
        "wireguard_control_plane_endpoint": "fleet.example.test:51820",
        "worker_image_digest": IMAGE,
        "fleet_ca_certificate_pem": "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n",
    }
    calls = []

    def fake_api(base, method, path, **kwargs):
        calls.append((base, method, path))
        if path == "/fleet/nodes/join":
            return dict(response)
        if path == "/health":
            return {"status": "healthy"}
        if path.endswith("/connection-bundle"):
            return {
                "delivered_once": True,
                "bundle": {
                    "redis_url": "redis://10.77.0.1:6379",
                    "database_url": "postgresql://scanner:scanner@10.77.0.1:5432/scanner",
                },
            }
        raise AssertionError(path)

    def fake_keys(private_path, public_path):
        fleet_cli.atomic_write(private_path, WG_KEY + "\n", 0o600)
        fleet_cli.atomic_write(public_path, WG_KEY + "\n", 0o644)
        return WG_KEY, WG_KEY

    started = []
    monkeypatch.setattr(fleet_cli, "_require_linux", lambda: None)
    monkeypatch.setattr(fleet_cli, "_require_commands", lambda _names: None)
    monkeypatch.setattr(fleet_cli, "_docker_compose_command", lambda: ["docker", "compose"])
    monkeypatch.setattr(fleet_cli, "generate_wireguard_keypair", fake_keys)
    monkeypatch.setattr(fleet_cli, "install_wireguard", lambda _path: None)
    monkeypatch.setattr(fleet_cli, "api_json", fake_api)
    monkeypatch.setattr(fleet_cli, "_start_worker_runtime", lambda _paths, result: started.append(result["node_id"]))

    fleet_cli.command_join(
        paths,
        types.SimpleNamespace(
            control_plane_url="https://fleet.example.test",
            token="ssj_" + "x" * 40,
            name="worker-a",
            region="us-central",
            overlay_timeout=1,
        ),
    )

    assert started == [NODE_ID]
    assert (paths.node / "state.json").stat().st_mode & 0o777 == 0o600
    worker_env = (paths.node / "worker.env").read_text(encoding="utf-8")
    assert "REDIS_URL=redis://10.77.0.1:6379" in worker_env
    assert calls[-1][2].endswith("/connection-bundle")


def test_init_persists_identity_bundle_and_fleet_profile(tmp_path, monkeypatch):
    paths = fleet_cli.RuntimePaths(tmp_path)
    scanner = tmp_path / "scanner.sh"
    scanner.write_text("#!/bin/sh\n", encoding="utf-8")
    scanner.chmod(0o755)
    key_calls = []

    def fake_keys(private_path, public_path):
        key_calls.append(private_path)
        fleet_cli.atomic_write(private_path, WG_KEY + "\n", 0o600)
        fleet_cli.atomic_write(public_path, WG_KEY + "\n", 0o644)
        return WG_KEY, WG_KEY

    monkeypatch.setattr(fleet_cli, "_require_linux", lambda: None)
    monkeypatch.setattr(fleet_cli, "_require_commands", lambda _names: None)
    monkeypatch.setattr(fleet_cli, "_docker_compose_command", lambda: ["docker", "compose"])
    monkeypatch.setattr(fleet_cli, "generate_wireguard_keypair", fake_keys)
    monkeypatch.setattr(fleet_cli, "generate_control_certificates", lambda _path, _ip: None)
    monkeypatch.setattr(fleet_cli, "install_wireguard", lambda _path: None)
    monkeypatch.setattr(fleet_cli, "_run", lambda *a, **k: types.SimpleNamespace(returncode=0, stdout=""))
    monkeypatch.setattr(fleet_cli, "api_json", lambda *a, **k: {"status": "healthy"})

    fleet_cli.command_init(
        paths,
        types.SimpleNamespace(
            overlay="10.77.0.0/24",
            endpoint="fleet.example.test:51820",
            listen_port=51820,
            tls_port=8443,
            public_url="https://fleet.example.test",
            skip_public_check=False,
            worker_image=IMAGE,
            workers=3,
            no_reconcile_service=True,
        ),
    )

    env = fleet_cli.load_dotenv(paths.dotenv)
    assert env["COMPOSE_PROFILES"] == "fleet"
    assert env["SHAKERSCAN_DATA_BIND_HOST"] == "10.77.0.1"
    assert env["FLEET_WORKER_IMAGE_DIGEST"] == IMAGE
    assert env["FLEET_CONNECTION_BUNDLE_JSON"] == ""
    bundle_path = paths.control / "connection-bundle.json"
    assert bundle_path.stat().st_mode & 0o777 == 0o600
    assert json.loads(bundle_path.read_text(encoding="utf-8"))["redis_url"] == "redis://10.77.0.1:6379"
    assert len(key_calls) == 1
