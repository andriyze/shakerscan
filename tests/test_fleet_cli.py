import base64
import json
import os
import sys
import types
import urllib.error
import ssl
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


def test_fleet_operator_token_preserves_strong_values_and_replaces_weak_ones():
    existing = "operator-" + "x" * 40
    assert fleet_cli.fleet_operator_token({"FLEET_OPERATOR_TOKEN": existing}) == existing
    generated = fleet_cli.fleet_operator_token({"FLEET_OPERATOR_TOKEN": "weak"})
    assert len(generated) >= 32
    assert generated != "weak"


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
        {
            "POSTGRES_PASSWORD": "p" * 40,
            "REDIS_PASSWORD": "r" * 40,
            "EVIDENCE_S3_SECRET_ACCESS_KEY": "secret$with#compose-characters",
        },
    )
    destination = tmp_path / "bundle.json"
    fleet_cli.atomic_write(destination, json.dumps(bundle), 0o600)
    loaded = json.loads(destination.read_text(encoding="utf-8"))
    assert loaded["worker_environment"]["EVIDENCE_S3_SECRET_ACCESS_KEY"] == "secret$with#compose-characters"
    assert destination.stat().st_mode & 0o777 == 0o600


def test_fleet_datastore_credentials_rotate_defaults_without_putting_secret_in_argv(monkeypatch):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        if argv[-3:] == ["ps", "-q", "postgres"]:
            return types.SimpleNamespace(returncode=0, stdout="container-id\n")
        return types.SimpleNamespace(returncode=0, stdout="")

    monkeypatch.setattr(fleet_cli, "_docker_compose_command", lambda: ["docker", "compose"])
    monkeypatch.setattr(fleet_cli, "_run", fake_run)
    credentials = fleet_cli.fleet_datastore_credentials({})
    fleet_cli.rotate_postgres_password_if_running(credentials["POSTGRES_PASSWORD"])

    assert len(credentials["POSTGRES_PASSWORD"]) >= 32
    assert len(credentials["REDIS_PASSWORD"]) >= 32
    alter_argv, alter_kwargs = calls[-1]
    assert credentials["POSTGRES_PASSWORD"] not in " ".join(alter_argv)
    assert credentials["POSTGRES_PASSWORD"] in alter_kwargs["input_text"]

    preserved = fleet_cli.fleet_datastore_credentials({
        "POSTGRES_PASSWORD": "p" * 40,
        "REDIS_PASSWORD": "r" * 40,
    })
    assert preserved == {"POSTGRES_PASSWORD": "p" * 40, "REDIS_PASSWORD": "r" * 40}
    with pytest.raises(fleet_cli.FleetCLIError, match="URL-safe"):
        fleet_cli.fleet_datastore_credentials({"POSTGRES_PASSWORD": ("p" * 39) + ":"})


def test_parser_exposes_documented_commands():
    parser = fleet_cli.build_parser()
    assert parser.parse_args(["join-token"]).command == "join-token"
    assert parser.parse_args(["reconcile"]).command == "reconcile"
    assert parser.parse_args([
        "preflight",
        "--endpoint", "fleet.example.test:51820",
        "--public-url", "https://fleet.example.test",
        "--worker-image", IMAGE,
        "--no-reconcile-service",
    ]).command == "preflight"
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
    broker = parser.parse_args([
        "init",
        "--network",
        "broker",
        "--public-url",
        "https://fleet.example.test",
        "--worker-image",
        IMAGE,
    ])
    assert broker.network == "broker"
    assert broker.endpoint is None


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
    monkeypatch.setattr(fleet_cli, "_wireguard_handshake_age", lambda: 1)
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
    assert calls[0][2] == "/health"
    assert calls[-1][2].endswith("/connection-bundle")


def test_broker_join_installs_no_database_or_redis_credentials(tmp_path, monkeypatch):
    paths = fleet_cli.RuntimePaths(tmp_path)
    paths.broker_worker_compose.write_text("services: {}\n", encoding="utf-8")
    response = {
        "node_id": NODE_ID,
        "node_credential": "node-secret",
        "transport": "broker",
        "worker_image_digest": IMAGE,
        "labels": {"transport": "broker", "network": "customer-vpc"},
    }
    payloads = []

    def fake_api(_base, _method, path, **kwargs):
        if path == "/health":
            return {"status": "healthy"}
        assert path == "/fleet/nodes/join"
        payloads.append(kwargs["payload"])
        return dict(response)

    started = []
    monkeypatch.setattr(fleet_cli, "_require_linux", lambda: None)
    monkeypatch.setattr(fleet_cli, "_require_commands", lambda _names: None)
    monkeypatch.setattr(fleet_cli, "_docker_compose_command", lambda: ["docker", "compose"])
    monkeypatch.setattr(fleet_cli, "api_json", fake_api)
    monkeypatch.setattr(fleet_cli, "_start_broker_runtime", lambda _paths, result: started.append(result["node_id"]))

    fleet_cli.command_join(
        paths,
        types.SimpleNamespace(
            control_plane_url="https://fleet.example.test",
            token="ssj_" + "x" * 40,
            name="broker-a",
            region="eu-test",
            transport="broker",
            egress_group=None,
            network_label="customer-vpc",
            data_residency=None,
            capability=["nuclei"],
            scan_tier=["smart"],
            label=[],
        ),
    )

    assert started == [NODE_ID]
    assert payloads[0]["wireguard_public_key"] is None
    assert payloads[0]["transport"] == "broker"
    state_text = (paths.node / "state.json").read_text(encoding="utf-8")
    assert "REDIS_URL" not in state_text
    assert "DATABASE_URL" not in state_text
    assert '"tls_ca_mode": "system"' in state_text
    assert not (paths.node / "worker.env").exists()


def test_broker_join_can_pin_a_private_enrollment_ca(tmp_path, monkeypatch):
    paths = fleet_cli.RuntimePaths(tmp_path)
    paths.broker_worker_compose.write_text("services: {}\n", encoding="utf-8")
    source_ca = tmp_path / "private-ca.pem"
    source_ca.write_text(
        "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n",
        encoding="utf-8",
    )
    response = {
        "node_id": NODE_ID,
        "node_credential": "node-secret",
        "transport": "broker",
        "worker_image_digest": IMAGE,
    }
    observed_ca_files = []

    def fake_api(_base, _method, path, **kwargs):
        if path == "/health":
            observed_ca_files.append(kwargs.get("ca_file"))
            return {"status": "healthy"}
        assert path == "/fleet/nodes/join"
        observed_ca_files.append(kwargs.get("ca_file"))
        return dict(response)

    monkeypatch.setattr(fleet_cli, "_require_linux", lambda: None)
    monkeypatch.setattr(fleet_cli, "_require_commands", lambda _names: None)
    monkeypatch.setattr(fleet_cli, "_docker_compose_command", lambda: ["docker", "compose"])
    monkeypatch.setattr(fleet_cli, "api_json", fake_api)
    monkeypatch.setattr(fleet_cli, "_start_broker_runtime", lambda *_args: None)

    fleet_cli.command_join(
        paths,
        types.SimpleNamespace(
            control_plane_url="https://fleet.example.test",
            token="ssj_" + "x" * 40,
            ca_cert=str(source_ca),
            name="broker-private-ca",
            transport="broker",
            region=None,
            egress_group=None,
            network_label=None,
            data_residency=None,
            capability=[],
            scan_tier=[],
            label=[],
        ),
    )

    assert observed_ca_files == [source_ca.resolve(), source_ca.resolve()]
    state = json.loads((paths.node / "state.json").read_text(encoding="utf-8"))
    assert state["tls_ca_mode"] == "file"
    assert state["ca_cert_path"] == "/run/shakerscan-fleet/ca.crt"
    assert (paths.node / "ca.crt").read_text(encoding="utf-8") == source_ca.read_text(encoding="utf-8")


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
    monkeypatch.setattr(
        fleet_cli,
        "api_json",
        lambda _base, _method, path, **_kwargs: {
            "status": "ok" if path.startswith("/artifacts/storage/health") else "healthy"
        },
    )

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
    assert env["COMPOSE_PROFILES"] == "artifacts,fleet"
    assert env["SHAKERSCAN_DATA_BIND_HOST"] == "10.77.0.1"
    assert env["FLEET_WORKER_IMAGE_DIGEST"] == IMAGE
    assert len(env["FLEET_OPERATOR_TOKEN"]) >= 32
    assert env["FLEET_CONNECTION_BUNDLE_JSON"] == ""
    assert env["EVIDENCE_STORAGE_BACKEND"] == "s3"
    assert env["ARTIFACT_STORAGE_REQUIRED"] == "true"
    assert env["EVIDENCE_S3_ENDPOINT_URL"] == "http://10.77.0.1:9000"
    assert len(env["MINIO_ROOT_PASSWORD"]) >= 32
    bundle_path = paths.control / "connection-bundle.json"
    assert bundle_path.stat().st_mode & 0o777 == 0o600
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    assert bundle["redis_url"].startswith("redis://:")
    assert bundle["redis_url"].endswith("@10.77.0.1:6379")
    assert bundle["database_url"].startswith("postgresql://scanner:")
    assert bundle["worker_environment"]["EVIDENCE_S3_ENDPOINT_URL"] == "http://10.77.0.1:9000"
    assert len(key_calls) == 1


def test_broker_init_uses_private_ca_for_public_health_checks(tmp_path, monkeypatch):
    paths = fleet_cli.RuntimePaths(tmp_path)
    scanner = tmp_path / "scanner.sh"
    scanner.write_text("#!/bin/sh\n", encoding="utf-8")
    scanner.chmod(0o755)
    ca_path = tmp_path / "private-ca.pem"
    ca_path.write_text(
        "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n",
        encoding="utf-8",
    )
    calls = []

    def fake_api(base, _method, path, **kwargs):
        calls.append((base, path, kwargs.get("ca_file")))
        if path.startswith("/artifacts/storage/health"):
            return {"status": "ok"}
        return {"status": "healthy"}

    monkeypatch.setattr(fleet_cli, "_require_linux", lambda: None)
    monkeypatch.setattr(fleet_cli, "_require_commands", lambda _names: None)
    monkeypatch.setattr(fleet_cli, "_docker_compose_command", lambda: ["docker", "compose"])
    monkeypatch.setattr(fleet_cli, "_run", lambda *a, **k: types.SimpleNamespace(returncode=0, stdout=""))
    monkeypatch.setattr(fleet_cli, "api_json", fake_api)

    fleet_cli.command_init(
        paths,
        types.SimpleNamespace(
            network="broker",
            public_url="https://fleet.internal.example",
            ca_cert=str(ca_path),
            skip_public_check=False,
            worker_image=IMAGE,
            workers=2,
        ),
    )

    public_checks = [item for item in calls if item[0] == "https://fleet.internal.example"]
    assert len(public_checks) == 2
    assert all(item[2] == ca_path.resolve() for item in public_checks)


def test_fleet_artifact_environment_preserves_external_s3():
    updates, bundled = fleet_cli._fleet_artifact_environment(
        "10.77.0.1",
        {
            "EVIDENCE_STORAGE_BACKEND": "s3",
            "EVIDENCE_S3_BUCKET": "external-bucket",
            "EVIDENCE_S3_ACCESS_KEY_ID": "access",
            "EVIDENCE_S3_SECRET_ACCESS_KEY": "secret",
            "EVIDENCE_S3_ENDPOINT_URL": "https://objects.example.test",
        },
    )
    assert bundled is False
    assert updates == {"ARTIFACT_STORAGE_REQUIRED": "true"}


def test_worker_image_tag_resolves_to_manifest_digest(monkeypatch):
    calls = []

    def fake_run(argv, **_kwargs):
        calls.append(argv)
        return types.SimpleNamespace(
            returncode=0,
            stdout="Name: registry.example/shakerscan:v8\nDigest: sha256:" + "b" * 64 + "\n",
        )

    monkeypatch.setattr(fleet_cli, "_run", fake_run)
    pinned, source = fleet_cli.resolve_worker_image("registry.example/shakerscan:v8", {})
    assert source == "registry.example/shakerscan:v8"
    assert pinned == "registry.example/shakerscan@sha256:" + "b" * 64
    assert calls[0][:4] == ["docker", "buildx", "imagetools", "inspect"]


def test_default_worker_image_resolves_without_cli_flag(monkeypatch):
    monkeypatch.setattr(
        fleet_cli,
        "_discover_digest_image",
        lambda _env: (_ for _ in ()).throw(fleet_cli.FleetCLIError("not local")),
    )
    monkeypatch.setattr(
        fleet_cli,
        "_run",
        lambda argv, **_kwargs: types.SimpleNamespace(
            returncode=0,
            stdout="Name: shakerscan/shakerscan-scanner:latest\nDigest: sha256:" + "c" * 64 + "\n",
        ),
    )
    pinned, source = fleet_cli.resolve_worker_image(None, {})
    assert source == "shakerscan/shakerscan-scanner:latest"
    assert pinned == "shakerscan/shakerscan-scanner@sha256:" + "c" * 64


def test_managed_gateway_caddyfile_only_exposes_worker_routes():
    rendered = fleet_cli.render_managed_caddyfile("https://fleet.example.test")
    assert rendered.startswith("# Managed by ShakerScan")
    assert "fleet.example.test {" in rendered
    assert "path /fleet/nodes/join" in rendered
    assert "path /fleet/broker/*" in rendered
    assert "/fleet/nodes/[0-9a-fA-F-]+/state" in rendered
    assert "/fleet/nodes/[0-9a-fA-F-]+/heartbeat" in rendered
    assert 'respond "Not found" 404' in rendered
    assert "/targets" not in rendered
    assert "/docs" not in rendered


def test_managed_gateway_requires_public_dns_address(monkeypatch):
    monkeypatch.setattr(
        fleet_cli.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", ("10.0.0.8", 443))],
    )
    with pytest.raises(fleet_cli.FleetCLIError, match="publicly routable"):
        fleet_cli._resolved_public_addresses("https://fleet.internal.example")


def test_broker_auto_preflight_selects_managed_https_when_url_is_not_ready(tmp_path, monkeypatch):
    paths = fleet_cli.RuntimePaths(tmp_path)
    monkeypatch.setattr(fleet_cli, "_require_linux", lambda: None)
    monkeypatch.setattr(fleet_cli, "_require_commands", lambda _names: None)
    monkeypatch.setattr(fleet_cli, "_docker_compose_command", lambda: ["docker", "compose"])
    monkeypatch.setattr(
        fleet_cli,
        "_require_healthy_api",
        lambda *_args: (_ for _ in ()).throw(fleet_cli.FleetCLIError("connection refused")),
    )
    monkeypatch.setattr(fleet_cli, "_resolved_public_addresses", lambda _url: ["203.0.113.8"])
    monkeypatch.setattr(fleet_cli, "_assert_port_available", lambda *_args, **_kwargs: None)
    prepared = fleet_cli.run_init_preflight(
        paths,
        types.SimpleNamespace(
            network="broker",
            public_url="https://fleet.example.test",
            ca_cert=None,
            skip_public_check=False,
            https_mode="auto",
            worker_image=IMAGE,
            workers=1,
        ),
    )
    assert prepared["https_mode"] == "managed"


def test_broker_managed_https_writes_gateway_and_rolls_back_on_failed_verification(tmp_path, monkeypatch):
    paths = fleet_cli.RuntimePaths(tmp_path)
    scanner = tmp_path / "scanner.sh"
    scanner.write_text("#!/bin/sh\n", encoding="utf-8")
    scanner.chmod(0o755)
    paths.dotenv.write_text("EXISTING=value\n", encoding="utf-8")
    paths.control.mkdir(parents=True)
    paths.gateway_config.write_text("old gateway\n", encoding="utf-8")

    monkeypatch.setattr(
        fleet_cli,
        "run_init_preflight",
        lambda *_args: {
            "public_url": "https://fleet.example.test",
            "enrollment_ca": None,
            "env": {"EXISTING": "value"},
            "worker_image": IMAGE,
            "https_mode": "managed",
        },
    )
    monkeypatch.setattr(fleet_cli, "_backup_standalone_if_running", lambda *_args: None)
    monkeypatch.setattr(
        fleet_cli,
        "_fleet_artifact_environment",
        lambda *_args: ({"ARTIFACT_STORAGE_REQUIRED": "true"}, False),
    )
    monkeypatch.setattr(fleet_cli, "_run", lambda *_args, **_kwargs: types.SimpleNamespace(returncode=0, stdout=""))
    monkeypatch.setattr(
        fleet_cli,
        "_wait_for_healthy_api",
        lambda *_args: (_ for _ in ()).throw(fleet_cli.FleetCLIError("ACME failed")),
    )

    with pytest.raises(fleet_cli.FleetCLIError, match="rolled back"):
        fleet_cli.command_init(
            paths,
            types.SimpleNamespace(network="broker", workers=1),
        )

    assert paths.dotenv.read_text(encoding="utf-8") == "EXISTING=value\n"
    assert paths.gateway_config.read_text(encoding="utf-8") == "old gateway\n"


def test_broker_managed_https_persists_profile_after_all_verification_passes(tmp_path, monkeypatch):
    paths = fleet_cli.RuntimePaths(tmp_path)
    scanner = tmp_path / "scanner.sh"
    scanner.write_text("#!/bin/sh\n", encoding="utf-8")
    scanner.chmod(0o755)
    isolation_checks = []

    monkeypatch.setattr(
        fleet_cli,
        "run_init_preflight",
        lambda *_args: {
            "public_url": "https://fleet.example.test",
            "enrollment_ca": None,
            "env": {},
            "worker_image": IMAGE,
            "https_mode": "managed",
        },
    )
    monkeypatch.setattr(fleet_cli, "_backup_standalone_if_running", lambda *_args: None)
    monkeypatch.setattr(
        fleet_cli,
        "_fleet_artifact_environment",
        lambda *_args: ({"ARTIFACT_STORAGE_REQUIRED": "true"}, False),
    )
    monkeypatch.setattr(fleet_cli, "_run", lambda *_args, **_kwargs: types.SimpleNamespace(returncode=0, stdout=""))
    monkeypatch.setattr(fleet_cli, "_wait_for_healthy_api", lambda *_args: None)
    monkeypatch.setattr(
        fleet_cli,
        "_verify_managed_gateway_isolation",
        lambda *args: isolation_checks.append(args),
    )
    monkeypatch.setattr(fleet_cli, "api_json", lambda *_args, **_kwargs: {"status": "ok"})

    fleet_cli.command_init(paths, types.SimpleNamespace(network="broker", workers=2))

    env = fleet_cli.load_dotenv(paths.dotenv)
    assert env["COMPOSE_PROFILES"] == "fleet-gateway"
    assert env["FLEET_HTTPS_MODE"] == "managed"
    assert env["FLEET_NETWORK_BACKEND"] == "broker"
    assert env["FLEET_WORKER_IMAGE_DIGEST"] == IMAGE
    assert paths.gateway_config.stat().st_mode & 0o777 == 0o600
    assert "fleet.example.test {" in paths.gateway_config.read_text(encoding="utf-8")
    assert isolation_checks == [("https://fleet.example.test", None)]


def test_preflight_reports_all_failures_before_mutation(tmp_path, monkeypatch, capsys):
    paths = fleet_cli.RuntimePaths(tmp_path)
    monkeypatch.setattr(fleet_cli, "_require_linux", lambda: (_ for _ in ()).throw(fleet_cli.FleetCLIError("not Linux")))
    monkeypatch.setattr(fleet_cli, "_require_commands", lambda _names: (_ for _ in ()).throw(fleet_cli.FleetCLIError("missing tools")))
    monkeypatch.setattr(fleet_cli, "_docker_compose_command", lambda: (_ for _ in ()).throw(fleet_cli.FleetCLIError("no Compose")))
    monkeypatch.setattr(fleet_cli, "api_json", lambda *_a, **_k: {"status": "healthy"})
    with pytest.raises(fleet_cli.FleetCLIError, match="preflight failed"):
        fleet_cli.command_preflight(
            paths,
            types.SimpleNamespace(
                network="wireguard",
                overlay="not-a-cidr",
                endpoint=None,
                listen_port=51820,
                tls_port=8443,
                public_url="http://not-https.example",
                ca_cert=None,
                skip_public_check=False,
                worker_image="bad image",
                workers=0,
                no_reconcile_service=False,
            ),
        )
    output = capsys.readouterr().out
    assert output.count("[FAIL]") >= 6
    assert not paths.fleet.exists()


def test_standalone_backup_runs_before_fleet_mutation(tmp_path, monkeypatch):
    paths = fleet_cli.RuntimePaths(tmp_path)
    scanner = tmp_path / "scanner.sh"
    scanner.write_text("#!/bin/sh\n", encoding="utf-8")
    calls = []

    def fake_run(argv, **_kwargs):
        calls.append(argv)
        stdout = "postgres-container\n" if argv[-3:] == ["ps", "-q", "postgres"] else ""
        return types.SimpleNamespace(returncode=0, stdout=stdout)

    monkeypatch.setattr(fleet_cli, "_docker_compose_command", lambda: ["docker", "compose"])
    monkeypatch.setattr(fleet_cli, "_run", fake_run)
    fleet_cli._backup_standalone_if_running(paths, {})
    assert calls[-1] == [str(scanner), "backup"]


def test_api_json_gives_private_ca_hint(monkeypatch):
    verification = ssl.SSLCertVerificationError("certificate verify failed")

    def fail(*_args, **_kwargs):
        raise urllib.error.URLError(verification)

    monkeypatch.setattr(fleet_cli.urllib.request, "urlopen", fail)
    with pytest.raises(fleet_cli.FleetCLIError, match="pass --ca-cert"):
        fleet_cli.api_json("https://fleet.internal", "GET", "/health")


def test_port_and_overlay_collision_detection(monkeypatch):
    def fake_run(argv, **_kwargs):
        if argv[0] == "ss":
            return types.SimpleNamespace(
                returncode=0,
                stdout="LISTEN 0 4096 0.0.0.0:8443 0.0.0.0:*\n",
            )
        return types.SimpleNamespace(
            returncode=0,
            stdout=json.dumps([
                {"dst": "10.77.0.0/16", "dev": "eth0"},
                {"dst": "192.168.1.0/24", "dev": "eth0"},
            ]),
        )

    monkeypatch.setattr(fleet_cli, "_run", fake_run)
    assert fleet_cli._listening_port("tcp", 8443) is True
    assert fleet_cli._overlay_route_conflicts(fleet_cli.ip_network("10.77.0.0/24")) == [
        "10.77.0.0/16 via eth0"
    ]
    with pytest.raises(fleet_cli.FleetCLIError, match="already in use"):
        fleet_cli._assert_port_available("tcp", 8443, existing_fleet=False)
    with pytest.raises(fleet_cli.FleetCLIError, match="overlaps existing route"):
        fleet_cli._assert_overlay_available(
            fleet_cli.ip_network("10.77.0.0/24"),
            existing_fleet=False,
        )
