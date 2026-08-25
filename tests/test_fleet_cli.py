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


def test_fleet_gateway_proxy_secret_is_strong_preserved_and_header_safe():
    generated = fleet_cli.fleet_gateway_proxy_secret({})
    assert len(generated) >= 32
    assert fleet_cli.URL_SAFE_SECRET_RE.fullmatch(generated)
    assert fleet_cli.fleet_gateway_proxy_secret({"FLEET_GATEWAY_PROXY_SECRET": generated}) == generated
    with pytest.raises(fleet_cli.FleetCLIError, match="at least 32"):
        fleet_cli.fleet_gateway_proxy_secret({"FLEET_GATEWAY_PROXY_SECRET": "weak"})


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
    reusable = parser.parse_args(["join-token", "--max-uses", "5"])
    assert reusable.max_uses == 5
    assert parser.parse_args(["revoke-join-token", NODE_ID]).command == "revoke-join-token"
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
    local_join = parser.parse_args([
        "join",
        "https://fleet.example.test",
        "--transport",
        "broker",
        "--local-build",
    ])
    assert local_join.local_build is True


def test_join_token_command_prints_one_shareable_bounded_command(tmp_path, monkeypatch, capsys):
    paths = fleet_cli.RuntimePaths(tmp_path)
    paths.dotenv.write_text(
        "FLEET_PUBLIC_URL=https://fleet.example.test\nFLEET_OPERATOR_TOKEN=operator-secret\n",
        encoding="utf-8",
    )
    payloads = []

    def fake_api(_base, method, path, **kwargs):
        assert method == "POST"
        assert path == "/fleet/join-tokens"
        assert kwargs["bearer"] == "operator-secret"
        payloads.append(kwargs["payload"])
        return {
            "token": "ssj_" + "x" * 40,
            "token_id": NODE_ID,
            "expires_at": "2026-07-26T10:00:00Z",
            "max_uses": 5,
        }

    monkeypatch.setattr(fleet_cli, "api_json", fake_api)
    fleet_cli.command_join_token(
        paths,
        types.SimpleNamespace(
            ttl="1h",
            role="worker",
            max_uses=5,
            public_url=None,
            local_api="http://127.0.0.1:8080",
            transport="broker",
        ),
    )

    output = capsys.readouterr().out
    assert payloads == [{
        "role": "worker",
        "transport": "broker",
        "ttl_seconds": 3600,
        "max_uses": 5,
    }]
    assert "up to 5 workers" in output
    assert output.count("shakerscan join https://fleet.example.test") == 1
    assert "--transport broker" in output
    assert f"shakerscan fleet revoke-join-token {NODE_ID}" in output


def test_control_plane_commands_resolve_remote_bind_when_local_api_is_omitted(tmp_path, monkeypatch):
    paths = fleet_cli.RuntimePaths(tmp_path)
    paths.dotenv.write_text(
        "SHAKERSCAN_BIND_HOST=100.121.87.22\n"
        "SHAKERSCAN_API_PORT=9080\n"
        "FLEET_PUBLIC_URL=https://fleet.example.test\n"
        "FLEET_OPERATOR_TOKEN=operator-secret\n",
        encoding="utf-8",
    )
    calls = []

    def fake_api(base, method, path, **kwargs):
        calls.append((base, method, path, kwargs))
        return {
            "token": "ssj_" + "x" * 40,
            "token_id": NODE_ID,
            "expires_at": "2026-07-26T10:00:00Z",
            "max_uses": 1,
        }

    monkeypatch.setattr(fleet_cli, "api_json", fake_api)
    fleet_cli.command_join_token(
        paths,
        types.SimpleNamespace(
            ttl="1h",
            role="worker",
            max_uses=1,
            public_url=None,
            local_api=None,
            transport="broker",
        ),
    )

    assert calls[0][0] == "http://100.121.87.22:9080"


def test_revoke_join_token_command_uses_identifier_not_secret(tmp_path, monkeypatch, capsys):
    paths = fleet_cli.RuntimePaths(tmp_path)
    paths.dotenv.write_text("FLEET_OPERATOR_TOKEN=operator-secret\n", encoding="utf-8")
    calls = []

    def fake_api(base, method, path, **kwargs):
        calls.append((base, method, path, kwargs))
        return {"token_id": NODE_ID, "revoked": True}

    monkeypatch.setattr(fleet_cli, "api_json", fake_api)
    fleet_cli.command_revoke_join_token(
        paths,
        types.SimpleNamespace(token_id=NODE_ID, local_api="http://127.0.0.1:8080"),
    )

    assert calls[0][1:3] == ("DELETE", f"/fleet/join-tokens/{NODE_ID}")
    assert calls[0][3]["bearer"] == "operator-secret"
    assert "revoked" in capsys.readouterr().out


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
    monkeypatch.setattr(
        fleet_cli,
        "_start_broker_runtime",
        lambda _paths, result, **_kwargs: started.append(result["node_id"]),
    )

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
            budget_profile=["thorough"],
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


def test_broker_join_local_build_skips_registry_runtime_and_persists_override(tmp_path, monkeypatch):
    paths = fleet_cli.RuntimePaths(tmp_path)
    paths.broker_worker_compose.write_text("services: {}\n", encoding="utf-8")
    (tmp_path / "scanner").mkdir()
    (tmp_path / "scanner" / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / "broker_worker.py").write_text("", encoding="utf-8")
    payloads = []
    starts = []

    def fake_api(_base, _method, path, **kwargs):
        if path == "/health":
            return {"status": "healthy"}
        payloads.append(kwargs["payload"])
        return {
            "node_id": NODE_ID,
            "node_credential": "node-secret",
            "transport": "broker",
            "worker_image_digest": IMAGE,
        }

    monkeypatch.setattr(fleet_cli, "_require_linux", lambda: None)
    monkeypatch.setattr(fleet_cli, "_require_commands", lambda _names: None)
    monkeypatch.setattr(fleet_cli, "_docker_compose_command", lambda: ["docker", "compose"])
    monkeypatch.setattr(fleet_cli, "api_json", fake_api)
    monkeypatch.setattr(
        fleet_cli,
        "_build_local_broker_worker_image",
        lambda _paths: "shakerscan-fleet-local:abc1234",
    )
    monkeypatch.setattr(
        fleet_cli,
        "_start_broker_runtime",
        lambda _paths, _response, **kwargs: starts.append(kwargs.get("runtime_image")),
    )

    fleet_cli.command_join(
        paths,
        types.SimpleNamespace(
            control_plane_url="https://fleet.example.test",
            token="ssj_" + "x" * 40,
            name="broker-local",
            transport="broker",
            local_build=True,
            region=None,
            egress_group=None,
            network_label=None,
            data_residency=None,
            capability=[],
            budget_profile=[],
            label=[],
        ),
    )

    assert starts == ["shakerscan-fleet-local:abc1234"]
    assert payloads[0]["labels"]["runtime_mode"] == "local-build"
    state = json.loads((paths.node / "state.json").read_text(encoding="utf-8"))
    assert state["runtime_image_override"] == "shakerscan-fleet-local:abc1234"
    assert state["worker_image_digest"] == IMAGE


def test_broker_resume_retires_local_override_after_control_plane_rollout(tmp_path, monkeypatch):
    paths = fleet_cli.RuntimePaths(tmp_path)
    paths.node.mkdir(parents=True)
    paths.broker_worker_compose.write_text("services: {}\n", encoding="utf-8")
    next_image = "registry.example/shakerscan@sha256:" + "b" * 64
    state_path = paths.node / "state.json"
    fleet_cli.atomic_write(
        state_path,
        json.dumps(
            {
                "node_id": NODE_ID,
                "node_credential": "node-secret",
                "control_plane_url": "https://fleet.example.test",
                "worker_image_digest": IMAGE,
                "tls_ca_mode": "system",
                "transport": "broker",
                "enrollment_url": "https://fleet.example.test",
                "runtime_image_override": "shakerscan-fleet-local:abc1234",
                "bootstrap": {
                    "node_id": NODE_ID,
                    "node_credential": "node-secret",
                    "transport": "broker",
                    "worker_image_digest": IMAGE,
                },
            }
        ),
        0o600,
    )
    starts = []

    monkeypatch.setattr(fleet_cli, "_require_linux", lambda: None)
    monkeypatch.setattr(fleet_cli, "_require_commands", lambda _names: None)
    monkeypatch.setattr(fleet_cli, "_docker_compose_command", lambda: ["docker", "compose"])

    def fake_api(_base, method, path, **kwargs):
        assert method == "GET"
        assert path == f"/fleet/nodes/{NODE_ID}/state"
        assert kwargs["bearer"] == "node-secret"
        return {"worker_image_digest": next_image, "rollout_in_progress": False}

    monkeypatch.setattr(fleet_cli, "api_json", fake_api)
    monkeypatch.setattr(
        fleet_cli,
        "_start_broker_runtime",
        lambda _paths, response, **kwargs: starts.append(
            (response["worker_image_digest"], kwargs.get("runtime_image"))
        ),
    )

    fleet_cli.command_join(
        paths,
        types.SimpleNamespace(
            control_plane_url="https://fleet.example.test",
            token=None,
            ca_cert=None,
            transport="broker",
            local_build=False,
        ),
    )

    assert starts == [(next_image, None)]
    persisted = json.loads(state_path.read_text(encoding="utf-8"))
    assert "runtime_image_override" not in persisted
    assert persisted["worker_image_digest"] == IMAGE
    assert persisted["bootstrap"]["worker_image_digest"] == next_image


def test_worker_compose_env_separates_local_runtime_from_expected_digest(tmp_path):
    paths = fleet_cli.RuntimePaths(tmp_path)
    values = fleet_cli._worker_compose_env(
        paths,
        {"node_id": NODE_ID, "worker_image_digest": IMAGE},
        runtime_image="shakerscan-fleet-local:abc1234",
    )
    assert values["FLEET_WORKER_IMAGE"] == "shakerscan-fleet-local:abc1234"
    assert values["FLEET_EXPECTED_WORKER_IMAGE_DIGEST"] == IMAGE
    expected_uid = 10001 if os.geteuid() == 0 else os.geteuid()
    expected_gid = 10001 if os.geteuid() == 0 else os.getegid()
    assert values["MODEL_INTAKE_SANDBOX_UID"] == str(expected_uid)
    assert values["MODEL_INTAKE_SANDBOX_GID"] == str(expected_gid)


def test_broker_runtime_forces_per_node_compose_project_and_skips_pull_for_local_image(
    tmp_path, monkeypatch
):
    paths = fleet_cli.RuntimePaths(tmp_path)
    paths.broker_worker_compose.write_text("services: {}\n", encoding="utf-8")
    calls = []
    monkeypatch.setattr(fleet_cli, "_docker_compose_command", lambda: ["docker", "compose"])
    monkeypatch.setattr(
        fleet_cli,
        "_prune_obsolete_local_broker_images",
        lambda **_kwargs: [],
    )
    monkeypatch.setattr(
        fleet_cli,
        "_run",
        lambda argv, **kwargs: calls.append((argv, kwargs))
        or types.SimpleNamespace(returncode=0, stdout=""),
    )

    fleet_cli._start_broker_runtime(
        paths,
        {"node_id": NODE_ID, "worker_image_digest": IMAGE},
        runtime_image="shakerscan-fleet-local:abc1234",
    )

    assert len(calls) == 2
    assert calls[0][0][:2] == ["docker", "ps"]
    assert "-a" in calls[0][0]
    argv = calls[1][0]
    assert argv[:4] == ["docker", "compose", "--project-name", "shakerscan-fleet-11111111"]
    assert "pull" not in argv
    result_root = tmp_path / "results"
    assert result_root.is_dir()
    assert result_root.stat().st_mode & 0o777 == 0o755
    quarantine = result_root / "model-intake-quarantine"
    assert quarantine.is_dir()
    assert quarantine.stat().st_mode & 0o777 == 0o755
    sandbox = result_root / "model-intake-sandbox"
    assert sandbox.is_dir()
    assert sandbox.stat().st_mode & 0o777 == 0o700


def test_worker_result_directory_preparation_repairs_docker_created_sandbox(tmp_path):
    paths = fleet_cli.RuntimePaths(tmp_path)
    sandbox = tmp_path / "results" / "model-intake-sandbox"
    sandbox.mkdir(parents=True, mode=0o755)
    sandbox.chmod(0o755)

    fleet_cli._prepare_worker_result_directories(paths)

    assert sandbox.stat().st_mode & 0o777 == 0o700


def test_sandbox_queue_owner_uses_os_chown_for_root(monkeypatch, tmp_path):
    queue = tmp_path / "queue"
    queue.mkdir()
    calls = []
    monkeypatch.setattr(fleet_cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(fleet_cli.os, "chown", lambda path, uid, gid: calls.append((path, uid, gid)))

    assert fleet_cli._sandbox_runtime_identity() == (10001, 10001)
    fleet_cli._set_sandbox_queue_owner(queue, 10001, 10001)

    assert calls == [(queue, 10001, 10001)]


def test_sandbox_runtime_identity_preserves_existing_non_root_owner(monkeypatch, tmp_path):
    queue = tmp_path / "queue"
    queue.mkdir()
    monkeypatch.setattr(fleet_cli.os, "geteuid", lambda: 2000)
    monkeypatch.setattr(fleet_cli.os, "getegid", lambda: 2000)
    stat_result = queue.stat()
    original_stat = fleet_cli.Path.stat

    def fake_stat(self, *args, **kwargs):
        if self != queue:
            return original_stat(self, *args, **kwargs)
        return types.SimpleNamespace(
            st_uid=10001 if self == queue else stat_result.st_uid,
            st_gid=10001 if self == queue else stat_result.st_gid,
            st_mode=stat_result.st_mode,
        )

    monkeypatch.setattr(fleet_cli.Path, "stat", fake_stat)

    assert fleet_cli._sandbox_runtime_identity(queue) == (10001, 10001)


def test_repair_permissions_requires_root_and_confirmation(monkeypatch, tmp_path):
    paths = fleet_cli.RuntimePaths(tmp_path)
    monkeypatch.setattr(fleet_cli, "_require_linux", lambda: None)
    monkeypatch.setattr(fleet_cli.os, "geteuid", lambda: 1000)
    with pytest.raises(fleet_cli.FleetCLIError, match="requires host root"):
        fleet_cli.command_repair_permissions(paths, types.SimpleNamespace(confirm=True))

    monkeypatch.setattr(fleet_cli.os, "geteuid", lambda: 0)
    with pytest.raises(fleet_cli.FleetCLIError, match="requires --confirm"):
        fleet_cli.command_repair_permissions(paths, types.SimpleNamespace(confirm=False))


def test_worker_result_directory_preparation_rejects_symlink(tmp_path):
    paths = fleet_cli.RuntimePaths(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    results = tmp_path / "results"
    results.symlink_to(outside, target_is_directory=True)

    with pytest.raises(fleet_cli.FleetCLIError, match="must not be a symlink"):
        fleet_cli._prepare_worker_result_directories(paths)


def test_broker_runtime_stops_only_standalone_project_and_preserves_volumes(tmp_path, monkeypatch):
    paths = fleet_cli.RuntimePaths(tmp_path)
    paths.broker_worker_compose.write_text("services: {}\n", encoding="utf-8")
    (tmp_path / "docker-compose.release.yml").write_text("services: {}\n", encoding="utf-8")
    paths.dotenv.write_text("COMPOSE_PROJECT_NAME=custom-scan\n", encoding="utf-8")
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        if argv[:2] == ["docker", "ps"]:
            return types.SimpleNamespace(returncode=0, stdout="standalone-id\n")
        return types.SimpleNamespace(returncode=0, stdout="")

    monkeypatch.setattr(fleet_cli, "_docker_compose_command", lambda: ["docker", "compose"])
    monkeypatch.setattr(fleet_cli, "_run", fake_run)

    fleet_cli._stop_standalone_runtime_for_worker(paths)

    down = calls[1][0]
    assert down[:4] == ["docker", "compose", "--project-name", "custom-scan"]
    assert "down" in down
    assert "--remove-orphans" in down
    assert "--volumes" not in down
    assert "-v" not in down


def test_worker_only_conversion_honors_process_compose_project(tmp_path, monkeypatch):
    paths = fleet_cli.RuntimePaths(tmp_path)
    (tmp_path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return types.SimpleNamespace(returncode=0, stdout="standalone-id\n")

    monkeypatch.setenv("COMPOSE_PROJECT_NAME", "operator-project")
    monkeypatch.setattr(fleet_cli, "_docker_compose_command", lambda: ["docker", "compose"])
    monkeypatch.setattr(fleet_cli, "_run", fake_run)

    fleet_cli._stop_standalone_runtime_for_worker(paths)

    assert "label=com.docker.compose.project=operator-project" in calls[0][0]
    assert calls[1][0][3] == "operator-project"


def test_worker_only_conversion_rejects_control_plane_runtime(tmp_path):
    paths = fleet_cli.RuntimePaths(tmp_path)
    paths.dotenv.write_text("FLEET_NETWORK_BACKEND=broker\n", encoding="utf-8")

    with pytest.raises(fleet_cli.FleetCLIError, match="control plane cannot also join"):
        fleet_cli._stop_standalone_runtime_for_worker(paths)


def test_persist_worker_runtime_template_captures_only_clone_allowlist(tmp_path, monkeypatch):
    paths = fleet_cli.RuntimePaths(tmp_path)
    paths.node.mkdir(parents=True)
    state_path = paths.node / "state.json"
    state_path.write_text(json.dumps({"node_id": NODE_ID}), encoding="utf-8")
    state_path.chmod(0o600)

    def fake_run(argv, **_kwargs):
        if argv[:2] == ["docker", "ps"]:
            assert "-a" not in argv
            return types.SimpleNamespace(returncode=0, stdout="worker123\n")
        if argv[:2] == ["docker", "inspect"]:
            return types.SimpleNamespace(
                returncode=0,
                stdout=json.dumps([
                    {
                        "Config": {
                            "Image": IMAGE,
                            "Cmd": ["python3", "/app/broker_worker.py"],
                            "Env": ["SAFE=1"],
                            "Labels": {
                                "com.docker.compose.project": "shakerscan-fleet-11111111",
                                "com.docker.compose.service": "worker",
                                "com.docker.compose.container-number": "1",
                                "com.shakerscan.node_id": NODE_ID,
                                "com.shakerscan.fleet_managed": "true",
                            },
                            "WorkingDir": "/app",
                        },
                        "HostConfig": {
                            "Binds": ["/srv/results:/results:rw"],
                            "NetworkMode": "fleet-test_default",
                            "RestartPolicy": {"Name": "unless-stopped"},
                            "Memory": 1024,
                            "Privileged": True,
                        },
                    }
                ]),
            )
        raise AssertionError(argv)

    monkeypatch.setattr(fleet_cli, "_run", fake_run)
    fleet_cli._persist_worker_runtime_template(
        paths,
        {"node_id": NODE_ID, "worker_image_digest": IMAGE},
    )

    persisted = json.loads(state_path.read_text(encoding="utf-8"))["worker_runtime_template"]
    assert persisted["Config"]["Cmd"] == ["python3", "/app/broker_worker.py"]
    assert persisted["HostConfig"]["Binds"] == ["/srv/results:/results:rw"]
    assert "Privileged" not in persisted["HostConfig"]


def test_persist_worker_runtime_template_ignores_exited_replacements_and_accepts_scaled_workers(
    tmp_path, monkeypatch
):
    paths = fleet_cli.RuntimePaths(tmp_path)
    paths.node.mkdir(parents=True)
    state_path = paths.node / "state.json"
    state_path.write_text(
        json.dumps(
            {
                "node_id": NODE_ID,
                "runtime_image_override": "shakerscan-fleet-local:abc1234",
            }
        ),
        encoding="utf-8",
    )
    state_path.chmod(0o600)

    def worker_item(container_number, marker):
        return {
            "Config": {
                "Image": "shakerscan-fleet-local:abc1234",
                "Cmd": ["python3", "/app/broker_worker.py"],
                "Env": [f"WORKER_MARKER={marker}"],
                "Labels": {
                    "com.docker.compose.project": "shakerscan-fleet-11111111",
                    "com.docker.compose.service": "worker",
                    "com.docker.compose.container-number": str(container_number),
                    "com.shakerscan.node_id": NODE_ID,
                    "com.shakerscan.fleet_managed": "true",
                },
                "WorkingDir": "/app",
            },
            "HostConfig": {"NetworkMode": "fleet-test_default"},
        }

    def fake_run(argv, **_kwargs):
        if argv[:2] == ["docker", "ps"]:
            assert "-a" not in argv
            return types.SimpleNamespace(returncode=0, stdout="worker5\nworker4\n")
        if argv[:2] == ["docker", "inspect"]:
            assert argv[2:] == ["worker5", "worker4"]
            return types.SimpleNamespace(
                returncode=0,
                stdout=json.dumps([worker_item(5, "later"), worker_item(4, "seed")]),
            )
        raise AssertionError(argv)

    monkeypatch.setattr(fleet_cli, "_run", fake_run)
    fleet_cli._persist_worker_runtime_template(
        paths,
        {"node_id": NODE_ID, "worker_image_digest": IMAGE},
    )

    persisted = json.loads(state_path.read_text(encoding="utf-8"))["worker_runtime_template"]
    assert "WORKER_MARKER=seed" in persisted["Config"]["Env"]


def test_local_broker_image_cleanup_removes_only_obsolete_product_tags(monkeypatch):
    calls = []

    def fake_run(argv, **_kwargs):
        calls.append(argv)
        if argv[:3] == ["docker", "image", "ls"]:
            return types.SimpleNamespace(
                returncode=0,
                stdout=(
                    "shakerscan-fleet-local:abc1234\n"
                    "shakerscan-fleet-local:old1234\n"
                    "unrelated:latest\n"
                ),
            )
        return types.SimpleNamespace(returncode=0, stdout="")

    monkeypatch.setattr(fleet_cli, "_run", fake_run)

    removed = fleet_cli._prune_obsolete_local_broker_images(
        keep_image="shakerscan-fleet-local:abc1234"
    )

    assert removed == ["shakerscan-fleet-local:old1234"]
    assert ["docker", "image", "rm", "unrelated:latest"] not in calls


def test_local_broker_build_warns_but_continues_when_disk_is_low(tmp_path, monkeypatch, capsys):
    paths = fleet_cli.RuntimePaths(tmp_path)
    (tmp_path / "scanner").mkdir()
    (tmp_path / "scanner" / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / "broker_worker.py").write_text("", encoding="utf-8")
    built = []
    revision = "abc1234567890abc1234567890abc1234567890a"

    def fake_run(argv, **_kwargs):
        if argv[:4] == ["git", "-C", str(tmp_path), "rev-parse"]:
            return types.SimpleNamespace(returncode=0, stdout=f"{revision}\n")
        if argv[:2] == ["docker", "build"]:
            built.append(argv)
        return types.SimpleNamespace(returncode=0, stdout="")

    monkeypatch.setattr(fleet_cli, "_run", fake_run)
    monkeypatch.setattr(fleet_cli.shutil, "which", lambda _name: "/usr/bin/git")
    monkeypatch.setattr(
        fleet_cli,
        "_prune_obsolete_local_broker_images",
        lambda **_kwargs: [],
    )
    monkeypatch.setattr(
        fleet_cli.shutil,
        "disk_usage",
        lambda _path: types.SimpleNamespace(free=2 * 1024**3),
    )

    assert fleet_cli._build_local_broker_worker_image(paths) == "shakerscan-fleet-local:abc123456789"
    assert len(built) == 1
    assert ["--build-arg", "SCANNER_VERSION=abc123456789"] == built[0][2:4]
    assert ["--build-arg", f"SCANNER_SOURCE_REVISION={revision}"] == built[0][4:6]
    assert "build will continue" in capsys.readouterr().out


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
    monkeypatch.setattr(fleet_cli, "_start_broker_runtime", lambda *_args, **_kwargs: None)

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
            budget_profile=[],
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
    paths.dotenv.write_text(
        "SHAKERSCAN_BIND_HOST=100.121.87.22\nSHAKERSCAN_API_PORT=9080\n",
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
    monkeypatch.setattr(
        fleet_cli,
        "http_response",
        lambda *_args, **_kwargs: (401, b'{"detail":"node bearer credential is required"}'),
    )

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
    artifact_checks = [item for item in calls if item[1].startswith("/artifacts/storage/health")]
    assert [item[0] for item in artifact_checks] == ["http://100.121.87.22:9080"]
    env = fleet_cli.load_dotenv(paths.dotenv)
    assert env["EVIDENCE_S3_ENDPOINT_URL"] == "http://minio:9000"
    assert env["COMPOSE_PROFILES"] == "artifacts"


def test_wait_for_artifact_store_retries_transient_startup_failures(tmp_path, monkeypatch):
    paths = fleet_cli.RuntimePaths(tmp_path)
    attempts = iter(
        [
            fleet_cli.FleetCLIError("control plane returned HTTP 503: HTTPError"),
            {"status": "error", "backend": "s3", "error": "HTTPError"},
            {"status": "ok", "backend": "s3", "write_probe": True},
        ]
    )
    calls = []

    def fake_api(base, method, path, **kwargs):
        calls.append((base, method, path, kwargs.get("timeout")))
        result = next(attempts)
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(fleet_cli, "api_json", fake_api)
    monkeypatch.setattr(fleet_cli.time, "sleep", lambda _seconds: None)

    fleet_cli._wait_for_artifact_store(paths, timeout=1)

    assert calls == [
        ("http://127.0.0.1:8080", "GET", "/artifacts/storage/health?probe=true", 15),
        ("http://127.0.0.1:8080", "GET", "/artifacts/storage/health?probe=true", 15),
        ("http://127.0.0.1:8080", "GET", "/artifacts/storage/health?probe=true", 15),
    ]


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


def test_broker_artifact_environment_repairs_legacy_loopback_minio_endpoint():
    updates, bundled = fleet_cli._fleet_artifact_environment(
        "minio",
        {
            "COMPOSE_PROFILES": "artifacts,fleet-gateway",
            "EVIDENCE_STORAGE_BACKEND": "s3",
            "EVIDENCE_S3_ENDPOINT_URL": "http://127.0.0.1:9000",
            "EVIDENCE_S3_BUCKET": "shakerscan-artifacts",
            "EVIDENCE_S3_ACCESS_KEY_ID": "generated-user",
            "EVIDENCE_S3_SECRET_ACCESS_KEY": "generated-password",
            "MINIO_ROOT_USER": "generated-user",
            "MINIO_ROOT_PASSWORD": "generated-password",
        },
    )

    assert bundled is True
    assert updates["EVIDENCE_S3_ENDPOINT_URL"] == "http://minio:9000"
    assert updates["MINIO_ROOT_USER"] == "generated-user"
    assert updates["MINIO_ROOT_PASSWORD"] == "generated-password"


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


def test_runtime_image_env_prefers_launcher_release_tag(monkeypatch):
    monkeypatch.setenv("SCANNER_IMAGE_TAG", "0.8.2")
    monkeypatch.setenv("SCANNER_IMAGE_REPO", "shakerscan/shakerscan-scanner")

    values = fleet_cli.runtime_image_env({"SCANNER_IMAGE_TAG": "latest", "KEEP": "value"})

    assert values == {
        "SCANNER_IMAGE_TAG": "0.8.2",
        "SCANNER_IMAGE_REPO": "shakerscan/shakerscan-scanner",
        "KEEP": "value",
    }


def test_managed_gateway_caddyfile_only_exposes_worker_routes():
    secret = "g" * 48
    rendered = fleet_cli.render_managed_caddyfile("https://fleet.example.test", secret)
    assert rendered.startswith("# Managed by ShakerScan")
    assert "fleet.example.test {" in rendered
    assert "path /fleet/nodes/join" in rendered
    assert "path /fleet/broker/*" in rendered
    assert "/fleet/nodes/[0-9a-fA-F-]+/state" in rendered
    assert "/fleet/nodes/[0-9a-fA-F-]+/heartbeat" in rendered
    assert 'respond "Not found" 404' in rendered
    assert "rewrite * /fleet/public-health" in rendered
    assert "header_up X-Forwarded-Proto https" in rendered
    assert rendered.count("header_up X-Forwarded-For {remote_host}") == 5
    assert f"header_up X-ShakerScan-Gateway-Secret {secret}" in rendered
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


def test_broker_auto_preflight_selects_managed_when_healthy_proxy_lacks_trust_boundary(
    tmp_path, monkeypatch, capsys
):
    paths = fleet_cli.RuntimePaths(tmp_path)
    monkeypatch.setattr(fleet_cli, "_require_linux", lambda: None)
    monkeypatch.setattr(fleet_cli, "_require_commands", lambda _names: None)
    monkeypatch.setattr(fleet_cli, "_docker_compose_command", lambda: ["docker", "compose"])
    monkeypatch.setattr(fleet_cli, "_require_healthy_api", lambda *_args: None)
    monkeypatch.setattr(
        fleet_cli,
        "_require_public_fleet_auth_boundary",
        lambda *_args: (_ for _ in ()).throw(fleet_cli.FleetCLIError("protected route returned HTTP 400")),
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
    output = capsys.readouterr().out
    assert "HTTPS is reachable but its fleet trust boundary is not ready" in output
    assert "[FAIL]" not in output


def test_broker_auto_preflight_reuses_only_verified_external_proxy(tmp_path, monkeypatch, capsys):
    paths = fleet_cli.RuntimePaths(tmp_path)
    boundary_calls = []
    monkeypatch.setattr(fleet_cli, "_require_linux", lambda: None)
    monkeypatch.setattr(fleet_cli, "_require_commands", lambda _names: None)
    monkeypatch.setattr(fleet_cli, "_docker_compose_command", lambda: ["docker", "compose"])
    monkeypatch.setattr(fleet_cli, "_require_healthy_api", lambda *_args: None)
    monkeypatch.setattr(
        fleet_cli,
        "_require_public_fleet_auth_boundary",
        lambda *args: boundary_calls.append(args),
    )

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

    assert prepared["https_mode"] == "external"
    assert boundary_calls == [("https://fleet.example.test", None)]
    output = capsys.readouterr().out
    assert output.count("Broker HTTPS authentication boundary") == 1


def test_managed_gateway_state_recognizes_pre_secret_gateway_file(tmp_path):
    paths = fleet_cli.RuntimePaths(tmp_path)
    paths.control.mkdir(parents=True)
    paths.gateway_config.write_text(
        "# Managed by ShakerScan. Local UI and operator APIs are intentionally not public.\n",
        encoding="utf-8",
    )

    assert fleet_cli._managed_gateway_state_present(paths, {}) is True
    assert fleet_cli._managed_gateway_state_present(
        fleet_cli.RuntimePaths(tmp_path / "other"),
        {"COMPOSE_PROFILES": "artifacts,fleet-gateway"},
    ) is True


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
    assert len(env["FLEET_GATEWAY_PROXY_SECRET"]) >= 32
    assert paths.gateway_config.stat().st_mode & 0o777 == 0o600
    assert "fleet.example.test {" in paths.gateway_config.read_text(encoding="utf-8")
    assert env["FLEET_GATEWAY_PROXY_SECRET"] in paths.gateway_config.read_text(encoding="utf-8")
    assert isolation_checks == [("https://fleet.example.test", None)]


def test_public_fleet_auth_boundary_requires_unauthenticated_401(monkeypatch):
    monkeypatch.setattr(
        fleet_cli,
        "http_response",
        lambda *_args, **_kwargs: (401, b'{"detail":"node bearer credential is required"}'),
    )
    fleet_cli._require_public_fleet_auth_boundary("https://fleet.example.test", None)
    monkeypatch.setattr(
        fleet_cli,
        "http_response",
        lambda *_args, **_kwargs: (401, b'{"detail":"proxy authentication required"}'),
    )
    with pytest.raises(fleet_cli.FleetCLIError, match="expected ShakerScan"):
        fleet_cli._require_public_fleet_auth_boundary("https://fleet.example.test", None)


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
