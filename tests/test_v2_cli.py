from __future__ import annotations

import json
import sys

import pytest


sys.path.insert(0, "scripts")
import v2_cli  # noqa: E402


HUNT_CONTRACT = {
    "schema_version": "hunt-start/v2",
    "target_kinds": ["web", "api", "network", "device"],
    "budget_profiles": {
        "balanced": {
            "max_active_actions": 20,
            "max_state_changing_requests": 20,
            "max_hosts": 500,
        },
    },
    "budget_dimensions": [
        {"name": "max_active_actions", "minimum": 0, "zeroable": True},
        {"name": "max_state_changing_requests", "minimum": 0, "zeroable": True},
        {"name": "max_hosts", "minimum": 0, "zeroable": True},
    ],
}


def _parse(*values: str):
    return v2_cli.build_parser().parse_args(["--api-url", "http://localhost:8080", *values])


def test_hunt_start_cli_uses_server_contract_and_preserves_explicit_zero():
    args = _parse(
        "hunt", "start", "--target-id", "target-1", "--target-kind", "web",
        "--budget", "max_active_actions=0",
        "--budget", "max_state_changing_requests=0",
        "--credential-ref", "primary_credential_profile_id=profile-1",
        "--collection-id", "collection-1",
    )
    payload = v2_cli._hunt_start_payload(args, HUNT_CONTRACT)
    assert payload["schema_version"] == "hunt-start/v2"
    assert payload["target_kind"] == "web"
    assert payload["budgets"]["max_active_actions"] == 0
    assert payload["budgets"]["max_state_changing_requests"] == 0
    assert payload["credential_refs"] == {
        "primary_credential_profile_id": "profile-1",
    }
    assert payload["request_collection_ids"] == ["collection-1"]
    assert "scan_type" not in payload


def test_hunt_start_cli_rejects_client_only_budget_or_target_kind():
    with pytest.raises(v2_cli.CliError, match="budget dimension"):
        v2_cli._hunt_start_payload(
            _parse(
                "hunt", "start", "--target-id", "target-1", "--target-kind", "web",
                "--budget", "invented_budget=1",
            ),
            HUNT_CONTRACT,
        )
    with pytest.raises(v2_cli.CliError, match="target kind"):
        v2_cli._hunt_start_payload(
            _parse(
                "hunt", "start", "--target-id", "target-1", "--target-kind", "firmware",
            ),
            HUNT_CONTRACT,
        )


def test_hunt_cli_help_is_first_class_and_non_mutating(capsys):
    with pytest.raises(SystemExit) as exc:
        v2_cli.build_parser().parse_args(["hunt", "--help"])
    assert exc.value.code == 0
    output = capsys.readouterr().out
    assert "start" in output
    assert "call" in output
    assert "deep-hunt" not in output


def test_credential_requests_are_checked_against_server_published_schema():
    schema = {
        "properties": {"target_id": {}, "secret": {}},
        "required": ["target_id", "secret"],
        "additionalProperties": False,
    }
    assert v2_cli._validate_schema_object(
        {"target_id": "target-1", "secret": "worker-only"}, schema,
        label="credential",
    )["secret"] == "worker-only"
    with pytest.raises(v2_cli.CliError, match="unsupported fields"):
        v2_cli._validate_schema_object(
            {"target_id": "target-1", "secret": "worker-only", "argv": []},
            schema,
            label="credential",
        )


def test_credentials_and_collections_are_first_class_commands():
    parser = v2_cli.build_parser()
    create = parser.parse_args([
        "--api-url", "http://localhost:8080", "credentials", "create",
        "--request", "-",
    ])
    assert create.credentials_command == "create"
    rotate = parser.parse_args([
        "--api-url", "http://localhost:8080", "credentials", "rotate",
        "profile-1", "--request", "-",
    ])
    assert rotate.profile_id == "profile-1"
    select = parser.parse_args([
        "--api-url", "http://localhost:8080", "collections", "select",
        "collection-1", "--method", "get", "--limit", "12",
    ])
    assert select.collections_command == "select"
    assert select.method == ["get"]
    assert select.limit == 12


def test_collection_upload_document_accepts_json_or_openapi_yaml(tmp_path):
    json_path = tmp_path / "postman.json"
    json_path.write_text('{"info":{"name":"fixture"}}')
    yaml_path = tmp_path / "openapi.yaml"
    yaml_path.write_text("openapi: 3.0.0\npaths: {}\n")
    assert v2_cli._read_document(str(json_path)) == {"info": {"name": "fixture"}}
    assert v2_cli._read_document(str(yaml_path)).startswith("openapi:")


def test_evidence_export_is_first_class_and_requires_output_for_zip():
    args = v2_cli.build_parser().parse_args([
        "--api-url", "http://localhost:8080", "evidence", "export",
        "--scan-id", "scan-1", "--format", "zip",
    ])

    class FakeClient:
        def download(self, path):
            assert "scan_id=scan-1" in path
            assert "format=zip" in path
            return b"PKfixture", "application/zip"

    with pytest.raises(v2_cli.CliError, match="requires --output"):
        v2_cli._run_evidence(args, FakeClient())


def test_evidence_export_writes_atomically_without_implicit_overwrite(tmp_path):
    output = tmp_path / "manifest.json"
    assert v2_cli._write_export(str(output), b"{}", force=False) == output.resolve()
    assert output.read_bytes() == b"{}"
    with pytest.raises(v2_cli.CliError, match="already exists"):
        v2_cli._write_export(str(output), b"changed", force=False)
    v2_cli._write_export(str(output), b"changed", force=True)
    assert output.read_bytes() == b"changed"


def test_hunt_call_retry_without_explicit_key_is_content_stable():
    args = _parse(
        "hunt", "call", "hunt-1", "collections.inspect", "--input", "-",
    )

    class FakeClient:
        def get(self, path):
            assert path == "/hunts/hunt-1"
            return {"capabilities": [{"name": "collections.inspect"}]}

        def post(self, path, payload, **_kwargs):
            return {"path": path, "payload": payload}

    original_stdin = sys.stdin
    try:
        class Input:
            class Buffer:
                @staticmethod
                def read(_limit):
                    return b'{"limit":0}'

            buffer = Buffer()

        sys.stdin = Input()
        first = v2_cli._run_hunt(args, FakeClient())
        second = v2_cli._run_hunt(args, FakeClient())
    finally:
        sys.stdin = original_stdin

    assert first["idempotency_key"] == second["idempotency_key"]
    assert first["response"]["payload"]["input"]["limit"] == 0


def test_cli_errors_are_stable_json_and_preserve_api_shape(monkeypatch, capsys):
    args = [
        "--api-url", "http://localhost:8080",
        "credentials", "test", "profile-1",
    ]

    def fail(_path):
        raise v2_cli.CliError(
            "profile unavailable",
            error_type="api_error",
            http_status=409,
            api_detail={"error": "profile_conflict"},
        )

    monkeypatch.setattr(v2_cli.ApiClient, "get", lambda self, path: fail(path))
    assert v2_cli.main(args) == 2
    assert json.loads(capsys.readouterr().err) == {
        "api_detail": {"error": "profile_conflict"},
        "error": "api_error",
        "http_status": 409,
        "message": "profile unavailable",
        "schema_version": "shakerscan-cli-error/v1",
    }


def test_mutating_commands_accept_only_secret_safe_retry_key_flags():
    help_text = v2_cli.build_parser().format_help()
    assert "--password" not in help_text
    assert "--secret" not in help_text
    assert "--token" not in help_text

    for values in (
        ("hunt", "start", "--idempotency-key", "retry-key-01"),
        ("credentials", "create", "--request", "-", "--idempotency-key", "retry-key-02"),
        ("credentials", "rotate", "profile-1", "--request", "-", "--idempotency-key", "retry-key-03"),
        ("collections", "upload", "fixture.json", "--idempotency-key", "retry-key-04"),
        ("collections", "bind", "collection-1", "--idempotency-key", "retry-key-05"),
        ("collections", "select", "collection-1", "--idempotency-key", "retry-key-06"),
    ):
        parsed = _parse(*values)
        assert parsed.idempotency_key.startswith("retry-key-")
