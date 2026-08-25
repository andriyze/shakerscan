from __future__ import annotations

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
