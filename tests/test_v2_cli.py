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
