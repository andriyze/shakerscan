from __future__ import annotations

import json
import pytest

from scripts import scan_cli


def _contract() -> dict:
    profiles = {
        "fast": 25,
        "balanced": 100,
        "thorough": 500,
    }
    return {
        "schema_version": "scan-public-contract/v1",
        "families": [
            {"name": name} for name in ("recon", "nuclei", "xss", "sqli", "bola")
        ],
        "advanced_limits": [{
            "name": name,
            "minimum": 0 if name == "max_state_changing_requests" else 1,
            "profile_ceilings": profiles,
        } for name in scan_cli.ADVANCED_FLAGS],
    }


def _run(monkeypatch, argv):
    calls = []

    def request(url, *, payload=None):
        calls.append((url, payload))
        if payload is None:
            return _contract()
        return {"scan_id": "00000000-0000-0000-0000-000000000001", "status": "queued"}

    monkeypatch.setattr(scan_cli, "_request_json", request)
    result = scan_cli.main([
        "--api-url", "http://api.test:8080",
        "--ui-url", "http://ui.test:3000",
        *argv,
    ])
    return result, calls


def test_scan_cli_emits_v2_json_and_canonical_secret_free_request(monkeypatch, capsys):
    result, calls = _run(monkeypatch, [
        "https://example.com",
        "--budget-profile", "balanced",
        "--active-testing",
        "--confirm-active",
        "--include-family", "xss,sqli",
        "--exclude-family", "nuclei",
        "--credential-profile", "profile-1",
        "--collection-selection", "selection-1",
        "--approval-receipt", "approval-1",
        "--placement", "remote",
        "--max-state-changing-requests", "0",
        "--json",
    ])

    assert result == 0
    output = json.loads(capsys.readouterr().out)
    assert output == {
        "active_testing": True,
        "budget_profile": "balanced",
        "engine": "scan",
        "scan_id": "00000000-0000-0000-0000-000000000001",
        "schema_version": "scan-start/v2",
        "status": "queued",
        "ui_url": "http://ui.test:3000/scans/00000000-0000-0000-0000-000000000001",
    }
    payload = calls[-1][1]
    assert payload["policy"]["include_families"] == ["xss", "sqli"]
    assert payload["policy"]["exclude_families"] == ["nuclei"]
    assert payload["advanced"]["max_state_changing_requests"] == 0
    assert payload["credential_profile_ids"] == ["profile-1"]
    assert payload["request_collections"] == [{"id": "selection-1"}]
    assert payload["options"]["placement"] == {"node_scope": "remote"}
    assert "scan_type" not in repr(payload)
    assert "password" not in repr(payload).lower()


def test_legacy_aliases_are_not_accepted_by_the_cli():
    parser = scan_cli._parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["https://example.com", "--type", "smart"])
    with pytest.raises(SystemExit):
        parser.parse_args([
            "https://example.com", "--compatibility-alias", "smart",
        ])


def test_cli_network_error_has_stable_json_error_and_exit_code(monkeypatch, capsys):
    def failed(*_args, **_kwargs):
        raise scan_cli.ScanCliError("could not reach the ShakerScan API")

    monkeypatch.setattr(scan_cli, "_request_json", failed)
    result = scan_cli.main([
        "--api-url", "http://api.test:8080",
        "--ui-url", "http://ui.test:3000",
        "https://example.com", "--json",
    ])

    assert result == 1
    error = json.loads(capsys.readouterr().err)
    assert error == {
        "error": "could not reach the ShakerScan API",
        "schema_version": "scan-start-error/v1",
    }


def test_cli_help_exposes_v2_authority_without_raw_secret_flags():
    help_text = scan_cli._parser().format_help()

    assert "--include-family" in help_text
    assert "--credential-profile" in help_text
    assert "--collection-selection" in help_text
    assert "--placement" in help_text
    assert "--json" in help_text
    assert "--password" not in help_text
    assert "--auth-header" not in help_text
    assert "--type" not in help_text
    assert "--compatibility-alias" not in help_text
