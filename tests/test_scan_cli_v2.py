from __future__ import annotations

import json

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

    def request(url, *, payload=None, compatibility_command=None):
        calls.append((url, payload, compatibility_command))
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


def test_legacy_alias_warns_translates_and_never_enters_payload(monkeypatch, capsys):
    result, calls = _run(monkeypatch, [
        "https://example.com", "--compatibility-alias", "smart",
        "--confirm-active", "--json",
    ])

    assert result == 0
    captured = capsys.readouterr()
    warning = json.loads(captured.err)
    assert warning["schema_version"] == "scan-cli-deprecation/v1"
    assert warning["sunset"] == "2026-12-31"
    assert warning["canonical_translation"] == {
        "active_testing": True,
        "budget_profile": "thorough",
        "engine": "scan",
    }
    payload = calls[-1][1]
    assert payload["budget_profile"] == "thorough"
    assert payload["policy"]["active_testing"] is True
    assert "smart" not in json.dumps(payload)
    assert calls[-1][2] == "scan-smart"


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
