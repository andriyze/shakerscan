from __future__ import annotations

import json
import types

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
            {"name": name} for name in ("recon", "nuclei", "nuclei_active", "xss", "sqli", "bola")
        ],
        "advanced_limits": [{
            "name": name,
            "minimum": 0 if name == "max_state_changing_requests" else 1,
            "profile_ceilings": profiles,
        } for name in scan_cli.ADVANCED_FLAGS],
    }


def _run(monkeypatch, argv):
    calls = []

    def request(url, *, payload=None, idempotency_key=None):
        calls.append((url, payload, idempotency_key))
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


def test_scan_cli_retry_key_is_forwarded_and_returned(monkeypatch, capsys):
    result, calls = _run(monkeypatch, [
        "https://example.com", "--json", "--idempotency-key", "scan-retry-0001",
    ])

    assert result == 0
    assert calls[-1][2] == "scan-retry-0001"
    assert json.loads(capsys.readouterr().out)["idempotency_key"] == "scan-retry-0001"


def test_auth_state_shards_require_explicit_parallel_execution():
    args = scan_cli._parser().parse_args([
        "https://example.com",
        "--api-url", "http://api.test:8080",
        "--ui-url", "http://ui.test:3000",
        "--auth-state-shards",
    ])

    with pytest.raises(scan_cli.ScanCliError, match="requires --execution"):
        scan_cli._payload(args)


def test_scan_api_error_json_preserves_sanitized_status_and_detail(monkeypatch, capsys):
    def failed(*_args, **_kwargs):
        raise scan_cli.ScanCliError(
            "API rejected the request (HTTP 409): retry conflict",
            http_status=409,
            api_detail={"error": "idempotency_key_reused", "message": "retry conflict"},
        )

    monkeypatch.setattr(scan_cli, "_request_json", failed)
    result = scan_cli.main([
        "--api-url", "http://api.test:8080",
        "--ui-url", "http://ui.test:3000",
        "https://example.com", "--json",
    ])

    assert result == 1
    assert json.loads(capsys.readouterr().err) == {
        "api_detail": {
            "error": "idempotency_key_reused", "message": "retry conflict",
        },
        "error": "API rejected the request (HTTP 409): retry conflict",
        "http_status": 409,
        "schema_version": "scan-start-error/v1",
    }



def test_scan_cli_sends_the_bearer_token_from_a_file_over_https_only(tmp_path, monkeypatch):
    import scan_cli

    token_file = tmp_path / "token"
    token_file.write_text("sse_secret\n", encoding="utf-8")
    monkeypatch.setenv("SHAKERSCAN_API_TOKEN_FILE", str(token_file))
    seen = {}

    class Response:
        status = 200

        def read(self):
            return b'{"ok": true}'

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(request, timeout=None):
        seen["auth"] = request.get_header("Authorization")
        return Response()

    monkeypatch.setattr(scan_cli, "_opener", lambda: types.SimpleNamespace(open=fake_urlopen))
    assert scan_cli._request_json("https://scanner.example.com/scan/contracts") == {"ok": True}
    assert seen["auth"] == "Bearer sse_secret"
    with pytest.raises(scan_cli.ScanCliError, match="https"):
        scan_cli._request_json("http://127.0.0.1:8080/scan/contracts")


def _run_with_response(monkeypatch, argv, response):
    def request(url, *, payload=None, idempotency_key=None):
        return _contract() if payload is None else dict(response)

    monkeypatch.setattr(scan_cli, "_request_json", request)
    return scan_cli.main(["--api-url", "http://api.test:8080", "--ui-url", "http://ui.test:3000", *argv])


_FALLBACK_RESPONSE = {
    "scan_id": "00000000-0000-0000-0000-000000000002",
    "status": "queued",
    "target": "https://www.example.com",
    "notice": "example.com has no address record; using www.example.com.",
    "dns_fallback": {
        "requested_host": "example.com",
        "resolved_host": "www.example.com",
        "resolved_url": "https://www.example.com",
        "reason": "no_address_record",
        "message": "example.com has no address record; using www.example.com.",
    },
}


def test_scan_cli_tells_the_user_when_the_www_twin_was_scanned(monkeypatch, capsys):
    assert _run_with_response(monkeypatch, ["example.com"], _FALLBACK_RESPONSE) == 0
    out = capsys.readouterr().out
    assert "Notice: example.com has no address record; using www.example.com." in out
    assert "Target: https://www.example.com" in out


def test_scan_cli_json_carries_the_fallback_notice(monkeypatch, capsys):
    assert _run_with_response(monkeypatch, ["example.com", "--json"], _FALLBACK_RESPONSE) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["notice"] == "example.com has no address record; using www.example.com."
    assert output["target"] == "https://www.example.com"
    assert output["dns_fallback"]["resolved_host"] == "www.example.com"


def test_scan_cli_prints_no_notice_without_a_fallback(monkeypatch, capsys):
    response = {"scan_id": "00000000-0000-0000-0000-000000000003", "status": "queued"}
    assert _run_with_response(monkeypatch, ["example.com"], response) == 0
    assert "Notice:" not in capsys.readouterr().out


def _run_recording(monkeypatch, argv):
    calls = []

    def request(url, *, payload=None, idempotency_key=None):
        calls.append((url, payload, idempotency_key))
        if url.endswith("/scan/contracts"):
            return _contract()
        return {"scan_id": "00000000-0000-0000-0000-000000000001", "status": "queued"}

    monkeypatch.setattr(scan_cli, "_request_json", request)
    result = scan_cli.main([
        "--api-url", "http://api.test:8080",
        "--ui-url", "http://ui.test:3000",
        *argv,
    ])
    return result, calls


@pytest.mark.parametrize("authority", [
    ["--active-testing", "--confirm-active", "--allow-state-changing-http",
     "--collection-selection", "selection-1"],
    ["--credential-profile", "profile-1"],
])
def test_a_scan_without_a_receipt_is_left_to_the_servers_standing_authorization(
    monkeypatch, capsys, authority,
):
    """The CLI refused before any request ("the selected authority requires --approval-receipt").

    Admission already resolves the target's standing authorization when no receipt is passed,
    exactly as for New Scan in the UI, and refuses with its own reason when it does not cover the
    request. The CLI registers nothing itself, so a refused scan leaves no target behind.
    """
    result, calls = _run_recording(monkeypatch, ["https://example.com", *authority, "--json"])

    assert result == 0, capsys.readouterr().err
    assert [url for url, _payload, _key in calls] == [
        "http://api.test:8080/scan/contracts", "http://api.test:8080/scans",
    ]
    assert "approval_receipt_id" not in calls[-1][1]


def test_scan_help_word_prints_help_and_submits_nothing(monkeypatch, capsys):
    result, calls = _run(monkeypatch, ["help"])

    assert result == 0
    assert calls == []
    assert "--budget-profile" in capsys.readouterr().out


def test_scan_help_documents_the_active_confirmation_and_the_receipt():
    help_text = " ".join(scan_cli._parser().format_help().split())
    assert "--confirm-active" in help_text
    receipt_line = help_text[help_text.index("--approval-receipt UUID Target-bound"):]
    assert "standing authorization" in receipt_line.split("--idempotency-key")[0]


def test_the_state_changing_flag_says_it_includes_default_login_attempts():
    # The Scan form says so next to its switch; the terminal flag says the same.
    help_text = " ".join(scan_cli._parser().format_help().split())
    options = help_text[help_text.index("options:"):]
    flag_help = options[options.index("--allow-state-changing-http"):].split("--network-discovery")[0]
    assert "includes default-login attempts, which can lock accounts" in flag_help


# A thorough scan from the terminal ran no active templates. Both entry points send the same
# policy (the CLI implies the preset from --active-testing, New Scan names "standard_active"), and
# that preset now runs the active templates on the thorough and deep profiles.
@pytest.mark.parametrize("profile", ["fast", "balanced", "thorough", "deep"])
def test_terminal_and_new_scan_resolve_the_same_families_for_a_profile(monkeypatch, profile):
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
    from scan.contracts import public_scan_contract, resolve_scan_contract

    _result, calls = _run_recording(monkeypatch, [
        "https://example.com", "--budget-profile", profile, "--active-testing", "--confirm-active", "--json",
    ])
    terminal = calls[-1][1]["policy"]
    new_scan = {"preset": "standard_active", "active_testing": True, "include_families": [], "exclude_families": []}
    resolved = resolve_scan_contract(budget_profile=profile, policy=new_scan).execution_plan.resolved_families
    assert resolve_scan_contract(budget_profile=profile, policy=terminal).execution_plan.resolved_families == resolved
    assert ("nuclei_active" in resolved) is (profile in {"thorough", "deep"})
    contract = public_scan_contract()
    expected = set(contract["family_presets"]["standard_active"]) | set(
        contract["family_preset_profile_additions"]["standard_active"].get(profile, ()))
    assert resolved == tuple(item["name"] for item in contract["families"] if item["name"] in expected), (
        "the public contract states what the preset resolves to on this profile")
    # New Scan's local preview reads the same contract, with the profile's additions.
    page = (Path(__file__).resolve().parents[1] / "ui/src/app/scan/new/page.tsx").read_text()
    assert "family_preset_profile_additions" in page and "budgetProfile" in page


def test_excluding_the_active_templates_on_a_thorough_scan_removes_them():
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
    from scan.contracts import resolve_scan_contract

    contract = resolve_scan_contract(budget_profile="deep", policy={
        "active_testing": True, "exclude_families": ["nuclei_active"]})
    assert "nuclei_active" not in contract.execution_plan.resolved_families
    passive = resolve_scan_contract(budget_profile="deep", policy={})
    assert "nuclei_active" not in passive.execution_plan.resolved_families


def test_the_terminal_says_which_families_run_and_how_to_add_active_templates(monkeypatch, capsys):
    response = {
        "scan_id": "00000000-0000-0000-0000-000000000004", "status": "queued",
        "family_preset": "standard_active",
        "resolved_families": ["recon", "nuclei_passive", "xss", "sqli", "sensitive_exposure"],
    }
    assert _run_with_response(monkeypatch, [
        "https://example.com", "--budget-profile", "balanced", "--active-testing", "--confirm-active",
    ], response) == 0
    out = capsys.readouterr().out
    assert "Families: recon, nuclei_passive, xss, sqli, sensitive_exposure (standard_active)" in out
    assert "--include-family nuclei_active" in out
    assert "thorough" in out and "deep" in out


def _thorough_contract(*, floors=True):
    contract = _contract()
    contract["advanced_limits"] = [{
        "name": name, "minimum": 0 if name == "max_state_changing_requests" else 1,
        "profile_ceilings": {"thorough": 60_000, "deep": 150_000},
    } for name in scan_cli.ADVANCED_FLAGS]
    if floors:
        contract["family_preset_addition_floors"] = {
            "standard_active": {"max_http_requests": 8_000, "max_state_changing_requests": 5_000}}
    return contract


@pytest.mark.parametrize("floors", [True, False])
def test_a_lowered_ceiling_on_thorough_says_why_the_active_templates_are_left_out(monkeypatch, capsys, floors):
    """On thorough the standard active set runs them; only a lowered ceiling leaves them out, so the
    hint names that ceiling instead of telling the operator the profile runs them."""
    response = {"scan_id": "00000000-0000-0000-0000-000000000008", "status": "queued",
                "family_preset": "standard_active",
                "resolved_families": ["recon", "nuclei_passive", "xss", "sqli", "sensitive_exposure"]}

    def request(url, *, payload=None, idempotency_key=None):
        return _thorough_contract(floors=floors) if payload is None else dict(response)

    monkeypatch.setattr(scan_cli, "_request_json", request)
    assert scan_cli.main([
        "--api-url", "http://api.test:8080", "--ui-url", "http://ui.test:3000",
        "https://example.com", "--budget-profile", "thorough", "--active-testing", "--confirm-active",
        "--max-http-requests", "5000",
    ]) == 0
    out = " ".join(capsys.readouterr().out.split())
    assert "--include-family nuclei_active" in out
    assert "runs them on --budget-profile thorough or deep" not in out
    assert "ceiling" in out
    # The floor is named as what it is, never as what the sweep holds at admission.
    assert "what their sweep holds" not in out
    if floors:
        assert "--max-http-requests 5,000 is below the floor of 8,000" in out


def test_a_lowered_mutation_ceiling_names_its_own_floor(monkeypatch, capsys):
    response = {"scan_id": "00000000-0000-0000-0000-000000000009", "status": "queued",
                "family_preset": "standard_active",
                "resolved_families": ["recon", "nuclei_passive", "xss", "sqli", "sensitive_exposure"]}

    def request(url, *, payload=None, idempotency_key=None):
        return _thorough_contract() if payload is None else dict(response)

    monkeypatch.setattr(scan_cli, "_request_json", request)
    assert scan_cli.main([
        "--api-url", "http://api.test:8080", "--ui-url", "http://ui.test:3000",
        "https://example.com", "--budget-profile", "thorough", "--active-testing", "--confirm-active",
        "--allow-state-changing-http", "--max-state-changing-requests", "4500",
    ]) == 0
    out = " ".join(capsys.readouterr().out.split())
    assert "--max-state-changing-requests 4,500 is below the floor of 5,000" in out
    assert "--max-http-requests" not in out


def test_no_active_template_hint_when_they_run_are_excluded_or_testing_is_passive(monkeypatch, capsys):
    response = {
        "scan_id": "00000000-0000-0000-0000-000000000005", "status": "queued",
        "resolved_families": ["recon", "nuclei_passive", "nuclei_active", "xss", "sqli"],
    }
    assert _run_with_response(monkeypatch, [
        "https://example.com", "--active-testing", "--confirm-active",
    ], response) == 0
    assert "--include-family nuclei_active" not in capsys.readouterr().out
    excluded = {"scan_id": "00000000-0000-0000-0000-000000000007", "status": "queued",
                "resolved_families": ["recon", "nuclei_passive", "xss", "sqli"]}
    assert _run_with_response(monkeypatch, [
        "https://example.com", "--budget-profile", "thorough", "--active-testing", "--confirm-active",
        "--exclude-family", "nuclei_active",
    ], excluded) == 0
    assert "--include-family nuclei_active" not in capsys.readouterr().out
    passive = {"scan_id": "00000000-0000-0000-0000-000000000006", "status": "queued",
               "resolved_families": ["recon", "nuclei_passive", "sensitive_exposure"]}
    assert _run_with_response(monkeypatch, ["https://example.com"], passive) == 0
    assert "--include-family nuclei_active" not in capsys.readouterr().out


def test_the_help_names_the_command_it_was_started_as(capsys):
    urls = ["--api-url", "http://api.test:8080", "--ui-url", "http://ui.test:3000"]
    assert scan_cli.main([*urls, "help"], prog="shakerscan scan") == 0
    out = capsys.readouterr().out
    assert out.startswith("usage: shakerscan scan ") and "scanner.sh" not in out
    with pytest.raises(SystemExit):
        scan_cli.main([*urls, "--help"], prog="shakerscan scan")
    assert capsys.readouterr().out.startswith("usage: shakerscan scan ")
    assert scan_cli.main([*urls, "help"]) == 0
    assert capsys.readouterr().out.startswith("usage: scanner.sh scan ")
