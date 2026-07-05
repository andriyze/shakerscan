import asyncio
import json

from scanner.scanner_tools import active_checks


def test_nosql_json_body_stops_on_method_not_allowed(monkeypatch, capsys):
    calls = []

    async def fake_run(cmd, *args, **kwargs):
        calls.append(cmd)
        return '{"detail":"Method Not Allowed"}__SHAKERSCAN_NOSQL__405__SHAKERSCAN_NOSQL__', "", 0

    monkeypatch.delenv("SCANNER_DEBUG_NOSQL", raising=False)
    monkeypatch.setattr(active_checks, "run", fake_run)

    result = asyncio.run(
        active_checks.nosql_injection_test_json_body(
            "https://example.test/api/features",
            method="POST",
            params=["email", "token"],
        )
    )

    assert result["vulnerable"] is False
    assert result["skipped"] is True
    assert result["reason"] == "method_or_content_type_not_supported"
    assert result["baseline_status"] == 405
    assert result["params_tested"] == 1
    assert result["endpoint_attempts"] == [
        {
            "custom_endpoint": 'POST /api/features json:{"email":"test@example.com","token":"test_token_abc123"}',
            "family": "nosqli",
            "method": "POST",
            "url": "https://example.test/api/features",
            "param_count": 2,
            "attempted_params_count": 1,
            "completed_params_count": 1,
            "status": "skipped",
            "skip_reason": "method_or_content_type_not_supported",
        }
    ]
    assert len(calls) == 1
    assert capsys.readouterr().err == ""


def test_nosql_json_body_stops_on_unsupported_media_type(monkeypatch):
    calls = []

    async def fake_run(cmd, *args, **kwargs):
        calls.append(cmd)
        return '{"detail":"Unsupported Media Type"}__SHAKERSCAN_NOSQL__415__SHAKERSCAN_NOSQL__', "", 0

    monkeypatch.setattr(active_checks, "run", fake_run)

    result = asyncio.run(
        active_checks.nosql_injection_test_json_body(
            "https://example.test/upload",
            method="POST",
            params=["file"],
        )
    )

    assert result["vulnerable"] is False
    assert result["skipped"] is True
    assert result["baseline_status"] == 415
    assert len(calls) == 1


def test_nosql_json_body_detects_paired_credential_operator_bypass(monkeypatch):
    calls = []

    async def fake_run(cmd, *args, **kwargs):
        calls.append(cmd)
        body = json.loads(cmd[cmd.index("-d") + 1])
        email = body.get("email")
        password = body.get("password")
        if isinstance(email, dict) and isinstance(password, dict):
            return (
                json.dumps({
                    "authentication": {"token": "jwt-token"},
                    "user": {"email": "admin@juice-sh.op", "role": "admin"},
                })
                + "__SHAKERSCAN_NOSQL__200__SHAKERSCAN_NOSQL__",
                "",
                0,
            )
        return '{"error":"Invalid credentials"}__SHAKERSCAN_NOSQL__401__SHAKERSCAN_NOSQL__', "", 0

    monkeypatch.setattr(active_checks, "run", fake_run)

    result = asyncio.run(
        active_checks.nosql_injection_test_json_body(
            "https://example.test/rest/user/login",
            method="POST",
            params=["email", "password"],
            body_template={"email": "test@example.com", "password": "wrong"},
        )
    )

    assert result["vulnerable"] is True
    assert result["findings"][0]["evidence_type"] == "credential_operator_bypass"
    assert result["findings"][0]["parameter"] == "email,password"
    assert result["findings"][0]["baseline_status"] == 401
    assert result["findings"][0]["payload_status"] == 200
    assert set(result["findings"][0]["success_signals"]) == {"auth_token_or_session", "user_identity_data"}
    assert result["endpoint_attempts"] == [
        {
            "custom_endpoint": 'POST /rest/user/login json:{"email":"test@example.com","password":"wrong"}',
            "family": "nosqli",
            "method": "POST",
            "url": "https://example.test/rest/user/login",
            "param_count": 2,
            "attempted_params_count": 2,
            "completed_params_count": 2,
            "status": "completed",
        }
    ]
    assert len(calls) == 2


def test_nosql_json_body_does_not_flag_generic_200_without_auth_signals(monkeypatch):
    async def fake_run(cmd, *args, **kwargs):
        body = json.loads(cmd[cmd.index("-d") + 1])
        if isinstance(body.get("email"), dict) and isinstance(body.get("password"), dict):
            return '{"ok":true}__SHAKERSCAN_NOSQL__200__SHAKERSCAN_NOSQL__', "", 0
        return '{"error":"Invalid credentials"}__SHAKERSCAN_NOSQL__401__SHAKERSCAN_NOSQL__', "", 0

    monkeypatch.setattr(active_checks, "run", fake_run)

    result = asyncio.run(
        active_checks.nosql_injection_test_json_body(
            "https://example.test/rest/user/login",
            method="POST",
            params=["email", "password"],
            body_template={"email": "test@example.com", "password": "wrong"},
        )
    )

    assert result["vulnerable"] is False
    assert result["findings"] == []
