import asyncio
import json
import urllib.parse

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
            "param_names": ["email", "token"],
            "param_location": "body",
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
            "param_names": ["email", "password"],
            "param_location": "body",
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


def test_nosql_json_body_accepts_token_with_account_id_identity(monkeypatch):
    async def fake_run(cmd, *args, **kwargs):
        body = json.loads(cmd[cmd.index("-d") + 1])
        if isinstance(body.get("email"), dict) and isinstance(body.get("password"), dict):
            return (
                '{"accessToken":"jwt-token","accountId":42}'
                "__SHAKERSCAN_NOSQL__200__SHAKERSCAN_NOSQL__",
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
    finding = result["findings"][0]
    assert finding["evidence_type"] == "credential_operator_bypass"
    assert set(finding["success_signals"]) == {"auth_token_or_session", "user_identity_data"}


def test_nosql_json_body_rejects_token_only_without_identity_signal(monkeypatch):
    async def fake_run(cmd, *args, **kwargs):
        body = json.loads(cmd[cmd.index("-d") + 1])
        if isinstance(body.get("email"), dict) and isinstance(body.get("password"), dict):
            return '{"accessToken":"jwt-token"}__SHAKERSCAN_NOSQL__200__SHAKERSCAN_NOSQL__', "", 0
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


def test_nosql_json_body_detects_collection_operator_differential(monkeypatch):
    calls = []

    async def fake_run(cmd, *args, **kwargs):
        calls.append(cmd)
        body = json.loads(cmd[cmd.index("-d") + 1])
        product_id = body.get("id")
        if isinstance(product_id, dict) and "$ne" in product_id:
            return (
                json.dumps({
                    "data": [
                        {"id": 1, "message": "great", "rating": 5},
                        {"id": 2, "message": "ok", "rating": 3},
                        {"id": 3, "message": "bad", "rating": 1},
                    ]
                })
                + "__SHAKERSCAN_NOSQL__200__SHAKERSCAN_NOSQL__",
                "",
                0,
            )
        return '{"data":[]}__SHAKERSCAN_NOSQL__200__SHAKERSCAN_NOSQL__', "", 0

    monkeypatch.setattr(active_checks, "run", fake_run)

    result = asyncio.run(
        active_checks.nosql_injection_test_json_body(
            "https://example.test/rest/products/reviews",
            method="POST",
            params=["id"],
            body_template={"id": 1},
        )
    )

    assert result["vulnerable"] is True
    finding = result["findings"][0]
    assert finding["evidence_type"] == "operator_collection_differential"
    assert finding["control_items"] == 0
    assert finding["payload_items"] == 3
    assert finding["payload_status"] == 200
    assert len(calls) == 3  # scalar baseline, restrictive $eq, permissive $ne


def test_nosql_json_body_rejects_uniform_collection_response(monkeypatch):
    async def fake_run(cmd, *args, **kwargs):
        return (
            json.dumps({"data": [{"id": 1, "message": "same"}, {"id": 2, "message": "same"}]})
            + "__SHAKERSCAN_NOSQL__200__SHAKERSCAN_NOSQL__",
            "",
            0,
        )

    monkeypatch.setattr(active_checks, "run", fake_run)

    result = asyncio.run(
        active_checks.nosql_injection_test_json_body(
            "https://example.test/rest/products/reviews",
            method="POST",
            params=["id"],
            body_template={"id": 1},
        )
    )

    assert result["vulnerable"] is False
    assert result["findings"] == []


def test_nosql_query_detects_collection_operator_differential(monkeypatch):
    async def fake_run(cmd, *args, **kwargs):
        parsed = urllib.parse.urlparse(cmd[-1])
        pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        names = {name for name, _value in pairs}
        if "id[$ne]" in names:
            body = json.dumps({
                "data": [
                    {"id": 1, "message": "great", "rating": 5},
                    {"id": 2, "message": "ok", "rating": 3},
                    {"id": 3, "message": "bad", "rating": 1},
                ]
            })
            return f"{body}__SHAKERSCAN_NOSQL_QUERY__200__SHAKERSCAN_NOSQL_QUERY__", "", 0
        return '{"data":[]}__SHAKERSCAN_NOSQL_QUERY__200__SHAKERSCAN_NOSQL_QUERY__', "", 0

    monkeypatch.setattr(active_checks, "run", fake_run)

    result = asyncio.run(
        active_checks.nosql_injection_test("https://example.test/rest/products/reviews?id=1")
    )

    assert result["vulnerable"] is True
    finding = result["findings"][0]
    assert finding["parameter"] == "id"
    assert finding["evidence_type"] == "operator_query_collection_differential"
    assert finding["control_items"] == 0
    assert finding["payload_items"] == 3


def test_nosql_query_rejects_uniform_collection_response(monkeypatch):
    async def fake_run(cmd, *args, **kwargs):
        body = json.dumps({"data": [{"id": 1, "message": "same"}, {"id": 2, "message": "same"}]})
        return f"{body}__SHAKERSCAN_NOSQL_QUERY__200__SHAKERSCAN_NOSQL_QUERY__", "", 0

    monkeypatch.setattr(active_checks, "run", fake_run)

    result = asyncio.run(
        active_checks.nosql_injection_test("https://example.test/rest/products/reviews?id=1")
    )

    assert result["vulnerable"] is False
    assert result["findings"] == []
