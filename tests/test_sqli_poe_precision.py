import asyncio
import json
import urllib.parse

from scanner.scanner_tools.proof_of_exploit import (
    _is_valid_sqli_extraction,
    _split_curl_response,
    prove_sqli_reflection_fp,
)
from scanner.scanner_tools import proof_of_exploit
from scanner.scanner_tools import active_checks
from scanner.scanner_tools.active_checks import _check_sqli_response, custom_sqli_test


HONEY_POSTGRES_ERROR = """ERROR: syntax error at or near "' OR 1=1--"
  LINE 1: SELECT id, username, role FROM users WHERE id = '' OR 1=1--'
                                                  ^
  Position: 48
  SQLSTATE: 42601
  PG_VERSION: PostgreSQL 14.7 on x86_64-pc-linux-gnu, compiled by gcc 11.3.0
  HINT: Check escaping of single quotes in the WHERE clause."""


def test_curl_response_parser_uses_final_redirect_response_body():
    stdout = (
        "HTTP/1.1 308 Permanent Redirect\r\n"
        "Location: https://example.test/api/\r\n"
        "\r\n"
        "HTTP/2 404\r\n"
        "content-type: text/html; charset=utf-8\r\n"
        "\r\n"
        "<!DOCTYPE html><html><head><title>Not Found</title></head></html>"
    )

    headers, body = _split_curl_response(stdout)

    assert headers.startswith("HTTP/2 404")
    assert "HTTP/1.1 308" not in body
    assert "HTTP/2 404" not in body
    assert body.startswith("<!DOCTYPE html>")


def test_sqli_poe_rejects_generic_http_header_token_as_database_name():
    response = (
        "HTTP/2 404\n"
        "content-type: text/html; charset=utf-8\n\n"
        "<!DOCTYPE html><html><head></head><body>Not Found</body></html>"
    )

    assert not _is_valid_sqli_extraction("database", "HTTP", response)
    assert not _is_valid_sqli_extraction("database", "DOCTYPE", response)


def test_sqli_poe_accepts_plausible_non_baseline_database_token():
    response = "query result: app_main_2026"
    baseline = "normal page without database output"

    assert _is_valid_sqli_extraction("database", "app_main_2026", response, baseline)


def test_sqli_poe_rejects_token_already_in_baseline():
    response = "query result: app_main_2026"
    baseline = "footer app_main_2026"

    assert not _is_valid_sqli_extraction("database", "app_main_2026", response, baseline)


def test_sqli_active_check_rejects_reflected_version_payload():
    out = "<!DOCTYPE html><body>search=' UNION SELECT NULL,@@version,NULL-- -</body>"

    vulnerable, evidence = _check_sqli_response(
        out=out,
        baseline_len=len("<!DOCTYPE html><body>search=normal</body>"),
        elapsed=0.1,
        technique="version",
        dbms_detected=None,
        baseline_body="<!DOCTYPE html><body>search=normal</body>",
    )

    assert vulnerable is False
    assert not any("@@version" in item for item in evidence)


def test_sqli_active_check_accepts_actual_database_banner():
    out = "query result: MySQL 8.0.36"

    vulnerable, evidence = _check_sqli_response(
        out=out,
        baseline_len=len("query result: normal"),
        elapsed=0.1,
        technique="version",
        dbms_detected="mysql",
        baseline_body="query result: normal",
    )

    assert vulnerable is True
    assert any("Data extraction indicator" in item for item in evidence)


def test_sqli_active_check_rejects_baseline_sql_error_banner():
    out = "OpenAPI examples mention Oracle Error ORA-00933"
    baseline = "OpenAPI examples mention Oracle Error ORA-00933"

    vulnerable, evidence = _check_sqli_response(
        out=out,
        baseline_len=len(baseline),
        elapsed=0.1,
        technique="error",
        dbms_detected=None,
        baseline_body=baseline,
    )

    assert vulnerable is False
    assert not any("SQL error detected" in item for item in evidence)


def test_sqli_active_check_accepts_honey_postgresql_error_banner():
    vulnerable, evidence = _check_sqli_response(
        out=HONEY_POSTGRES_ERROR,
        baseline_len=len('{"id":1,"username":"admin","role":"admin"}'),
        elapsed=0.1,
        technique="boolean",
        dbms_detected=None,
        status_code=500,
        baseline_status=200,
        baseline_body='{"id":1,"username":"admin","role":"admin"}',
    )

    assert vulnerable is True
    assert any("postgresql" in item.lower() for item in evidence)
    assert any("SQL error detected" in item for item in evidence)


def test_sqli_active_check_accepts_login_auth_bypass():
    body = json.dumps({
        "authentication": {"token": "jwt-token"},
        "user": {"email": "admin@juice-sh.op", "role": "admin"},
    })

    vulnerable, evidence = _check_sqli_response(
        out=body,
        baseline_len=len("Invalid email or password."),
        elapsed=0.1,
        technique="auth_bypass_boolean",
        dbms_detected="sqlite",
        status_code=200,
        baseline_status=401,
        baseline_body="Invalid email or password.",
        payload="' OR 1=1--",
    )

    assert vulnerable is True
    assert any("Authentication bypass via SQLi" in item for item in evidence)


def test_sqli_active_check_accepts_json_collection_expansion():
    baseline = json.dumps({"data": []})
    body = json.dumps({
        "data": [
            {"id": 1, "code": "SAVE10", "amount": 10},
            {"id": 2, "code": "SAVE20", "amount": 20},
            {"id": 3, "code": "SAVE30", "amount": 30},
        ]
    })

    vulnerable, evidence = _check_sqli_response(
        out=body,
        baseline_len=len(baseline),
        elapsed=0.1,
        technique="boolean",
        dbms_detected=None,
        status_code=200,
        baseline_status=422,
        baseline_body=baseline,
        payload="' OR 1=1--",
    )

    assert vulnerable is True
    assert any("SQLi JSON collection expansion" in item for item in evidence)


def test_sqli_active_check_rejects_uniform_json_collection_response():
    body = json.dumps({
        "data": [
            {"id": 1, "code": "SAVE10"},
            {"id": 2, "code": "SAVE20"},
        ]
    })

    vulnerable, evidence = _check_sqli_response(
        out=body,
        baseline_len=len(body),
        elapsed=0.1,
        technique="boolean",
        dbms_detected=None,
        status_code=200,
        baseline_status=200,
        baseline_body=body,
        payload="' OR 1=1--",
    )

    assert vulnerable is False
    assert not any("SQLi JSON collection expansion" in item for item in evidence)


def test_smart_sqli_detects_json_coupon_collection_expansion(monkeypatch):
    marker = active_checks._CURL_STATUS_MARKER

    async def fake_run(cmd, *args, **kwargs):
        if "-d" not in cmd:
            return f'{{"error":"invalid coupon"}}\n{marker}422', "", 0
        body = json.loads(cmd[cmd.index("-d") + 1])
        code = str(body.get("code") or body.get("coupon") or "")
        if " OR " in code.upper():
            return (
                json.dumps({
                    "data": [
                        {"id": 1, "code": "SAVE10", "amount": 10},
                        {"id": 2, "code": "SAVE20", "amount": 20},
                        {"id": 3, "code": "SAVE30", "amount": 30},
                    ]
                })
                + f"\n{marker}200",
                "",
                0,
            )
        return f'{{"data":[]}}\n{marker}422', "", 0

    monkeypatch.setattr(active_checks, "run", fake_run)

    result = asyncio.run(
        active_checks.smart_sqli_test(
            "https://example.test",
            [
                {
                    "url": "https://example.test/community/api/v2/coupon",
                    "method": "POST",
                    "content_type": "application/json",
                    "body_params": ["code"],
                    "body_template": {"code": "TEST123"},
                }
            ],
            max_seconds=10,
            max_params_per_endpoint=1,
        )
    )

    assert result["vulnerabilities_found"] == 1
    finding = result["findings"][0]
    assert finding["url"].endswith("/community/api/v2/coupon")
    assert finding["param"] == "code"
    assert any("SQLi JSON collection expansion" in item for item in finding["evidence"])


def test_smart_sqli_detects_json_login_auth_bypass(monkeypatch):
    marker = active_checks._CURL_STATUS_MARKER

    async def fake_run(cmd, *args, **kwargs):
        if "-d" in cmd:
            body = json.loads(cmd[cmd.index("-d") + 1])
            if body.get("email") == "' OR 1=1--":
                return (
                    json.dumps({
                        "authentication": {"token": "jwt-token"},
                        "user": {"email": "admin@juice-sh.op", "role": "admin"},
                    })
                    + f"\n{marker}200",
                    "",
                    0,
                )
        return f"Invalid email or password.\n{marker}401", "", 0

    monkeypatch.setattr(active_checks, "run", fake_run)

    result = asyncio.run(
        active_checks.smart_sqli_test(
            "https://example.test",
            [
                {
                    "url": "https://example.test/rest/user/login",
                    "method": "POST",
                    "content_type": "application/json",
                    "body_params": ["email", "password"],
                }
            ],
            dbms="sqlite",
            max_seconds=10,
            max_params_per_endpoint=2,
        )
    )

    assert result["vulnerabilities_found"] == 1
    finding = result["findings"][0]
    assert finding["severity"] == "critical"
    assert finding["payload"] == "' OR 1=1--"
    assert any("Authentication bypass via SQLi" in item for item in finding["evidence"])


def test_smart_sqli_repairs_numeric_login_json_replay(monkeypatch):
    marker = active_checks._CURL_STATUS_MARKER

    async def fake_run(cmd, *args, **kwargs):
        if "-d" in cmd:
            body = json.loads(cmd[cmd.index("-d") + 1])
            if not isinstance(body.get("password"), str):
                return f"TypeError: password must be a string\n{marker}500", "", 0
            if body.get("email") in {"' OR '1'='1'--", "' OR 1=1--"}:
                return (
                    json.dumps({
                        "authentication": {"token": "jwt-token"},
                        "bid": 1,
                        "umail": "admin@juice-sh.op",
                    })
                    + f"\n{marker}200",
                    "",
                    0,
                )
        return f"Invalid email or password.\n{marker}401", "", 0

    monkeypatch.setattr(active_checks, "run", fake_run)

    result = asyncio.run(
        active_checks.smart_sqli_test(
            "https://example.test",
            [
                {
                    "url": "https://example.test/rest/user/login",
                    "method": "POST",
                    "content_type": "application/json",
                    "body_template": {"email": 1, "username": 1, "password": 1},
                    "body_param_defaults": {"email": 1, "username": 1, "password": 1},
                    "body_params": ["email", "username", "password"],
                }
            ],
            max_seconds=10,
            max_params_per_endpoint=3,
        )
    )

    assert result["vulnerabilities_found"] == 1
    finding = result["findings"][0]
    assert finding["severity"] == "critical"
    assert finding["param"] == "email"
    assert any("Authentication bypass via SQLi" in item for item in finding["evidence"])


def test_detect_dbms_post_uses_nested_json_body_param(monkeypatch):
    marker = active_checks._CURL_STATUS_MARKER
    sent_bodies: list[dict] = []

    async def fake_run(cmd, *args, **kwargs):
        body = json.loads(cmd[cmd.index("-d") + 1])
        sent_bodies.append(body)
        assert "credentials.email" not in body
        assert body["credentials"]["password"] == "not-real"
        if body["credentials"]["email"] == "1'":
            return HONEY_POSTGRES_ERROR + f"\n{marker}500", "", 0
        return f'{{"error":"invalid login"}}\n{marker}401', "", 0

    monkeypatch.setattr(active_checks, "run", fake_run)

    result = asyncio.run(
        active_checks._detect_dbms_post(
            "https://example.test/api/login",
            "credentials.email",
            "application/json",
            [],
            method="POST",
            base_body={
                "credentials": {
                    "email": "nobody@example.test",
                    "password": "not-real",
                }
            },
        )
    )

    assert result["detected"] == "postgresql"
    assert len(sent_bodies) == 2
    assert all("credentials.email" not in body for body in sent_bodies)


def test_smart_sqli_nested_json_body_param_auth_bypass(monkeypatch):
    marker = active_checks._CURL_STATUS_MARKER
    sent_bodies: list[dict] = []

    async def fake_run(cmd, *args, **kwargs):
        if "-d" not in cmd:
            return f"normal\n{marker}200", "", 0
        body = json.loads(cmd[cmd.index("-d") + 1])
        sent_bodies.append(body)
        assert "credentials.email" not in body
        email = body["credentials"]["email"]
        if email == "' OR 1=1--":
            assert body["credentials"]["password"] == "not-real"
            return (
                json.dumps({
                    "authentication": {"token": "jwt-token"},
                    "user": {"email": "admin@example.test", "role": "admin"},
                })
                + f"\n{marker}200",
                "",
                0,
            )
        return f"Invalid email or password.\n{marker}401", "", 0

    monkeypatch.setattr(active_checks, "run", fake_run)

    result = asyncio.run(
        active_checks.smart_sqli_test(
            "https://example.test",
            [
                {
                    "url": "https://example.test/api/login",
                    "method": "POST",
                    "content_type": "application/json",
                    "body_template": {
                        "credentials": {
                            "email": "nobody@example.test",
                            "password": "not-real",
                        }
                    },
                    "body_params": ["credentials.email", "credentials.password"],
                }
            ],
            dbms="sqlite",
            max_seconds=10,
            max_params_per_endpoint=2,
        )
    )

    assert result["vulnerabilities_found"] == 1
    finding = result["findings"][0]
    assert finding["param"] == "credentials.email"
    assert json.loads(finding["body"]) == {
        "credentials": {
            "email": "nobody@example.test",
            "password": "not-real",
        }
    }
    assert any("Authentication bypass via SQLi" in item for item in finding["evidence"])
    assert sent_bodies
    assert all("credentials.email" not in body for body in sent_bodies)


def test_detect_dbms_accepts_honey_postgresql_error(monkeypatch):
    async def fake_run(cmd, *args, **kwargs):
        url = cmd[-1]
        if "shakerscan_dbms_baseline" in url:
            return '{"id":1,"username":"admin","role":"admin"}', "", 0
        if "%27" in url:
            return HONEY_POSTGRES_ERROR, "", 0
        return '{"id":1,"username":"admin","role":"admin"}', "", 0

    monkeypatch.setattr(active_checks, "run", fake_run)

    result = asyncio.run(active_checks.detect_dbms("https://example.test/user?id=1", "id"))

    assert result["detected"] == "postgresql"
    assert result["confidence"] == 0.9
    assert result["evidence"][0]["match"]


def test_smart_sqli_sets_dbms_from_postgresql_error_finding(monkeypatch):
    marker = active_checks._CURL_STATUS_MARKER

    async def fake_run(cmd, *args, **kwargs):
        url = cmd[-1]
        has_status_marker = marker in " ".join(cmd)
        if "shakerscan_dbms_baseline" in url:
            return '{"id":1,"username":"admin","role":"admin"}', "", 0
        if "%27" in url:
            body = HONEY_POSTGRES_ERROR
            return (f"{body}\n{marker}500" if has_status_marker else body), "", 0
        return f'{{"id":1,"username":"admin","role":"admin"}}\n{marker}200', "", 0

    monkeypatch.setattr(active_checks, "run", fake_run)

    result = asyncio.run(
        active_checks.smart_sqli_test(
            "https://example.test",
            [
                {
                    "url": "https://example.test/user?id=1",
                    "method": "GET",
                    "params": ["id"],
                }
            ],
            max_seconds=10,
        )
    )

    assert result["dbms_detected"] == "postgresql"
    assert result["vulnerabilities_found"] == 1
    assert result["findings"][0]["dbms"] == "postgresql"
    assert any("postgresql" in item.lower() for item in result["findings"][0]["evidence"])


def test_sqli_data_extraction_skips_documentation_endpoint(monkeypatch):
    async def fail_run(*args, **kwargs):
        raise AssertionError("documentation endpoints should not be used for SQLi extraction")

    monkeypatch.setattr(active_checks, "run", fail_run)

    result = asyncio.run(
        active_checks.sqli_data_extraction(
            {
                "url": "https://example.test/api/openapi.json",
                "param": "id",
                "dbms": "mysql",
                "method": "GET",
            }
        )
    )

    assert result["extraction_successful"] is False
    assert result["skipped"] is True
    assert result["reason"] == "documentation_endpoint"


def test_sqli_data_extraction_skips_unknown_dbms(monkeypatch):
    async def fail_run(*args, **kwargs):
        raise AssertionError("unknown DBMS should not use default extraction payloads")

    monkeypatch.setattr(active_checks, "run", fail_run)

    result = asyncio.run(
        active_checks.sqli_data_extraction(
            {
                "url": "https://example.test/user",
                "param": "id",
                "dbms": None,
                "method": "GET",
            }
        )
    )

    assert result["extraction_successful"] is False
    assert result["skipped"] is True
    assert result["reason"] == "unsupported_or_unknown_dbms"


def test_sqli_data_extraction_accepts_sensitive_rowset(monkeypatch):
    marker = active_checks._CURL_STATUS_MARKER
    rowset = (
        '{"results":[{"id":1,"username":"admin","password_hash":"abc",'
        '"api_key":"sk_live_example"}],"row_count":1,"vulnerable":true}'
    )

    async def fake_run(cmd, *args, **kwargs):
        url = cmd[-1]
        if "UNION" in url or "version%28%29" in url:
            return f"{rowset}\n{marker}200", "", 0
        return f'{{"id":1,"username":"admin","role":"admin"}}\n{marker}200', "", 0

    monkeypatch.setattr(active_checks, "run", fake_run)

    result = asyncio.run(
        active_checks.sqli_data_extraction(
            {
                "url": "https://example.test/user?id=1",
                "param": "id",
                "dbms": "postgresql",
                "method": "GET",
            }
        )
    )

    assert result["extraction_successful"] is True
    assert result["proof_of_exploitation"] is True
    assert result["dbms_confirmed"] == "postgresql"
    assert "password_hash" in result["extracted_data"]["sensitive_markers"]
    assert any("sensitive rowset" in item for item in result["evidence"])


def test_check_sqli_response_payload_guard_ignores_reflected_schema_keyword():
    """A reflected schema keyword (echoed payload) must not count as exfiltration."""
    payload = "')) UNION SELECT sql,name FROM sqlite_master--"
    out = f"<!DOCTYPE html><body>results for: {payload}</body>"
    baseline = "<!DOCTYPE html><body>results for: normal</body>"

    # Without payload context, the reflected `sqlite_master` token scores as a leak.
    vuln_no_guard, ev_no_guard = _check_sqli_response(
        out=out, baseline_len=len(baseline), elapsed=0.1, technique="schema_dump",
        dbms_detected=None, baseline_body=baseline,
    )
    # With the payload supplied, the same token is recognised as reflection.
    vuln_guard, ev_guard = _check_sqli_response(
        out=out, baseline_len=len(baseline), elapsed=0.1, technique="schema_dump",
        dbms_detected=None, baseline_body=baseline, payload=payload,
    )

    assert vuln_no_guard is True
    assert any("sqlite_master" in item for item in ev_no_guard)
    assert vuln_guard is False
    assert not any("sqlite_master" in item for item in ev_guard)


def test_check_sqli_response_suppresses_extraction_for_reflected_param():
    """Defense-in-depth: when a parameter is confirmed to reflect input, any
    extraction token in the response is unreliable and must be suppressed — even
    a resolved version string the per-payload guard would otherwise miss."""
    # The resolved version is NOT in the payload, so the per-payload guard does
    # not catch it; only the reflection flag should.
    payload = "' UNION SELECT NULL,NULL,NULL-- -"
    out = "<body>results for your search: MySQL 8.0.32-log</body>"
    baseline = "<body>results for your search: normal</body>"

    vuln_unreflected, _ev = _check_sqli_response(
        out=out, baseline_len=len(baseline), elapsed=0.1, technique="version",
        dbms_detected=None, baseline_body=baseline, payload=payload, reflected=False,
    )
    vuln_reflected, ev_reflected = _check_sqli_response(
        out=out, baseline_len=len(baseline), elapsed=0.1, technique="version",
        dbms_detected=None, baseline_body=baseline, payload=payload, reflected=True,
    )

    assert vuln_unreflected is True
    assert vuln_reflected is False
    assert not any("Data extraction indicator" in item for item in ev_reflected)


def test_custom_sqli_test_ignores_reflecting_app(monkeypatch):
    """Reproduces the tidyhelpers false positive: an app that echoes the query
    (so the SQL payload appears in the page) but raises no DB error and returns
    no real banner must produce zero SQLi findings."""

    async def reflecting_run(cmd, *args, **kwargs):
        url = cmd[-1]
        decoded = urllib.parse.unquote_plus(url)  # echo the payload like a search box
        body = f"<!DOCTYPE html><html><body>Search results for: {decoded}</body></html>"
        return f"{body}\n200", "", 0

    monkeypatch.setattr(active_checks, "run", reflecting_run)

    result = asyncio.run(custom_sqli_test("https://tidyhelpers.com/search?query=test"))

    assert result["scan_completed"] is True
    assert result["vulnerable"] is False
    assert result["findings"] == []


def test_custom_sqli_test_detects_real_postgres_error(monkeypatch):
    """A genuine database error in the response is still reported (high severity)."""

    async def erroring_run(cmd, *args, **kwargs):
        url = cmd[-1]
        if "%27" in url:  # any payload that injected a quote breaks the query
            return f"{HONEY_POSTGRES_ERROR}\n500", "", 0
        return '{"id":1,"username":"admin","role":"admin"}\n200', "", 0

    monkeypatch.setattr(active_checks, "run", erroring_run)

    result = asyncio.run(custom_sqli_test("https://example.test/user?id=1"))

    assert result["vulnerable"] is True
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["severity"] == "high"
    assert finding["type"] == "SQL Injection"
    assert any("SQL error detected" in item for item in finding["evidence"])
    assert any("postgresql" in item.lower() for item in finding["evidence"])


def test_sqli_data_extraction_rejects_version_already_in_baseline(monkeypatch):
    async def fake_run(*args, **kwargs):
        body = "OpenAPI 3.1.0 examples mention MySQL 8.0.36"
        return f"{body}\n__CURL_STATUS__:200", "", 0

    monkeypatch.setattr(active_checks, "run", fake_run)

    result = asyncio.run(
        active_checks.sqli_data_extraction(
            {
                "url": "https://example.test/search",
                "param": "q",
                "dbms": "mysql",
                "method": "GET",
            }
        )
    )

    assert result["extraction_successful"] is False
    assert "version" not in result["extracted_data"]


def test_sqli_data_extraction_reuses_post_body_template(monkeypatch):
    marker = active_checks._CURL_STATUS_MARKER
    sent_bodies: list[dict] = []

    async def fake_run(cmd, *args, **kwargs):
        body_arg = json.loads(cmd[cmd.index("-d") + 1])
        sent_bodies.append(body_arg)
        # This endpoint requires the sibling category field. The old extraction
        # replay sent only {"q": payload}, which never reached the SQL sink.
        if body_arg.get("category") != "all":
            return f'{{"error":"category required"}}\n{marker}400', "", 0
        if "sqlite_version()" in str(body_arg.get("q")):
            return f"SQLite 3.40.1\n{marker}200", "", 0
        return f'{{"items":[]}}\n{marker}200', "", 0

    monkeypatch.setattr(active_checks, "run", fake_run)

    result = asyncio.run(
        active_checks.sqli_data_extraction(
            {
                "url": "https://example.test/api/search",
                "param": "q",
                "dbms": "sqlite",
                "method": "POST",
                "content_type": "application/json",
                "body": json.dumps({"q": "apple", "category": "all"}),
            }
        )
    )

    assert result["extraction_successful"] is True
    assert result["extracted_data"]["version"] == "3.40.1"
    assert sent_bodies
    assert all(body.get("category") == "all" for body in sent_bodies)


# ---------------------------------------------------------------------------
# Deterministic reflection false-positive prover (retest path)
# ---------------------------------------------------------------------------

def _fake_capture(by_substring):
    """Return a fake fetch_with_capture that picks a body by matching the URL."""
    async def fake_fetch_with_capture(url, **kwargs):
        body = ""
        for needle, value in by_substring:
            if needle in url:
                body = value
                break
        return {"status_code": 200, "headers": {}, "body": body, "final_url": url, "elapsed_ms": 1.0, "error": None}
    return fake_fetch_with_capture


def test_reflection_fp_prover_flags_echoing_param(monkeypatch):
    # The app echoes whatever is in `service_id` (canary + the UNION expression)
    # but never evaluates SQL: the arithmetic product never appears.
    def body_for(url):
        decoded = urllib.parse.unquote_plus(url)
        return f"<html><body>results for: {decoded}</body></html>"

    async def fake(url, **kwargs):
        return {"status_code": 200, "headers": {}, "body": body_for(url), "final_url": url, "elapsed_ms": 1.0, "error": None}

    monkeypatch.setattr(proof_of_exploit, "fetch_with_capture", fake)
    proof = asyncio.run(prove_sqli_reflection_fp("https://x.test/market/svc?service_id=1", "service_id"))
    assert proof is not None
    assert proof.is_false_positive is True
    assert proof.confidence >= 0.85
    assert proof.evidence_type == "reflection_false_positive"


def test_reflection_fp_prover_skips_when_db_evaluates(monkeypatch):
    # The DB actually computes 7857*7919 -> product appears: NOT a reflection FP.
    product = str(7857 * 7919)

    async def fake(url, **kwargs):
        decoded = urllib.parse.unquote_plus(url)
        body = f"<html><body>row: {product}</body></html>" if "UNION" in decoded else f"echo {decoded}"
        return {"status_code": 200, "headers": {}, "body": body, "final_url": url, "elapsed_ms": 1.0, "error": None}

    monkeypatch.setattr(proof_of_exploit, "fetch_with_capture", fake)
    proof = asyncio.run(prove_sqli_reflection_fp("https://x.test/s?service_id=1", "service_id"))
    assert proof is None


def test_reflection_fp_prover_skips_when_not_reflected(monkeypatch):
    async def fake(url, **kwargs):
        return {"status_code": 200, "headers": {}, "body": "<html>static page, no echo</html>", "final_url": url, "elapsed_ms": 1.0, "error": None}

    monkeypatch.setattr(proof_of_exploit, "fetch_with_capture", fake)
    proof = asyncio.run(prove_sqli_reflection_fp("https://x.test/s?service_id=1", "service_id"))
    assert proof is None


def test_reflection_fp_prover_skips_on_sql_error(monkeypatch):
    async def fake(url, **kwargs):
        decoded = urllib.parse.unquote_plus(url)
        if "UNION" in decoded:
            return {"status_code": 200, "headers": {}, "body": "You have an error in your SQL syntax near", "final_url": url, "elapsed_ms": 1.0, "error": None}
        return {"status_code": 200, "headers": {}, "body": f"echo {decoded}", "final_url": url, "elapsed_ms": 1.0, "error": None}

    monkeypatch.setattr(proof_of_exploit, "fetch_with_capture", fake)
    proof = asyncio.run(prove_sqli_reflection_fp("https://x.test/s?service_id=1", "service_id"))
    assert proof is None


def test_reflection_fp_prover_skips_when_sql_payload_is_filtered(monkeypatch):
    # Simple input reflection is not enough to prove a SQLi false positive. If the
    # UNION payload is filtered/dropped, the prover must bow out instead of
    # clearing the finding as an objective FP.
    async def fake(url, **kwargs):
        decoded = urllib.parse.unquote_plus(url)
        if "UNION" in decoded:
            body = "<html>results normalized by input filter</html>"
        else:
            body = f"<html>echo {decoded}</html>"
        return {"status_code": 200, "headers": {}, "body": body, "final_url": url, "elapsed_ms": 1.0, "error": None}

    monkeypatch.setattr(proof_of_exploit, "fetch_with_capture", fake)
    proof = asyncio.run(prove_sqli_reflection_fp("https://x.test/s?service_id=1", "service_id"))
    assert proof is None


def test_reflection_fp_prover_injects_param_absent_from_url(monkeypatch):
    # Finding URL has no query string (the param lives only in evidence). The
    # prover must still inject it and detect the reflection FP.
    async def fake(url, **kwargs):
        decoded = urllib.parse.unquote_plus(url)
        return {"status_code": 200, "headers": {}, "body": f"<html>results for: {decoded}</html>", "final_url": url, "elapsed_ms": 1.0, "error": None}

    monkeypatch.setattr(proof_of_exploit, "fetch_with_capture", fake)
    proof = asyncio.run(prove_sqli_reflection_fp("https://gap.test/market/bronx/mulching", "service_id"))
    assert proof is not None and proof.is_false_positive is True
