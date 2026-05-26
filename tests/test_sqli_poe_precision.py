import asyncio

from scanner.scanner_tools.proof_of_exploit import (
    _is_valid_sqli_extraction,
    _split_curl_response,
)
from scanner.scanner_tools import active_checks
from scanner.scanner_tools.active_checks import _check_sqli_response


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
