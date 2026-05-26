from scanner.scanner_tools.proof_of_exploit import (
    _is_valid_sqli_extraction,
    _split_curl_response,
)
from scanner.scanner_tools.active_checks import _check_sqli_response


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
