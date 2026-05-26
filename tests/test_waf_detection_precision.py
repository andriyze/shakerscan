import asyncio
import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))
from scanner_tools import discovery  # noqa: E402


def _curl_output(body: str, status_code: str = "200") -> str:
    return f"{body}\n{status_code}"


def test_detect_waf_does_not_count_baseline_security_copy_as_block(monkeypatch):
    body = "<html><title>Honey Security Demo</title><p>security controls are visible here</p></html>"

    async def fake_run(cmd, timeout=10):
        return _curl_output(body), "", 0

    monkeypatch.setattr(discovery, "run", fake_run)

    result = asyncio.run(discovery.detect_waf("https://example.test/security", {}))

    assert result["waf_detected"] is False
    assert result.get("input_validation_detected") is not True
    assert "blocked_details" not in result


def test_detect_waf_counts_payload_specific_block_response(monkeypatch):
    baseline = "<html><p>normal application page</p></html>"
    blocked = "<html><h1>Request blocked by web application firewall</h1></html>"

    async def fake_run(cmd, timeout=10):
        url = cmd[-1]
        if "test=" not in url:
            return _curl_output(baseline), "", 0
        return _curl_output(blocked, "403"), "", 0

    monkeypatch.setattr(discovery, "run", fake_run)

    result = asyncio.run(discovery.detect_waf("https://example.test/", {}))

    assert result["waf_detected"] is False
    assert result["input_validation_detected"] is True
    assert result["blocked_payloads"] == 4
    assert all(detail["block_reason"] == "HTTP 403" for detail in result["blocked_details"])


def test_append_query_param_preserves_existing_query_string():
    url = discovery._append_query_param("https://example.test/path?existing=1", "test", "' OR '1'='1")

    assert url.startswith("https://example.test/path?")
    assert "existing=1" in url
    assert "test=%27+OR+%271%27%3D%271" in url
