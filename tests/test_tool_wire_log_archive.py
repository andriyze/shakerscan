"""An external verifier's own wire log puts what it sent into the Scan archive.

sqlmap's ``-t`` traffic file and Dalfox's HAR record every request the tool sends. Over HTTPS the
engine's tunnel reads none of it, so a seeded login form a verifier tested looked untested in the
archive. These logs are parsed into archive rows (fixture logs below, identified as such; no
target is contacted), bounded, and kept to the tunnel's one origin.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "api", ROOT / "scanner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import agent_tools  # noqa: E402
from scanner_tools import http_archive_capture as capture  # noqa: E402
from scanner_tools import tool_wire_log  # noqa: E402

ORIGIN = "https://app.example.test"

# A sqlmap -t log as sqlmap writes it (fixture): a GET baseline answered 303 then followed by
# nothing (--ignore-redirects), and a POST answered 200.
SQLMAP_LOG = (
    "HTTP request [#1]:\n"
    "GET /hub/login HTTP/1.1\n"
    "Host: app.example.test\n"
    "User-agent: shakerscan-sqlmap/1.0\n"
    "\n"
    "HTTP response [#1] (303 See Other):\n"
    "Location: /hub/\n"
    "URI: https://app.example.test/hub/login\n"
    "\n"
    "\n"
    "HTTP request [#2]:\n"
    "POST /hub/login HTTP/1.1\n"
    "Host: app.example.test\n"
    "Content-type: application/x-www-form-urlencoded\n"
    "\n"
    "username=%27%20OR%201%3D1--&password=fixture-pass\n"
    "\n"
    "HTTP response [#2] (200 OK):\n"
    "Content-type: text/html\n"
    "\n"
    "<html>Invalid sign-in</html>\n"
)


def _har(*urls_and_methods):
    return json.dumps({"log": {"entries": [
        {"request": {"method": method, "url": url,
                     "headers": [{"name": "Content-Type", "value": "application/x-www-form-urlencoded"}],
                     "postData": {"text": "username=%3Csvg%3E&password=x"} if method == "POST" else {}},
         "response": {"status": 200, "headers": [{"name": "Content-Type", "value": "text/html"}],
                      "content": {"text": "<p>hi</p>"}}}
        for url, method in urls_and_methods
    ]}})


def test_a_sqlmap_traffic_log_becomes_one_transaction_per_request():
    found, dropped = tool_wire_log.wire_log_transactions("sqlmap", SQLMAP_LOG, ORIGIN)
    assert dropped == 0
    assert [(item["method"], item["url"], item["status_code"]) for item in found] == [
        ("GET", f"{ORIGIN}/hub/login", 303), ("POST", f"{ORIGIN}/hub/login", 200),
    ]
    post = found[1]
    assert post["request_body"] == "username=%27%20OR%201%3D1--&password=fixture-pass"
    assert post["request_headers"]["content-type"] == "application/x-www-form-urlencoded"
    assert post["response_body"].startswith("<html>Invalid sign-in")


def test_a_dalfox_har_keeps_only_the_tunnels_origin_and_is_bounded(monkeypatch):
    text = _har((f"{ORIGIN}/hub/login", "POST"), ("https://other.example.test/x", "GET"),
                (f"{ORIGIN}:8443/hub/login", "POST"))
    found, dropped = tool_wire_log.wire_log_transactions("dalfox", text, ORIGIN)
    assert [(item["method"], item["url"]) for item in found] == [("POST", f"{ORIGIN}/hub/login")]
    assert found[0]["request_body"] == "username=%3Csvg%3E&password=x"
    monkeypatch.setattr(tool_wire_log, "MAX_TRANSACTIONS", 2)
    found, dropped = tool_wire_log.wire_log_transactions(
        "dalfox", _har(*[(f"{ORIGIN}/a", "GET")] * 5), ORIGIN)
    assert len(found) == 2 and dropped == 3


def test_bodies_are_cut_to_a_prefix():
    big = "A" * (tool_wire_log.MAX_RESPONSE_BODY_BYTES + 100)
    text = json.dumps({"log": {"entries": [{"request": {"method": "GET", "url": f"{ORIGIN}/"},
                                            "response": {"status": 200, "content": {"text": big}}}]}})
    found, _dropped = tool_wire_log.wire_log_transactions("dalfox", text, ORIGIN)
    assert len(found[0]["response_body"]) == tool_wire_log.MAX_RESPONSE_BODY_BYTES
    assert found[0]["response_body_truncated"] is True


def test_the_worker_reads_the_log_from_the_job_scratch_directory(tmp_path):
    (tmp_path / "traffic.log").write_text(SQLMAP_LOG)
    found, dropped = agent_tools.scanner_wire_log_transactions("sqlmap", str(tmp_path), origin=ORIGIN)
    assert len(found) == 2 and dropped == 0
    assert agent_tools.scanner_wire_log_transactions("nuclei", str(tmp_path), origin=ORIGIN) is None
    assert agent_tools.scanner_wire_log_transactions("dalfox", str(tmp_path), origin=ORIGIN) is None


def test_the_worker_attaches_the_log_to_the_tunnel_account():
    import worker

    tunnel = {"host": "app.example.test", "scheme": "https"}
    attached = worker._tunnel_with_wire_log(tunnel, ([{"url": f"{ORIGIN}/x"}], 4))
    assert attached["wire_log_transactions"] == [{"url": f"{ORIGIN}/x"}] and attached["wire_log_dropped"] == 4
    assert worker._tunnel_with_wire_log(tunnel, None) is tunnel
    assert worker._tunnel_with_wire_log(None, ([{"url": "x"}], 0)) is None
    assert worker._scanner_archive_origin("https://user@app.example.test/hub/login?q=1") == ORIGIN


def _tunnel(**extra):
    return {
        "scheme": "https", "host": "app.example.test", "port": 443,
        "address_connections": {"192.0.2.10": 1}, "connections_attempted": 1,
        "connections_opened": 1, "connections_rejected": 0, "bytes_to_target": 900,
        "bytes_from_target": 4000, "http_requests_observed": 0, "content_readable": False,
        "methods_observed": {}, "request_lines": [], "request_lines_dropped": 0,
        "refused_destinations": [], "refused_destinations_other": 0, **extra,
    }


def test_a_tunnel_with_a_wire_log_archives_each_logged_request():
    found, _dropped = tool_wire_log.wire_log_transactions("sqlmap", SQLMAP_LOG, ORIGIN)
    capture.start_capture()
    try:
        capture.record_tunnel(_tunnel(wire_log_transactions=found, wire_log_dropped=0),
                              capability_name="sqli.verify_batch", tool="sqlmap")
    finally:
        calls = capture.drain_capture()["calls"]
    tunnel, *logged = calls
    assert tunnel["method"] == "CONNECT" and tunnel["tunnel"]["wire_log_archived"] == 2
    assert "wire_log_transactions" not in tunnel["tunnel"]
    assert [(call["method"], call["url"], call["status_code"], call["fidelity"]) for call in logged] == [
        ("GET", f"{ORIGIN}/hub/login", 303, "tool_wire_log"),
        ("POST", f"{ORIGIN}/hub/login", 200, "tool_wire_log"),
    ]
    assert logged[1]["request_body"].endswith("password=fixture-pass")
    assert {call["capability_name"] for call in logged} == {"sqli.verify_batch"}


def test_a_logged_request_to_another_origin_is_never_archived():
    capture.start_capture()
    try:
        capture.record_tunnel(_tunnel(wire_log_transactions=[
            {"method": "GET", "url": "https://other.example.test/", "status_code": 200}]),
            capability_name="xss.verify_batch", tool="dalfox")
    finally:
        calls = capture.drain_capture()["calls"]
    assert [call["method"] for call in calls] == ["CONNECT"]
    assert "wire_log_archived" not in calls[0]["tunnel"]
