"""In the scanner image: the sign-in probe's Dalfox run finds a login form's reflected XSS,
and cannot clear a login that does not reflect inside its probe set.

The credential profile's own sign-in endpoint is probed with Dalfox's own discovery and payloads
for the request's body, one worker, stopping at the first verified finding. Its custom-payload
mode had put every payload in the URL's query and left the body untested, so a sign-in form that
reflects its username unescaped read as tested and clean. This runs the engine's exact argv
(``build_enforced_scanner_plan``, the proxy removed and the delay set to 0 so the run is quick)
against a loopback fixture login form that reflects the username, and checks that a verified
finding arrives inside the endpoint's probe set with every payload in the body. Against a login
that echoes nothing, or echoes the username escaped, the same argv with no request ceiling sends
Dalfox's whole payload set before it reports nothing: ten times the probe set. That is why an
attempt there that verified nothing is inconclusive (``auth_endpoint_probe_limited``), never a
negative, and why a sign-in form without a verified XSS leaves the XSS family partial.

Skipped outside the scanner image (it needs ``/opt/tools/dalfox``); the release workflow runs it
there.
"""
from __future__ import annotations

import html
import http.server
import json
import subprocess
import threading
import urllib.parse
from pathlib import Path

import pytest

import agent_tools
from scan.auth_endpoint_probe import probe_set_requests

DALFOX = Path("/opt/tools/dalfox")
pytestmark = pytest.mark.skipif(not DALFOX.is_file(), reason="requires the scanner image's Dalfox")


class _ReflectingLogin(http.server.BaseHTTPRequestHandler):
    """Fixture: POST /login answers a failed sign-in that reflects the username unescaped."""

    mode = "attribute"  # or "text"; "silent" echoes nothing, "escaped" echoes it HTML-escaped

    def log_message(self, *_args):
        return None

    def _page(self, username: str = "") -> None:
        if self.mode == "silent":
            username = ""
        elif self.mode == "escaped":
            username = html.escape(username, quote=True)
        if self.mode in {"attribute", "silent", "escaped"}:
            body = ('<p>Invalid username or password</p><form method="post" action="/login">'
                    f'<input name="username" value="{username}"><input name="password" type="password">'
                    "<button>Sign in</button></form>")
        else:
            body = (f"<p>No account named {username}</p><form method=\"post\" action=\"/login\">"
                    '<input name="username"><input name="password" type="password"></form>')
        payload = f"<html><body>{body}</body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):  # noqa: N802
        self._page()

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        form = urllib.parse.parse_qs(self.rfile.read(length).decode(errors="replace"))
        self._page(form.get("username", [""])[0])


def _run_sign_in_dalfox(mode, tmp_path):
    """Run the engine's sign-in argv (no proxy, no delay) against the fixture; (findings, entries)."""
    handler = type("Handler", (_ReflectingLogin,), {"mode": mode})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/login"
        hold = probe_set_requests("xss.verify_batch", 2)
        plan = agent_tools.build_enforced_scanner_plan(
            "dalfox", url,
            {"_batch_attempt": True, "method": "POST", "body_field_names": ["username", "password"],
             "injection_field": "username", "content_type": "application/x-www-form-urlencoded",
             "probe_profile": "auth_endpoint", "probe_pace_seconds": 3},
            reserved_budget={"http_requests": hold, "state_changing_requests": hold,
                             "tool_wall_seconds": 420},
            pinned_proxy_url="socks5://127.0.0.1:9",
        )
        argv = list(plan.argv)
        index = argv.index("--proxy")
        del argv[index:index + 2]
        argv[argv.index("--delay") + 1] = "0"
        har = tmp_path / "requests.har"
        argv[argv.index("--har-file-path") + 1] = str(har)
        result = subprocess.run([str(DALFOX), *argv], capture_output=True, text=True, timeout=600,
                                stdin=subprocess.DEVNULL)
    finally:
        server.shutdown()
    findings = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    entries = json.loads(har.read_text())["log"]["entries"]
    return findings, entries, result


@pytest.mark.parametrize("mode", ["attribute", "text"])
def test_the_sign_in_probe_finds_the_login_body_reflection_inside_its_probe_set(mode, tmp_path):
    hold = probe_set_requests("xss.verify_batch", 2)
    findings, entries, result = _run_sign_in_dalfox(mode, tmp_path)
    assert any(item.get("type") == "V" for item in findings), result.stdout[-2000:]
    assert len(entries) <= hold
    # Every payload went to the sign-in request's body, none to the URL's query.
    assert all(not urllib.parse.urlsplit(entry["request"]["url"]).query for entry in entries)


@pytest.mark.parametrize("mode", ["silent", "escaped"])
def test_a_login_that_does_not_reflect_needs_far_more_than_the_probe_set_to_clear(mode, tmp_path):
    """Dalfox sends its whole payload set to a body whether or not a field reflects (1,347
    requests for two fields in v2.13.0): a negative there never fits the probe set."""
    hold = probe_set_requests("xss.verify_batch", 2)
    findings, entries, _result = _run_sign_in_dalfox(mode, tmp_path)
    assert not any(item.get("type") == "V" for item in findings)
    assert len(entries) > 4 * hold, len(entries)
