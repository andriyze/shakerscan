"""A proven server-side injection is retested by the check that proved it, one class only."""
from __future__ import annotations

import asyncio
import dataclasses
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import shutil
import sys
import threading
import urllib.parse
import uuid

import pytest

ROOT = Path(__file__).resolve().parents[1]
for entry in (ROOT / "api", ROOT / "scanner"):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

import finding_routes.router as findings_router  # noqa: E402
from proof_retest import proof_retest_request  # noqa: E402
from retest_contract import infer_type_from_title_tool, retest_refusal_reason  # noqa: E402

FINDING = uuid.UUID("77777777-7777-4777-8777-777777777778")
PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"


def _row(title: str, injection_class: str, *, url: str = "/download", field: str = "file",
         method: str = "GET", **evidence) -> dict:
    return {
        "id": FINDING, "tool": "shakerscan_injection_verify", "title": title, "severity": "high",
        "status": "active", "source": "dast", "target_id": None,
        "target_url": "http://shop.fixture.invalid", "url": url,
        "evidence": {"method": method, "field_path": field, "request_ref_id": None,
                     "request_class": "safe_read", "candidate_id": "8eeb6fab21745777e07db6e1",
                     "proof_state": "verified", "injection_class": injection_class, **evidence},
    }


TRAVERSAL = _row("Verified path traversal", "path_traversal")


@pytest.mark.parametrize(("title", "retest_type"), [
    ("Verified server-side template injection", "ssti"),
    ("Verified command injection", "command_injection"),
    ("Verified path traversal", "path_traversal"),
    ("Verified XML external entity injection", "xxe"),
    ("Verified server-side request forgery", "ssrf"),
])
def test_each_injection_finding_names_its_retest_type_by_its_whole_title(title, retest_type):
    assert infer_type_from_title_tool(title, "shakerscan_injection_verify") == retest_type
    # Never a guess from words in a title: only the titles the finalizer gives.
    assert infer_type_from_title_tool(title + " in search", "shakerscan_injection_verify") is None


def test_a_proven_injection_rebuilds_its_request_and_names_its_one_class():
    request, gap = proof_retest_request(TRAVERSAL)
    assert gap is None
    assert request.capability == "injection.verify_batch"
    assert request.url == "http://shop.fixture.invalid/download?file=1"
    assert (request.param, request.expected) == ("file", "path_traversal")
    assert retest_refusal_reason(TRAVERSAL, "path_traversal") is None


def test_an_injection_proved_through_a_body_is_checked_by_a_new_scan():
    row = _row("Verified XML external entity injection", "xxe", url="/order", field="item", method="POST")
    assert proof_retest_request(row) == (None, "request_shape")


class _Files(BaseHTTPRequestHandler):
    """``GET /download?file=NAME`` (unit fixture). Vulnerable, the name is joined to a directory
    and read; fixed, only a listed name is served."""

    vulnerable = True

    def log_message(self, *_args):
        return None

    def do_GET(self):  # noqa: N802 - http.server API
        parsed = urllib.parse.urlsplit(self.path)
        name = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)).get("file", "")
        if parsed.path != "/download":
            status, body = 404, "not found"
        elif self.vulnerable and name.startswith("../") and name.endswith("/etc/passwd"):
            status, body = 200, PASSWD
        elif name == "1":
            status, body = 200, "report one\n"
        else:
            status, body = 404, "no such file\n"
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def files():
    if shutil.which("curl") is None:
        pytest.skip("the retest's HTTP client is curl")
    handler = type("Files", (_Files,), {"vulnerable": True})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield handler, f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def _verification(row: dict, origin: str) -> dict:
    admitted = findings_router.extract_retest_inputs({**row, "target_url": origin})["original_url"]
    return {
        "id": uuid.uuid4(), "finding_id": FINDING, "tool": row["tool"], "title": row["title"],
        "evidence": row["evidence"], "finding_url": row["url"], "target_url": origin,
        "finding_type": "path_traversal", "original_url": admitted, "param": None, "method": "GET",
        "source_scan_target_url": origin, "source_scan_type": "full",
        "source_scan_options": {"exploit_depth": True}, "auth_context": None,
    }


def test_the_worker_retests_a_proven_traversal_with_the_check_that_proved_it(monkeypatch, files):
    import worker
    from scanner_tools import proof_of_exploit

    handler, origin = files
    monkeypatch.setattr(proof_of_exploit, "_poe_config",
                        dataclasses.replace(proof_of_exploit._poe_config, rate_limit_ms=0))
    sent = []
    real_fetch = proof_of_exploit.fetch_with_capture

    async def fetch(url, *args, **kwargs):
        sent.append(url)
        return await real_fetch(url, *args, **kwargs)

    monkeypatch.setattr(proof_of_exploit, "fetch_with_capture", fetch)
    still = asyncio.run(worker.run_finding_retest(_verification(TRAVERSAL, origin)))
    assert (still["status"], still["verdict"], still["result_status"]) == (
        "completed", "exploited", "still_vulnerable",
    )
    assert still["artifacts"]["check"] == "injection.verify_batch"
    # Only the class the finding proved is run: no template or command probe is sent.
    values = [urllib.parse.unquote(urllib.parse.urlsplit(url).query) for url in sent]
    assert all(urllib.parse.urlsplit(url).path == "/download" for url in sent)
    assert not any("{{" in value or "echo" in value or "sleep" in value for value in values)

    handler.vulnerable = False
    sent.clear()
    fixed = asyncio.run(worker.run_finding_retest(_verification(TRAVERSAL, origin)))
    assert (fixed["status"], fixed["verdict"], fixed["result_status"]) == (
        "completed", "likely_fixed", "likely_fixed",
    )
