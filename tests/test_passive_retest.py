"""A passive finding is retested by the check that found it, over the request it sent.

A sensitive-exposure finding (``shakerscan_exposure_probe``) records the URL the probe read: a
retest reads it again with one plain GET and classifies the answer with the probe's own classifier,
so the finding stays open while the same exposure class matches and is likely fixed once it does
not. A missing-header finding (``http_baseline`` ``missing_header_*`` or the passive template
``http-missing-security-headers``) records the response that lacked the header: a retest sends that
GET again and reads the header. Neither sends anything else, neither reaches the AI tier, and an
answer the check cannot judge (a 503, an error page for a header) leaves the finding open.

The rows have the shapes the 2.12 Scan stores (unit fixtures under fixture hostnames); the worker
tests run the real check, over the retest's real HTTP client, against a local fixture server.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import dataclasses
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import shutil
import sys
import threading
import types
import uuid

import pytest
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "api", ROOT / "scanner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import finding_routes.router as findings_router  # noqa: E402
from capabilities.exposure_probe import classify_exposure  # noqa: E402
from proof_retest import PROOF_RETEST_GAPS, passive_retest_type, proof_retest_request  # noqa: E402
from retest_contract import (  # noqa: E402
    PASSIVE_RETEST_TYPES, SUPPORTED_RETEST_TYPES, build_replay_commands, infer_retest_inputs,
    retest_refusal_reason,
)

FINDING = uuid.UUID("88888888-8888-4888-8888-888888888888")
SITE = "http://shop.fixture.invalid"

# One body per exposure family a first Scan of a typical site reports (unit fixtures, no real
# secrets): path -> (body, content type, the class the probe proves for it).
EXPOSED: dict[str, tuple[bytes, str, str]] = {
    "/.env": (
        b"APP_ENV=production\nDB_HOST=db.internal\nDB_PASSWORD=Zq8vLp2xR9wKt4mN7sQ3\n"
        b"SESSION_SECRET=Hq7Lw2Zp9Xc4Vb8Nm3Kd6Fs1Tj5Rg0Ye\n",
        "text/plain", "environment_secret_file",
    ),
    "/.git/config": (
        b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n",
        "text/plain", "version_control_exposure",
    ),
    "/id_rsa": (
        b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1c2Vx7d1fixture\n-----END RSA PRIVATE KEY-----\n",
        "application/octet-stream", "private_key_material",
    ),
    "/.aws/credentials": (
        b"[default]\naws_access_key_id = " + b"AKIA" + b"IOSFODNN7FIXTURE\n"
        b"aws_secret_access_key = wJalrXUtnFEMIK7MDENGbPxRfiCYFIXTUREKEY12\n",
        "text/plain", "cloud_credential_material",
    ),
    "/phpinfo.php": (
        b"<!DOCTYPE html><html><head><title>phpinfo()</title></head><body><h1>PHP Version 8.1.2</h1>"
        b"<table><tr><td class=\"e\">System </td><td class=\"v\">Linux fixture </td></tr></table></body></html>",
        "text/html", "phpinfo_disclosure",
    ),
    "/backup.sql": (
        b"-- MySQL dump 10.13  Distrib 8.0.32\n--\nCREATE TABLE users (id int);\nINSERT INTO users VALUES (1);\n",
        "text/plain", "backup_or_source_artifact",
    ),
}


def _exposure(path: str, exposure_class: str, *, site: str = SITE, **evidence) -> dict:
    url = f"{site}{path}"
    return {
        "id": FINDING, "tool": "shakerscan_exposure_probe", "severity": "high", "status": "active",
        "title": f"Sensitive exposure: {exposure_class.replace('_', ' ')}", "source": "dast",
        "target_id": None, "target_url": site, "url": url, "verified": True, "proof_state": "verified",
        "evidence": {
            "exposure_class": exposure_class, "request_url": url, "response_status": 200,
            "matched_signature": "fixture_signature", "discovered_via": "seed_path",
            "proof_contract": "fixture/v1", "evidence_type": "deterministic_response_signature",
            **evidence,
        },
    }


def _baseline_header(header: str, *, site: str = SITE, path: str = "/") -> dict:
    return {
        "id": FINDING, "tool": "http_baseline", "severity": "low", "status": "active",
        "title": f"Missing {header} header", "source": "dast", "target_id": None, "target_url": site,
        "url": site, "verified": True, "proof_state": "verified",
        "evidence": {
            "check": f"missing_header_{header}", "url": site, "status": 200, "header": header,
            "observed_response": {
                "request_line": f"GET {site}{path}", "response_status": 200,
                "observed_headers": {"content-type": "text/html"}, "source_action_id": "baseline.http",
                "principal": "anonymous", "header_absent": header,
            },
        },
    }


def _template_header(header: str, *, site: str = SITE, url: str | None = None) -> dict:
    return {
        "id": FINDING, "tool": "nuclei", "severity": "low", "status": "active",
        "title": f"Missing HTTP response header: {header.title()}", "source": "dast",
        "target_id": None, "target_url": site, "url": url or f"{site}/", "verified": False,
        "evidence": {"template_id": "http-missing-security-headers", "header_name": header,
                     "matched_urls": [url or f"{site}/"], "matched_url_count": 1},
    }


EXPOSURE_ROWS = [_exposure(path, cls) for path, (_body, _type, cls) in EXPOSED.items()] + [
    # The other families the honey-style first Scan reports.
    _exposure("/actuator/env", "actuator_secret_disclosure"),
    _exposure("/swagger.json", "api_specification_secret"),
    _exposure("/config/database.yml", "configuration_secret_file"),
]
HEADER_ROWS = [
    *(_baseline_header(name) for name in (
        "content-security-policy", "referrer-policy", "permissions-policy", "strict-transport-security")),
    _template_header("x-frame-options"), _template_header("x-content-type-options"),
]


def test_the_fixture_bodies_are_what_the_probe_proves():
    for path, (body, content_type, expected) in EXPOSED.items():
        signature = classify_exposure(path=SITE + path, status=200, headers={"Content-Type": content_type}, body=body)
        assert signature is not None and signature.exposure_class == expected, path
        assert signature.proves_sensitive_exposure


@pytest.mark.parametrize("row", EXPOSURE_ROWS, ids=lambda row: row["evidence"]["exposure_class"])
def test_an_exposure_finding_is_retested_by_reading_its_url_again(row):
    request, gap = proof_retest_request(row)
    assert gap is None
    assert (request.capability, request.method, request.url) == ("exposure.probe", "GET", row["evidence"]["request_url"])
    assert request.expected == row["evidence"]["exposure_class"]
    queued = findings_router.extract_retest_inputs(dict(row))
    assert (queued["finding_type"], queued["original_url"], queued["method"]) == ("exposed_file", request.url, "GET")
    assert queued["payload"] is None and queued["request_body"] is None
    assert retest_refusal_reason(row, queued["finding_type"]) is None
    # The worker's view of the queued retest replays the same URL.
    worker_view = {**{k: v for k, v in row.items() if k != "url"}, "finding_url": row["url"],
                   "finding_type": "exposed_file", "original_url": request.url}
    assert infer_retest_inputs(worker_view)["original_url"] == request.url
    assert build_replay_commands(queued) == [f"curl -i -k {request.url}"]


@pytest.mark.parametrize("row", HEADER_ROWS, ids=lambda row: row["evidence"].get("header") or row["evidence"]["header_name"])
def test_a_missing_header_finding_is_retested_by_reading_the_header_again(row):
    request, gap = proof_retest_request(row)
    assert gap is None
    header = row["evidence"].get("header") or row["evidence"]["header_name"]
    assert (request.capability, request.method, request.url, request.expected) == (
        "http.header_check", "GET", f"{SITE}/", header)
    queued = findings_router.extract_retest_inputs(dict(row))
    assert queued["finding_type"] == "missing_header"
    assert retest_refusal_reason(row, "missing_header") is None
    assert "missing_header" in SUPPORTED_RETEST_TYPES and "missing_header" in PASSIVE_RETEST_TYPES


def test_a_header_finding_replays_the_recorded_response_on_its_own_origin_only():
    landing = _baseline_header("content-security-policy", path="/login")
    assert proof_retest_request(landing)[0].url == f"{SITE}/login"
    elsewhere = _baseline_header("referrer-policy")
    elsewhere["evidence"]["observed_response"]["request_line"] = "GET http://other.fixture.invalid/"
    assert proof_retest_request(elsewhere)[0].url == SITE


@pytest.mark.parametrize("row,gap", [
    (_exposure("/site.zip", "backup_or_source_artifact", matched_signature="backup_archive_magic"), "binary_body"),
    (_exposure("/.DS_Store", "directory_metadata_file", matched_signature="ds_store_bud1_header"), "binary_body"),
    (_exposure("/x", "environment_secret_file", request_url="/.env", site=""), "no_origin"),
    ({**_baseline_header("referrer-policy"), "url": None, "target_url": None,
      "evidence": {"check": "missing_header_referrer-policy", "header": "referrer-policy"}}, "no_origin"),
])
def test_a_passive_finding_the_retest_cannot_judge_the_same_way_is_checked_by_a_new_scan(row, gap):
    assert proof_retest_request(row) == (None, gap)
    assert retest_refusal_reason(row, passive_retest_type(row)) == "retest_by_rescan_only"
    assert PROOF_RETEST_GAPS[gap].endswith("Run a new Scan to check it again.")


def test_other_passive_findings_keep_their_reason():
    graphql = _exposure("/graphql", "graphql_introspection_enabled", discovered_via="graphql_seed")
    assert proof_retest_request(graphql) == (None, None)
    assert retest_refusal_reason(graphql, findings_router.infer_retest_type(graphql, graphql["evidence"])) \
        == "retest_exposure_by_rescan"
    template = {"tool": "nuclei", "url": SITE, "evidence": {"template_id": "CVE-2021-1234"}}
    assert proof_retest_request(template) == (None, None)
    assert retest_refusal_reason(template, None) == "retest_needs_template_replay"
    cookie = {"tool": "http_baseline", "url": SITE, "evidence": {"check": "cookie_missing_httponly"}}
    assert proof_retest_request(cookie) == (None, None)
    assert retest_refusal_reason(cookie, None) == "retest_by_rescan_only"


# --- the API -------------------------------------------------------------------------------------

def _install(monkeypatch, row: dict) -> None:
    @asynccontextmanager
    async def acquire():
        yield object()

    class _Pool:
        def acquire(self):
            return acquire()

    async def record(_conn, _finding_id):
        return dict(row)

    async def no_exposures(_conn, _finding):
        return []

    monkeypatch.setattr(findings_router, "_pool_provider", lambda: _Pool())
    monkeypatch.setattr(findings_router, "get_finding_record", record)
    monkeypatch.setattr(findings_router, "related_exposures", no_exposures)
    monkeypatch.setattr(findings_router, "_load_effective_ai_settings", lambda: {})
    # An AI verifier is configured: a passive retest still never reaches it.
    monkeypatch.setattr(findings_router, "_ai_verifier_ready", lambda: True)


@pytest.mark.parametrize("row", [EXPOSURE_ROWS[0], HEADER_ROWS[0], HEADER_ROWS[-1]],
                         ids=["exposure", "baseline-header", "template-header"])
def test_the_finding_detail_offers_a_passive_retest(monkeypatch, row):
    _install(monkeypatch, row)
    result = asyncio.run(findings_router.get_finding(str(FINDING)))
    assert result["retest_supported"] is True, result.get("retest_unsupported_reason")
    assert result["retest_type"] == ("exposed_file" if row["tool"] == "shakerscan_exposure_probe" else "missing_header")
    assert result["retest_active"] is False
    assert "retest_unsupported_reason" not in result


class _Redis:
    def ping(self):
        return True


def test_a_retest_request_queues_the_recorded_url(monkeypatch):
    row = {**EXPOSURE_ROWS[0], "target_id": uuid.uuid4()}
    _install(monkeypatch, row)
    monkeypatch.setattr(findings_router, "get_redis", lambda: _Redis())

    async def no_receipt(*_args, **_kwargs):
        return None

    queued = []

    async def enqueue(_conn, _finding, inputs, **_kwargs):
        queued.append(dict(inputs))
        raise HTTPException(status_code=409, detail={"error": "stop here"})

    monkeypatch.setattr(findings_router, "_validate_approval_receipt_for_action", no_receipt)
    monkeypatch.setattr(findings_router, "enqueue_finding_retest", enqueue)
    with pytest.raises(HTTPException):
        asyncio.run(findings_router.retest_finding(str(FINDING), None, mode=None))
    assert (queued[0]["finding_type"], queued[0]["original_url"], queued[0]["method"]) == (
        "exposed_file", f"{SITE}/.env", "GET")


# --- the worker ----------------------------------------------------------------------------------

class _Site(BaseHTTPRequestHandler):
    """A site whose exposed files and response headers a test can fix and revert (unit fixture)."""

    removed: set[str] = set()
    headers_on: dict[str, str] = {}
    root_status = 200
    seen: list[tuple[str, str, int]] = []

    def log_message(self, *_args):
        return None

    def _send(self, status: int, body: bytes, content_type: str, extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 - http.server API
        type(self).seen.append(("GET", self.path, int(self.headers.get("Content-Length") or 0)))
        if self.path == "/":
            return self._send(type(self).root_status, b"<html><body>shop</body></html>", "text/html",
                              dict(type(self).headers_on))
        if self.path in EXPOSED and self.path not in type(self).removed:
            body, content_type, _cls = EXPOSED[self.path]
            return self._send(200, body, content_type)
        # A removed file: the application's own page, as a single-page app answers unknown paths.
        return self._send(200, b"<!doctype html><html><body><div id=app></div></body></html>", "text/html")

    def do_POST(self):  # noqa: N802 - http.server API
        type(self).seen.append(("POST", self.path, 0))
        return self._send(405, b"", "text/plain")


@pytest.fixture
def site():
    if shutil.which("curl") is None:
        pytest.skip("the retest's HTTP client is curl")
    handler = type("Site", (_Site,), {"removed": set(), "headers_on": {}, "seen": [], "root_status": 200})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield handler, f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def _verification(row: dict, origin: str) -> dict:
    """A queued retest joined with its finding, as ``process_finding_retest_job`` reads it."""
    inputs = findings_router.extract_retest_inputs({**row, "target_url": origin})
    return {
        "id": uuid.uuid4(), "finding_id": FINDING, "tool": row["tool"], "title": row["title"],
        "evidence": row["evidence"], "finding_url": row["url"], "target_url": origin,
        "finding_type": inputs["finding_type"], "original_url": inputs["original_url"], "param": None,
        "method": "GET", "source_scan_target_url": origin, "source_scan_type": "full",
        "source_scan_options": {}, "auth_context": None,
    }


def _quick(monkeypatch):
    from scanner_tools import proof_of_exploit

    monkeypatch.setattr(proof_of_exploit, "_poe_config",
                        dataclasses.replace(proof_of_exploit._poe_config, rate_limit_ms=0))


@pytest.mark.parametrize("path", list(EXPOSED), ids=[cls for _b, _t, cls in EXPOSED.values()])
def test_the_worker_closes_a_removed_exposure_and_keeps_a_served_one_open(monkeypatch, site, path):
    import worker

    _quick(monkeypatch)
    handler, origin = site
    row = _exposure(path, EXPOSED[path][2], site=origin)
    still = asyncio.run(worker.run_finding_retest(_verification(row, origin)))
    assert (still["status"], still["verdict"], still["result_status"]) == ("completed", "exploited", "still_vulnerable")
    assert still["artifacts"]["check"] == "exposure.probe"
    assert still["proof"]["exposure_class"] == EXPOSED[path][2] and still["proof"]["response_status"] == 200
    assert still["has_ai_step"] is False
    # The excerpt is the probe's own: a secret-bearing body is never shown.
    assert "Zq8vLp2xR9wKt4mN7sQ3" not in str(still) and "wJalrXUtnFEMIK7MDENG" not in str(still)
    # One plain GET of the recorded URL: nothing else is sent.
    assert handler.seen == [("GET", path, 0)]

    handler.removed.add(path)
    fixed = asyncio.run(worker.run_finding_retest(_verification(row, origin)))
    assert (fixed["verdict"], fixed["result_status"]) == ("likely_fixed", "likely_fixed"), fixed["verdict_reason"]
    assert "no longer serves the exposed content" in fixed["verdict_reason"]
    assert fixed["proof"]["response_status"] == 200 and "exposure_class" not in fixed["proof"]

    handler.removed.clear()
    again = asyncio.run(worker.run_finding_retest(_verification(row, origin)))
    assert again["verdict"] == "exploited"


@pytest.mark.parametrize("row_for", [
    lambda origin: _baseline_header("content-security-policy", site=origin),
    lambda origin: _template_header("x-frame-options", site=origin),
], ids=["baseline", "template"])
def test_the_worker_closes_a_header_once_it_is_sent_and_reopens_when_it_goes(monkeypatch, site, row_for):
    import worker

    _quick(monkeypatch)
    handler, origin = site
    row = row_for(origin)
    header = row["evidence"].get("header") or row["evidence"]["header_name"]
    still = asyncio.run(worker.run_finding_retest(_verification(row, origin)))
    assert (still["verdict"], still["result_status"]) == ("exploited", "still_vulnerable"), still["verdict_reason"]
    assert still["artifacts"]["check"] == "http.header_check"
    assert still["proof"]["header_present"] is False and still["has_ai_step"] is False
    assert handler.seen == [("GET", "/", 0)]

    handler.headers_on[header] = "default-src 'self'" if header == "content-security-policy" else "DENY"
    fixed = asyncio.run(worker.run_finding_retest(_verification(row, origin)))
    assert (fixed["verdict"], fixed["result_status"]) == ("likely_fixed", "likely_fixed"), fixed["verdict_reason"]
    assert fixed["proof"]["header_present"] is True
    assert fixed["proof"]["observed_headers"][header] == handler.headers_on[header]

    handler.headers_on.clear()
    assert asyncio.run(worker.run_finding_retest(_verification(row, origin)))["verdict"] == "exploited"
    assert all(method == "GET" for method, _path, _length in handler.seen)


@pytest.mark.parametrize("status,outcome", [(503, "unavailable"), (429, "unavailable"), (404, "unjudged"), (500, "unjudged")])
def test_a_header_retest_that_gets_no_page_to_judge_leaves_the_finding_open(monkeypatch, site, status, outcome):
    import worker

    _quick(monkeypatch)
    handler, origin = site
    handler.root_status = status
    result = asyncio.run(worker.run_finding_retest(_verification(_baseline_header("referrer-policy", site=origin), origin)))
    assert (result["verdict"], result["result_status"]) == ("inconclusive", "inconclusive")
    assert result["artifacts"]["outcome"] == outcome
    assert "stays open" in result["verdict_reason"]


@pytest.mark.parametrize("status", [503, 429, 502])
def test_an_exposure_retest_against_an_unavailable_service_is_inconclusive(status):
    from worker_handlers.proof_replay import run_proof_retest

    async def answer(url, **_kwargs):
        return {"status_code": status, "headers": {}, "body": "busy", "final_url": url, "elapsed_ms": 3}

    poe = types.SimpleNamespace(fetch_with_capture=answer, start_scan_session=lambda *_a, **_k: None,
                                end_scan_session=lambda *_a, **_k: None)
    verification = _verification(EXPOSURE_ROWS[0], SITE)
    result = asyncio.run(run_proof_retest(
        verification, infer_retest_inputs(verification), poe=poe, replay_commands=[], ladder=[],
        cancelled=lambda: False))
    assert (result["verdict"], result["artifacts"]["outcome"]) == ("inconclusive", "unavailable")


def test_an_exposure_retest_that_gets_no_answer_is_inconclusive():
    from worker_handlers.proof_replay import run_proof_retest

    async def unreachable(url, **_kwargs):
        return {"status_code": 0, "headers": {}, "body": "", "final_url": url, "elapsed_ms": 3,
                "error": "curl: (7) Failed to connect"}

    poe = types.SimpleNamespace(fetch_with_capture=unreachable, start_scan_session=lambda *_a, **_k: None,
                                end_scan_session=lambda *_a, **_k: None)
    verification = _verification(EXPOSURE_ROWS[0], SITE)
    result = asyncio.run(run_proof_retest(
        verification, infer_retest_inputs(verification), poe=poe, replay_commands=[], ladder=[],
        cancelled=lambda: False))
    assert (result["verdict"], result["artifacts"]["outcome"]) == ("inconclusive", "failed")
