"""A proven Scan finding is retested with the request its proof sent, or not at all.

The SQL and NoSQL proofs record the route (``/product``), the tested field (``field_path``) and the
method; the browser XSS proof records the page URL with the tested value masked, the parameter
(``parameter_name``) and its candidate, from which its payload is derived. A retest rebuilds that
request exactly -- the route on the target's origin with the tested query parameter set as the
Scan set it, or the page with the same payload -- and replays it through the proof's own check.
When the finding does not keep what the request needs (a templated segment, a path segment, a
request body, a recorded private request, a masked value, a fragment or another page), nothing is
queued and the finding says why: it is checked again by a new Scan. It is never told that the
target's authorization does not cover a host.

The rows below have the shapes the 2.11 Scan stores for each proven kind. They are unit fixtures,
under fixture hostnames; the worker test runs the real check against a local fixture server.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import dataclasses
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import sys
import threading
import types
import urllib.parse
import uuid

import pytest
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "api", ROOT / "scanner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import finding_routes.router as findings_router  # noqa: E402
from proof_retest import PROOF_RETEST_GAPS, proof_retest_request  # noqa: E402
from retest_contract import infer_retest_inputs, retest_refusal_reason  # noqa: E402

FINDING = uuid.UUID("77777777-7777-4777-8777-777777777777")
CANDIDATE = "6ff4725e740bec0e8c3c0ef856998b102a540072479f238120b39eea2e9fa35d"
RESCAN = "retest_by_rescan_only"


def _xss_payload(candidate: str) -> str:
    marker = f"shakerscan_xss_{candidate[:12]}"
    return ('<img src=x onerror="document.documentElement.setAttribute('
            f"'data-shakerscan-proof','{marker}');console.log('{marker}')\">")


def _differential(tool: str, url: str, field: str, *, target: str = "http://shop.fixture.invalid", **evidence) -> dict:
    return {
        "id": FINDING, "tool": tool, "title": "Verified SQL injection", "severity": "critical",
        "status": "active", "source": "dast", "target_id": None, "target_url": target, "url": url,
        "evidence": {"method": "GET", "field_path": field, "request_ref_id": None,
                     "request_class": "safe_read", "candidate_id": "8eeb6fab21745777e07db6e1",
                     "proof_state": "verified", **evidence},
    }


def _sqli(url: str = "/product", field: str = "id", **evidence) -> dict:
    return _differential("shakerscan_sqli_proof", url, field, **evidence)


def _nosqli(url: str = "/api/users", field: str = "username", **evidence) -> dict:
    row = _differential("shakerscan_nosqli_verify", url, field, operator="$ne", **evidence)
    return {**row, "title": "Verified NoSQL injection"}


def _xss(url: str = "http://shop.fixture.invalid/search?q=%3Credacted%3E", **evidence) -> dict:
    stored = {
        "request_url": url, "related_request_urls": [url], "parameter_name": "q",
        "injection_location": "query", "candidate_id": CANDIDATE,
        "payload_sha256": hashlib.sha256(_xss_payload(CANDIDATE).encode()).hexdigest(),
        "execution_sink": {"signal": "console", "location": "query", "parameter": "q"},
        "proof_state": "verified",
    }
    stored.update(evidence)
    return {
        "id": FINDING, "tool": "shakerscan_browser_proof", "title": "Verified cross-site scripting",
        "severity": "high", "status": "active", "source": "dast", "target_id": None,
        "target_url": "http://shop.fixture.invalid", "url": url,
        "evidence": {key: value for key, value in stored.items() if value is not None},
    }


# (row, the URL, parameter and payload the proof sent) for every proven kind it can rebuild.
REBUILT = [
    (_sqli(), "http://shop.fixture.invalid/product?id=1", "id", None),
    (_nosqli(), "http://shop.fixture.invalid/api/users?username=1", "username", None),
    (_xss(), "http://shop.fixture.invalid/search?q=%3Credacted%3E", "q", _xss_payload(CANDIDATE)),
    # The origin the proof recorded wins over the target's URL; a path on the target URL is not kept.
    (_sqli(origin="https://api.fixture.invalid:8443"), "https://api.fixture.invalid:8443/product?id=1", "id", None),
    ({**_sqli(), "target_url": "https://shop.fixture.invalid/app/"}, "https://shop.fixture.invalid/product?id=1", "id", None),
]

# (row, gap): what each finding lacks, so nothing is sent.
GAPS = [
    (_sqli("/products/{int}", "path_2"), "path_segment"),
    (_sqli("/products/{int}", "q"), "templated_path"),
    (_nosqli("/api/{uuid}/orders", "status"), "templated_path"),
    (_sqli(request_ref_id="request-1"), "private_request"),
    (_sqli(method="POST"), "request_shape"),
    (_sqli(method=None), "request_shape"),
    (_sqli(field=""), "no_parameter"),
    (_sqli(target=""), "no_origin"),
    ({**_sqli(), "url": None}, "no_route"),
    (_differential("request_sqli_differential", None, "id", origin="http://shop.fixture.invalid"), "no_route"),
    (_differential("request_xss_differential", None, "q", origin="http://shop.fixture.invalid"), "no_route"),
    (_xss(injection_location="fragment"), "not_query"),
    (_xss("http://shop.fixture.invalid/#/search?q=%3Credacted%3E"), "not_query"),
    (_xss(related_request_urls=["http://shop.fixture.invalid/comments"]), "not_query"),
    (_xss("http://shop.fixture.invalid/search?page=1"), "not_query"),
    (_xss("http://shop.fixture.invalid/search?q=%3Credacted%3E&token=%3Credacted%3E"), "masked_value"),
    (_xss(payload_sha256="0" * 64), "payload_unknown"),
    (_xss(candidate_id=None), "payload_unknown"),
    (_xss(parameter_name=None, execution_sink={}), "no_parameter"),
]


@pytest.mark.parametrize("row,url,param,payload", REBUILT)
def test_a_proven_finding_rebuilds_the_request_its_proof_sent(row, url, param, payload):
    request, gap = proof_retest_request(row)
    assert gap is None
    assert (request.url, request.method, request.param, request.payload) == (url, "GET", param, payload)
    # The API queues exactly that request, and a retest row joined with its finding (the worker's
    # view, which keeps the finding's URL as finding_url) replays the same one.
    queued = findings_router.extract_retest_inputs(dict(row))
    assert (queued["original_url"], queued["param"], queued["method"]) == (url, param, "GET")
    assert retest_refusal_reason(row, queued["finding_type"]) is None
    worker_view = {**{k: v for k, v in row.items() if k != "url"}, "finding_url": row["url"],
                   "finding_type": queued["finding_type"], "original_url": row["url"], "param": None}
    replayed = infer_retest_inputs(worker_view)
    assert (replayed["original_url"], replayed["param"], replayed["method"]) == (url, param, "GET")


@pytest.mark.parametrize("row,gap", GAPS)
def test_a_proven_finding_whose_request_cannot_be_rebuilt_is_checked_by_a_new_scan(row, gap):
    assert proof_retest_request(row) == (None, gap)
    # Whatever type the request names, it is refused with the reason and the words for the gap.
    for override in (None, "sqli", "xss"):
        inputs = findings_router.extract_retest_inputs(dict(row), override_type=override)
        assert retest_refusal_reason(row, inputs["finding_type"]) == RESCAN
    message = PROOF_RETEST_GAPS[gap]
    assert message.endswith("Run a new Scan to check it again.")
    assert "authoriz" not in message.lower()


def test_other_findings_are_not_proof_retests():
    redirect = {"tool": "shakerscan_redirect_probe", "url": "http://shop.fixture.invalid/go?next=x",
                "evidence": {"parameter": "next"}}
    assert proof_retest_request(redirect) == (None, None)
    assert proof_retest_request({"tool": "sqlmap", "url": "/product", "evidence": {}}) == (None, None)


def test_the_browser_payload_is_the_one_the_browser_proof_sends():
    from capabilities.xss_proof_payload import xss_proof_payload

    assert xss_proof_payload(CANDIDATE) == _xss_payload(CANDIDATE)
    source = (ROOT / "api" / "capabilities" / "browser.py").read_text(encoding="utf-8")
    assert "payload = xss_proof_payload(candidate_id)" in source


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


class _Redis:
    def ping(self):
        return True


@pytest.mark.parametrize("row,retest_type", [(REBUILT[0][0], "sqli"), (REBUILT[1][0], "nosqli"), (REBUILT[2][0], "xss")])
def test_the_finding_detail_offers_a_retest_of_a_rebuilt_request(monkeypatch, row, retest_type):
    _install(monkeypatch, row)
    result = asyncio.run(findings_router.get_finding(str(FINDING)))
    assert (result["retest_supported"], result["retest_type"]) == (True, retest_type)
    assert "retest_unsupported_message" not in result


@pytest.mark.parametrize("row,gap", GAPS[:3] + GAPS[11:12])
def test_the_finding_detail_says_why_a_proven_finding_has_no_retest(monkeypatch, row, gap):
    _install(monkeypatch, row)
    result = asyncio.run(findings_router.get_finding(str(FINDING)))
    assert (result["retest_supported"], result["retest_type"], result["retest_modes"]) == (False, None, [])
    assert result["retest_unsupported_reason"] == RESCAN
    assert result["retest_unsupported_message"] == PROOF_RETEST_GAPS[gap]


@pytest.mark.parametrize("row,gap", GAPS[:4])
def test_a_retest_request_for_a_proven_finding_that_cannot_be_rebuilt_is_refused_honestly(monkeypatch, row, gap):
    _install(monkeypatch, row)
    monkeypatch.setattr(findings_router, "get_redis", lambda: _Redis())

    async def never(*_args, **_kwargs):
        raise AssertionError("nothing is queued")

    monkeypatch.setattr(findings_router, "enqueue_finding_retest", never)
    monkeypatch.setattr(findings_router, "_validate_approval_receipt_for_action", never)
    with pytest.raises(HTTPException) as refused:
        asyncio.run(findings_router.retest_finding(str(FINDING), None, mode=None))
    assert refused.value.status_code == 400
    assert refused.value.detail["error"] == "unsupported_finding_type"
    assert refused.value.detail["reason"] == RESCAN
    assert refused.value.detail["message"] == PROOF_RETEST_GAPS[gap]


def test_a_retest_request_queues_the_rebuilt_request_and_checks_its_host(monkeypatch):
    row = {**REBUILT[0][0], "target_id": uuid.uuid4()}
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
    assert queued[0]["original_url"] == "http://shop.fixture.invalid/product?id=1"
    assert (queued[0]["param"], queued[0]["method"], queued[0]["finding_type"]) == ("id", "GET", "sqli")


class _ScopeConn:
    """A target whose authorization covers shop.fixture.invalid (unit fixture)."""

    async def fetchrow(self, query, *_args):
        if "scope_receipts" in query:
            return {"verdict": "allowed", "normalized_scope": {"hosts": ["shop.fixture.invalid"]},
                    "allowed_hosts": ["shop.fixture.invalid"], "allowed_root_domains": []}
        return None


def test_a_replay_url_with_no_host_is_never_called_out_of_scope(monkeypatch):
    from scan import retest_authority

    async def standing(_conn, _target):
        return {"approval_receipt_id": str(uuid.UUID(int=5))}

    monkeypatch.setattr(retest_authority, "_current_authorization", standing)
    target = uuid.UUID(int=9)
    _record, refusal = asyncio.run(retest_authority.admit_retest(_ScopeConn(), target_id=target, destination="/product"))
    assert refusal == retest_authority.REPLAY_URL_UNRESOLVED_MESSAGE
    assert "authoriz" not in refusal.lower() and "cover" not in refusal.lower()
    # An authority clients read differently is a host no scope covers, never "no site".
    _record, spoofed = asyncio.run(retest_authority.admit_retest(
        _ScopeConn(), target_id=target, destination="http://evil.example\\@shop.fixture.invalid/x"))
    assert spoofed == "The target's authorization does not cover the host of the URL the retest replays"
    _record, covered = asyncio.run(retest_authority.admit_retest(
        _ScopeConn(), target_id=target, destination="http://shop.fixture.invalid/product?id=1"))
    assert covered is None
    # The finding router reports it as an unresolved URL, never as out of scope.
    with pytest.raises(HTTPException) as refused:
        asyncio.run(findings_router._enqueue_finding_retest_unlocked(
            _ScopeConn(), {"id": FINDING, "target_id": target},
            {"finding_type": "sqli", "target_url": "/product", "original_url": "/product"}))
    assert refused.value.detail == {"error": "replay_url_unresolved",
                                    "message": retest_authority.REPLAY_URL_UNRESOLVED_MESSAGE}


def test_a_retest_queued_before_its_request_was_rebuilt_is_bound_to_its_target_url():
    from worker_handlers.retest_authority import retest_destination

    earlier = {"tool": "shakerscan_sqli_proof", "finding_type": "sqli", "finding_url": "/products/{int}",
               "target_url": "http://shop.fixture.invalid", "original_url": "/products/{int}",
               "evidence": {"method": "GET", "field_path": "path_2"}}
    assert retest_destination(earlier) == "http://shop.fixture.invalid"
    resolvable = {**earlier, "finding_url": "/product", "original_url": "/product",
                  "evidence": {"method": "GET", "field_path": "id"}}
    assert retest_destination(resolvable) == "http://shop.fixture.invalid/product?id=1"


# --- the worker ----------------------------------------------------------------------------------

class _Shop(BaseHTTPRequestHandler):
    """``GET /product?id=N`` and ``GET /api/users?username=X`` (unit fixture). Vulnerable, the
    product id is concatenated into SQL and the user filter takes query operators; fixed, the id
    is a bound integer and the filter takes only a string."""

    vulnerable = True

    def log_message(self, *_args):
        return None

    def _send(self, status: int, body: str, content_type: str = "text/html") -> None:
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802 - http.server API
        parsed = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        values = dict(query)
        if parsed.path == "/product":
            value = values.get("id", "")
            if self.vulnerable and "'" in value:
                return self._send(500, "<pre>sqlite3.OperationalError: unrecognized token: \"'\"</pre>")
            if not value.isdigit():
                return self._send(404, "<p>No such product</p>")
            return self._send(200, f"<h1>Product {value}</h1><p>A plain mug.</p>")
        if parsed.path == "/api/users":
            users = [{"username": name} for name in ("alice", "bob", "carol")]
            if self.vulnerable:
                ne = [value for name, value in query if name == "username[$ne]"]
                eq = [value for name, value in query if name == "username[$eq]"]
                if ne:
                    found = [user for user in users if user["username"] != ne[0]]
                else:
                    wanted = eq[0] if eq else values.get("username")
                    found = [user for user in users if user["username"] == wanted]
                return self._send(200, json.dumps(found), "application/json")
            if "username" not in values:
                return self._send(400, json.dumps({"error": "username is required"}), "application/json")
            found = [user for user in users if user["username"] == values["username"]]
            return self._send(200, json.dumps(found), "application/json")
        return self._send(404, "not found")


@pytest.fixture
def shop():
    if shutil.which("curl") is None:
        pytest.skip("the retest's HTTP client is curl")
    handler = type("Shop", (_Shop,), {"vulnerable": True})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield handler, f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def _verification(row: dict, origin: str) -> dict:
    """A retest row joined with its finding, as ``process_finding_retest_job`` reads it."""
    return {
        "id": uuid.uuid4(), "finding_id": FINDING, "tool": row["tool"], "title": row["title"],
        "evidence": row["evidence"], "finding_url": row["url"], "target_url": origin,
        "finding_type": "nosqli" if row["tool"] == "shakerscan_nosqli_verify" else "sqli",
        "original_url": origin + row["url"], "param": None, "method": "GET",
        # The Scan that found it ran against this origin with exploit depth: its private target
        # is in scope for the retest's verdict.
        "source_scan_target_url": origin, "source_scan_type": "full",
        "source_scan_options": {"exploit_depth": True}, "auth_context": None,
    }


@pytest.mark.parametrize("row", [_sqli(), _nosqli()], ids=["sqli", "nosqli"])
def test_the_worker_retests_a_proven_injection_with_the_check_that_proved_it(monkeypatch, shop, row):
    import worker
    from scanner_tools import proof_of_exploit

    handler, origin = shop
    monkeypatch.setattr(proof_of_exploit, "_poe_config", dataclasses.replace(proof_of_exploit._poe_config, rate_limit_ms=0))
    sent = []
    real_fetch = proof_of_exploit.fetch_with_capture

    async def fetch(url, *args, **kwargs):
        sent.append(url)
        return await real_fetch(url, *args, **kwargs)

    monkeypatch.setattr(proof_of_exploit, "fetch_with_capture", fetch)
    still = asyncio.run(worker.run_finding_retest(_verification(row, origin)))
    assert (still["status"], still["verdict"], still["result_status"]) == ("completed", "exploited", "still_vulnerable")
    assert still["artifacts"]["check"] == ("sqli.prove_batch" if row["tool"] == "shakerscan_sqli_proof" else "nosqli.verify_batch")
    # Every request is the proved route with the tested parameter, and nothing else.
    field = row["evidence"]["field_path"]
    assert sent and all(urllib.parse.urlsplit(url).path == row["url"] for url in sent)
    assert all(urllib.parse.unquote(urllib.parse.urlsplit(url).query).startswith(field) for url in sent)

    handler.vulnerable = False
    sent.clear()
    fixed = asyncio.run(worker.run_finding_retest(_verification(row, origin)))
    assert (fixed["status"], fixed["verdict"], fixed["result_status"]) == ("completed", "likely_fixed", "likely_fixed")
    assert "check that proved the finding" in fixed["verdict_reason"]
    assert fixed["has_ai_step"] is False and sent


@pytest.mark.parametrize("row", [_sqli(), _nosqli()], ids=["sqli", "nosqli"])
def test_a_proven_injection_whose_retest_requests_get_no_answer_is_inconclusive(row):
    """A target that answers nothing reproduces nothing, and that is no evidence of a fix."""
    from worker_handlers.proof_replay import run_proof_retest

    sent = []

    async def unreachable(url, **_kwargs):
        sent.append(url)
        return {"status_code": 0, "headers": {}, "body": "", "final_url": url, "elapsed_ms": 3,
                "error": "curl: (7) Failed to connect to shop.fixture.invalid port 80"}

    poe = types.SimpleNamespace(fetch_with_capture=unreachable, start_scan_session=lambda *_a, **_k: None,
                                end_scan_session=lambda *_a, **_k: None)
    verification = _verification(row, "http://shop.fixture.invalid")
    result = asyncio.run(run_proof_retest(
        verification, infer_retest_inputs(verification), poe=poe, replay_commands=[], ladder=[],
        cancelled=lambda: False))
    assert sent
    assert (result["verdict"], result["result_status"]) == ("inconclusive", "inconclusive")
    assert "did not all get an answer" in result["verdict_reason"]
    assert result["proof"]["errors"]


def test_the_worker_sends_nothing_for_a_proven_finding_it_cannot_rebuild(monkeypatch):
    import worker
    from scanner_tools import proof_of_exploit

    async def never(*_args, **_kwargs):
        raise AssertionError("nothing is sent")

    monkeypatch.setattr(proof_of_exploit, "fetch_with_capture", never)
    row = _sqli("/products/{int}", "q")
    result = asyncio.run(worker.run_finding_retest(_verification(row, "http://shop.fixture.invalid")))
    assert (result["verdict"], result["result_status"]) == ("inconclusive", "inconclusive")
    assert result["verdict_reason"] == PROOF_RETEST_GAPS["templated_path"]
    assert result["artifacts"]["skipped_reason"] == "templated_path"


def _browser_poe(*, available: bool, proven: bool, status: int = 200):
    calls = []

    async def fetch(url, **_kwargs):
        calls.append(("fetch", url))
        return {"status_code": status, "headers": {}, "body": "<p>results</p>", "final_url": url}

    async def browser():
        return available

    async def headless(url, param, payload, **kwargs):
        calls.append(("browser", url, param, payload))
        return types.SimpleNamespace(proven=proven, technique="headless_xss_console", evidence_type="dom_execution")

    from scanner_tools.proof_of_exploit import baseline_refusal

    poe = types.SimpleNamespace(
        fetch_with_capture=fetch, baseline_refusal=baseline_refusal, headless_browser_available=browser,
        prove_xss_headless=headless, start_scan_session=lambda *_a, **_k: None,
        end_scan_session=lambda *_a, **_k: None,
    )
    return poe, calls


@pytest.mark.parametrize("available,proven,status,verdict", [
    (True, True, 200, "exploited"),
    (True, False, 200, "likely_fixed"),
    (False, False, 200, "inconclusive"),
    (True, False, 401, "inconclusive"),
])
def test_a_browser_proof_is_retested_with_its_own_payload_in_a_browser(available, proven, status, verdict):
    from worker_handlers.proof_replay import run_proof_retest

    row = _xss()
    poe, calls = _browser_poe(available=available, proven=proven, status=status)
    verification = {**_verification({**row, "url": row["url"]}, "http://shop.fixture.invalid"),
                    "finding_url": row["url"], "finding_type": "xss",
                    "source_scan_target_url": "http://shop.fixture.invalid"}
    result = asyncio.run(run_proof_retest(
        verification, infer_retest_inputs(verification), poe=poe, replay_commands=[], ladder=[],
        cancelled=lambda: False))
    assert result["verdict"] == verdict
    # One ordinary request of the page (the tested value inert), then the proof's own payload.
    assert calls[0] == ("fetch", "http://shop.fixture.invalid/search?q=shakerscan")
    browsed = [call for call in calls if call[0] == "browser"]
    if available and status == 200:
        assert browsed == [("browser", row["url"], "q", _xss_payload(CANDIDATE))]
    else:
        assert browsed == []


def test_automatic_retests_skip_a_proven_finding_that_cannot_be_rebuilt(monkeypatch):
    """The automatic queue after a Scan asks the same question as the API (unit fixtures)."""
    import worker

    rebuilt = {**_sqli(), "id": uuid.uuid4(), "scan_id": None, "verification_count": 0,
               "last_verification_verdict": None}
    templated = {**_sqli("/products/{int}", "q"), "id": uuid.uuid4(), "scan_id": None,
                 "verification_count": 0, "last_verification_verdict": None}

    class Conn:
        async def fetchrow(self, _query, *_args):
            return {"options": "{}"}

        async def fetch(self, _query, *_args):
            return [templated, rebuilt]

        async def fetchval(self, _query, *_args):
            return None

        async def execute(self, query, *_args):
            raise AssertionError(f"nothing is queued: {query[:40]}")

    class Pool:
        def acquire(self):
            class _Acquire:
                async def __aenter__(self):
                    return Conn()

                async def __aexit__(self, *_exc):
                    return False
            return _Acquire()

    admitted = []

    async def admit(_conn, **kwargs):
        admitted.append(kwargs["destination"])
        return None, "outside the fixture scope"

    async def running(_conn, _scan_id):
        return False

    policy = dataclasses.replace(
        worker.VerificationPolicy.from_env(overrides={}), auto_retest_enabled=True,
        auto_retest_max_per_scan=5, verification_min_severity="low")
    monkeypatch.setattr(worker.VerificationPolicy, "from_env", classmethod(lambda cls, overrides=None: policy))
    monkeypatch.setattr(worker, "_load_runtime_ai_settings", lambda: {})
    monkeypatch.setattr(worker, "db_pool", Pool())
    monkeypatch.setattr(worker, "get_redis", lambda: object())
    monkeypatch.setattr(worker, "scan_stopped_by_authority", running)
    monkeypatch.setattr(worker, "admit_retest", admit)
    counts = asyncio.run(worker.queue_auto_retests_for_scan(str(uuid.uuid4()), None, "http://shop.fixture.invalid"))
    assert counts == {"queued": 0, "skipped": 2}
    # Only the rebuilt request reaches admission, as the request its proof sent.
    assert admitted == ["http://shop.fixture.invalid/product?id=1"]
