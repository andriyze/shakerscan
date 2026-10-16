"""A Scan's request archive accounts for the traffic of every capability, tunnelled ones included.

External tools (template batches, crawlers, content discovery, probes, process verifiers) and the
engine's browser reach the target only through a pinned SOCKS tunnel that admits one host and
port. Before, none of that traffic reached the archive: a lab Scan's archive held 14 calls while
its budget counted 5,731, and named eight capabilities as "relayed as an opaque pinned tunnel,
not archived", so the Scan's scope could not be shown from it. Now each tunnel writes one row
naming its destination (and any destination it refused), and a cleartext tunnel also writes the
request lines it relayed.

Entry points: the pinned proxy, the worker's scanner process runner, the Scan dispatcher's single
and batch external actions (one per capability family), the browser proof adapter, and the
archive reader. Targets are loopback fixture servers or fixture process results; no real target
is contacted.
"""

from __future__ import annotations

import asyncio
import json
import sys
import types
import urllib.parse
import uuid

import pytest
import scan.action_adapter as action_adapter_module
from capabilities import scanner as scanner_capability
from hunt.capability_executor import CapabilityAdapterResult
from pinned_socks_proxy import MAX_REFUSED_DESTINATIONS, PinnedSocksProxy
from runtime.http_archive import scan_transactions_from_capture
from runtime.http_archive_reader import (
    archive_fidelity,
    read_archive_stats,
    scan_action_sent_traffic,
)
from runtime.models import ScanPolicy
from scan.action_plan import ScanActionPlan
from scan.work_manifests import build_candidate_manifest, build_endpoint_manifest

from tests.test_pinned_socks_proxy import _socks_connect
from tests.test_scan_action_adapter import (
    TARGET,
    Backend,
    _action,
    _dispatcher,
    _lease,
    _noop,
)

capture = scanner_capability._scan_capture


def test_every_tunnel_recorder_writes_into_the_one_capture_the_worker_drains():
    import worker
    from capabilities import browser

    assert action_adapter_module._scan_capture is capture
    assert browser._scan_capture is capture
    assert worker.scanner_http_capture is capture


# --- the pinned proxy -------------------------------------------------------------------------


async def _serve_http(seen: list[bytes]):
    async def handle(reader, writer):
        try:
            while True:
                head = await reader.readuntil(b"\r\n\r\n")
                seen.append(head)
                length = next((int(line.split(b":", 1)[1]) for line in head.split(b"\r\n")
                               if line.lower().startswith(b"content-length:")), 0)
                if length:
                    await reader.readexactly(length)
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    try:
        return await asyncio.start_server(handle, "127.0.0.1", 0)
    except PermissionError:
        pytest.skip("the unit-test sandbox forbids loopback listeners")


async def _send_through(proxy_url: str, host: str, port: int, payload: bytes, *, replies: int):
    reader, writer, code = await _socks_connect(proxy_url, host, port)
    assert code == 0
    writer.write(payload)
    await writer.drain()
    for _ in range(replies):
        await reader.readuntil(b"ok")
    writer.close()
    await writer.wait_closed()


def _tunnel_through_fixture_server(*, refused_hosts=("evil.example.test",), payload=None, replies=2):
    async def scenario():
        seen: list[bytes] = []
        server = await _serve_http(seen)
        port = server.sockets[0].getsockname()[1]
        async with server, PinnedSocksProxy(
            hostname="app.example.test", pinned_address="127.0.0.1", port=port,
        ) as proxy:
            await _send_through(
                proxy.proxy_url, "app.example.test", port,
                payload if payload is not None else (
                    b"GET /login?next=%2F HTTP/1.1\r\nHost: app.example.test\r\n\r\n"
                    b"POST /api/items HTTP/1.1\r\nHost: app.example.test\r\n"
                    b"Content-Length: 28\r\n\r\nGET /smuggled HTTP/1.1\r\n\r\n12"
                ),
                replies=replies,
            )
            for host in refused_hosts:
                _reader, writer, code = await _socks_connect(proxy.proxy_url, host, port)
                assert code == 2
                writer.close()
            # The relay has read every byte the client sent once the counters show them.
            sent = len(payload) if payload is not None else 0
            for _ in range(100):
                if proxy.http_requests_observed >= replies and proxy.bytes_to_target >= sent:
                    break
                await asyncio.sleep(0.01)
            return proxy.tunnel_record(scheme="http"), port, seen

    return asyncio.run(asyncio.wait_for(scenario(), 10))


def test_a_cleartext_tunnel_keeps_each_request_line_and_its_host_header():
    record, port, seen = _tunnel_through_fixture_server()

    assert len(seen) == 2  # the server saw exactly the two messages
    assert record["host"] == "app.example.test" and record["port"] == port
    assert record["address_connections"] == {"127.0.0.1": 1}
    assert record["content_readable"] is True
    # A request line inside a body is data, not a request (the counter's message framing).
    assert record["request_lines"] == [
        {"method": "GET", "target": "/login?next=%2F", "host": "app.example.test"},
        {"method": "POST", "target": "/api/items", "host": "app.example.test"},
    ]
    assert record["methods_observed"] == {"GET": 1, "POST": 1}
    assert record["refused_destinations"] == [
        {"destination": f"evil.example.test:{port}", "attempts": 1},
    ]


def test_an_encrypted_tunnel_proves_its_destination_and_claims_no_content():
    record, _port, _seen = _tunnel_through_fixture_server(
        refused_hosts=(), payload=b"\x16\x03\x01\x02\x00\x01\x00\x01\xfcok-not-http", replies=0,
    )
    assert record["content_readable"] is False
    assert record["request_lines"] == [] and record["methods_observed"] == {}
    assert record["connections_opened"] == 1 and record["bytes_to_target"] > 0


def test_refused_destinations_are_bounded_by_name_and_counted_beyond():
    hosts = tuple(f"other-{index}.example.test" for index in range(MAX_REFUSED_DESTINATIONS + 3))
    record, _port, _seen = _tunnel_through_fixture_server(refused_hosts=hosts)
    assert len(record["refused_destinations"]) == MAX_REFUSED_DESTINATIONS
    assert record["refused_destinations_other"] == 3


# --- the worker's process runner --------------------------------------------------------------


class _Redis:
    def exists(self, _key):
        return False


class _Process:
    pid = 4343

    def __init__(self, stdout: bytes):
        self.returncode = 0
        self.stdout = asyncio.StreamReader()
        self.stderr = asyncio.StreamReader()
        self.stdout.feed_data(stdout)
        self.stdout.feed_eof()
        self.stderr.feed_eof()

    async def wait(self):
        return self.returncode

    def kill(self):
        self.returncode = -9


def test_the_scanner_process_runner_returns_its_tunnels_account(monkeypatch):
    """The real runner and pinned proxy; the crawler process is a fixture that sends two
    requests through the proxy the runner gave it on its command line."""
    import worker

    monkeypatch.setattr(worker, "get_redis", lambda: _Redis())

    async def scenario():
        seen: list[bytes] = []
        server = await _serve_http(seen)
        port = server.sockets[0].getsockname()[1]

        async def fixture_crawler(*cmd, **_kwargs):
            proxy_url = next(str(item) for item in cmd if str(item).startswith("socks5://"))
            await _send_through(
                proxy_url, "app.example.test", port,
                b"GET / HTTP/1.1\r\nHost: app.example.test\r\n\r\n"
                b"HEAD /robots.txt HTTP/1.1\r\nHost: app.example.test\r\n\r\n",
                replies=1,
            )
            await asyncio.sleep(0.05)
            return _Process(b"")

        monkeypatch.setattr(worker.asyncio, "create_subprocess_exec", fixture_crawler)
        async with server:
            return await worker._execute_agent_scanner_process({
                "job_id": "tunnel-job-1",
                "tool_name": "katana",
                "registered_target": f"http://app.example.test:{port}",
                "execution_target": f"http://app.example.test:{port}/",
                "scanner_options": {},
                "timeout_ms": 30_000,
                "pinned_address": "127.0.0.1",
                "authorized_addresses": ["127.0.0.1"],
                "_reserved_budget": {"http_requests": 20, "tool_wall_seconds": 30},
            }), port

    result, port = asyncio.run(scenario())
    tunnel = result["tunnel"]
    assert tunnel["scheme"] == "http" and tunnel["host"] == "app.example.test"
    assert tunnel["port"] == port
    assert [line["method"] for line in tunnel["request_lines"]] == ["GET", "HEAD"]
    assert result["network_telemetry"]["connections_opened"] == 1


def test_a_queued_scanner_job_result_does_not_carry_the_archive_account(monkeypatch):
    import worker

    stored = {}

    class Redis:
        def set(self, key, value, ex=None):
            stored[key] = json.loads(value)

        def hset(self, *_a, **_k):
            return None

        def expire(self, *_a):
            return None

        def delete(self, *_a):
            return None

    async def runner(_job):
        return {"status": "success", "tunnel": {"host": "app.example.test", "request_lines": []}}

    monkeypatch.setattr(worker, "get_redis", lambda: Redis())
    monkeypatch.setattr(worker, "_execute_agent_scanner_process", runner)
    asyncio.run(worker.process_agent_scanner_tool_job({"job_id": "legacy-1"}))
    assert "tunnel" not in stored["agent_tool_result:legacy-1"]


# --- the Scan dispatcher: one test per capability family --------------------------------------


def _fixture_tunnel(*, scheme="https", port=443, lines=(), readable=True, refused=()):
    return {
        "scheme": scheme, "host": "app.example.test", "port": port,
        "address_connections": {"192.0.2.10": 1}, "connections_attempted": 1,
        "connections_opened": 1, "connections_rejected": 0, "bytes_to_target": 517,
        "bytes_from_target": 4096, "http_requests_observed": len(lines),
        "content_readable": readable, "methods_observed": {},
        "request_lines": list(lines), "request_lines_dropped": 0,
        "refused_destinations": list(refused), "refused_destinations_other": 0,
    }


def _run_real_scanner_adapter(monkeypatch, tunnel):
    """The dispatcher builds the real ScannerExecutionAdapter; its execute runs with a fixture
    process result (the shared executor is bypassed: it only wraps the adapter)."""
    payloads = []

    async def execute(_self, context, adapter, **_kwargs):
        async def process_runner(payload, heartbeat):
            payloads.append(payload)
            return {"status": "success", "typed_output": {"records": []}, "settlement": {},
                    "elapsed_seconds": 2, "tunnel": dict(tunnel)}

        adapter._process_runner = process_runner
        await adapter.execute(heartbeat=_noop, cancelled=lambda: False)
        assert "tunnel" not in adapter.process_result
        return CapabilityAdapterResult(
            status="success", actual_budget={name: 1 for name in context.requested_budget},
            observations=(), execution_started=True, parser_version="fixture/v1",
        )

    monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", execute)
    return payloads


def _drained_rows(scan_id: str):
    rows = scan_transactions_from_capture(capture.drain_capture(), scan_id=scan_id, target_id=None)
    return [
        {"capability": row.capability_name, "method": row.method, "url": row.url,
         "fidelity": row.metadata.get("fidelity"), "tunnel": row.metadata.get("tunnel"),
         "host_header": dict(row.request_headers or {}).get("host")}
        for row in rows
    ]


@pytest.mark.parametrize("capability", [
    "web.probe", "web.crawl", "web.browser_crawl", "web.content_discover",
])
def test_a_single_external_action_archives_its_tunnel_under_its_capability(monkeypatch, capability):
    action = _action("external.one", capability, 0)
    plan = ScanActionPlan(scan_id=str(uuid.uuid4()), execution_plan_digest="a" * 64,
                          target_binding_digest=TARGET.digest, actions=(action,))
    payloads = _run_real_scanner_adapter(monkeypatch, _fixture_tunnel(readable=False))
    dispatcher = _dispatcher(plan, Backend(), policy=ScanPolicy(
        active_testing=True, approval_receipt_id="approval-1"))

    capture.start_capture()
    try:
        asyncio.run(dispatcher(action, _lease(plan, action), _noop))
    finally:
        rows = _drained_rows(plan.scan_id)
    assert payloads, "the scanner process ran"
    assert rows == [{
        "capability": capability, "method": "CONNECT", "url": "https://app.example.test/",
        "fidelity": "pinned_tunnel", "tunnel": rows[0]["tunnel"], "host_header": None,
    }]
    assert rows[0]["tunnel"]["content_readable"] is False
    assert rows[0]["tunnel"]["tool"] == payloads[0]["tool_name"]


def _candidate_batch_plan(capability: str):
    scan_id = str(uuid.uuid4())
    endpoints = build_endpoint_manifest(
        scan_id=scan_id, target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2", "status": "complete", "reason": None,
            "endpoints": [{
                "method": "GET", "scheme": "https", "host": "app.example.test", "port": 443,
                "normalized_path": "/search", "concrete_path": "/search",
                "query_keys": ["q"], "source": "web.crawl",
            }],
        },
        source_action_ids=("discover.web_crawl",),
    )
    candidates = build_candidate_manifest(
        endpoints, source_action_ids=("discover.web_crawl",), maximum=10,
    )
    action = _action("verify.batch.00000", capability, 0, capability_args={
        "candidate_manifest_ref": candidates.reference().canonical_dict(),
        "endpoint_manifest_ref": endpoints.reference().canonical_dict(),
        "slice": {"start": 0, "count": 1}, "profile": "balanced", "proof_policy": "deterministic",
    })
    plan = ScanActionPlan(scan_id=scan_id, execution_plan_digest="a" * 64,
                          target_binding_digest=TARGET.digest, actions=(action,))
    return plan, action, Backend(manifests={
        endpoints.manifest_id: endpoints, candidates.manifest_id: candidates,
    })


def _template_batch_plan(capability: str):
    from tests.test_nuclei_active_batch_wiring import _plan_and_action

    plan, action, backend = _plan_and_action(requested_budget={"http_requests": 120, "tool_wall_seconds": 45})
    assert action.capability_name == capability
    return plan, action, backend


@pytest.mark.parametrize("capability,build", [
    ("xss.verify_batch", _candidate_batch_plan),
    ("sqli.verify_batch", _candidate_batch_plan),
    ("templates.active_batch", _template_batch_plan),
])
def test_a_batch_attempt_archives_its_tunnel_under_the_batch_capability(monkeypatch, capability, build):
    """Each attempt runs the family's per-candidate capability (dalfox, sqlmap, nuclei); the
    archive names the Scan action's batch capability, which is what its completeness is judged
    against. (templates.passive_batch runs through the same attempt constructor.)"""
    monkeypatch.setattr(action_adapter_module, "nuclei_templates_directory", lambda: str(
        __import__("pathlib").Path(__file__).resolve().parent / "fixtures" / "nuclei_templates"))
    plan, action, backend = build(capability)
    lines = [{"method": "GET", "target": "/search?q=%3Cscript%3E", "host": "evil.example.test"}]
    payloads = _run_real_scanner_adapter(monkeypatch, _fixture_tunnel(
        scheme="http", port=8080, lines=lines,
        refused=[{"destination": "oob.example.net:80", "attempts": 2}],
    ))
    dispatcher = _dispatcher(plan, backend, policy=ScanPolicy(
        active_testing=True, approval_receipt_id="approval-1"))

    capture.start_capture()
    try:
        asyncio.run(dispatcher(action, _lease(plan, action), _noop))
    finally:
        rows = _drained_rows(plan.scan_id)
    assert payloads, "an attempt ran"
    assert rows and {row["capability"] for row in rows} == {capability}
    tunnels = [row for row in rows if row["fidelity"] == "pinned_tunnel"]
    requests = [row for row in rows if row["fidelity"] == "tunnel_request_line"]
    assert len(tunnels) == len(payloads) and len(requests) == len(payloads)
    assert tunnels[0]["url"] == "http://app.example.test:8080/"
    assert tunnels[0]["tunnel"]["refused_destinations"] == [
        {"destination": "oob.example.net:80", "attempts": 2},
    ]
    # The destination is the tunnel's; a Host header the tool wrote is kept as written.
    assert requests[0]["url"] == "http://app.example.test:8080/search?q=%3Cscript%3E"
    assert requests[0]["host_header"] == "evil.example.test"


def test_outside_a_scan_capture_a_tunnel_records_nothing():
    """A Hunt (or any work without an open Scan capture) is unchanged."""
    assert not capture.capture_active()
    capture.record_tunnel(_fixture_tunnel(), capability_name="web.crawl", tool="katana")
    assert capture.drain_capture()["calls"] == []


def test_lines_a_tunnel_could_not_keep_make_the_archive_partial():
    capture.start_capture()
    tunnel = _fixture_tunnel(scheme="http", port=80, lines=[{"method": "GET", "target": "/"}])
    tunnel["request_lines_dropped"] = 7
    capture.record_tunnel(tunnel, capability_name="web.content_discover", tool="ffuf")
    drained = capture.drain_capture()
    assert drained["dropped"] == 7
    assert [call["url"] for call in drained["calls"]] == ["http://app.example.test/"] * 2


# --- the browser ------------------------------------------------------------------------------


def test_the_browser_proofs_tunnel_is_archived_under_its_capability(monkeypatch):
    from capabilities import browser
    from capabilities.browser import XSSBrowserProofAdapter

    class RecordingProxy:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.socket_factory = types.SimpleNamespace(policy_receipt={})
            self.address_attempts = {"192.0.2.10": 1}
            self.address_connections = {"192.0.2.10": 1}
            self.proxy_url = "socks5://127.0.0.1:41000"

        async def start(self):
            return self

        async def close(self):
            return None

        def tunnel_record(self, *, scheme):
            return {**_fixture_tunnel(scheme=scheme, readable=False),
                    "host": self.kwargs["hostname"], "port": self.kwargs["port"]}

    class Starter:
        async def start(self):
            raise RuntimeError("fixture: no browser in unit tests")

    async_api = types.ModuleType("playwright.async_api")
    async_api.TimeoutError = type("FixtureTimeout", (Exception,), {})
    async_api.async_playwright = lambda: Starter()
    package = types.ModuleType("playwright")
    package.async_api = async_api
    monkeypatch.setitem(sys.modules, "playwright", package)
    monkeypatch.setitem(sys.modules, "playwright.async_api", async_api)
    monkeypatch.setattr(browser, "PinnedSocksProxy", RecordingProxy)

    target = TARGET
    prepared = XSSBrowserProofAdapter.prepare(
        target=target, execution_url="https://app.example.test/#/search?q=seed",
        candidate_id="c0deadbeefcafe01", parameter_name="q",
    )
    capture.start_capture()
    try:
        asyncio.run(XSSBrowserProofAdapter(prepared).execute(
            heartbeat=_noop, cancelled=lambda: False))
    finally:
        rows = _drained_rows("11111111-1111-4111-8111-111111111111")
    assert [(row["capability"], row["method"], row["url"]) for row in rows] == [
        ("xss.browser_prove_batch", "CONNECT", "https://app.example.test/"),
    ]
    assert rows[0]["tunnel"]["tool"] == "chromium"


# --- the reader -------------------------------------------------------------------------------


class _StatsConn:
    """Fixture connection answering the reader's queries by shape (not a database)."""

    def __init__(self, *, actions, origins, refused=(), detail=None):
        self.actions, self.origins, self.refused = actions, origins, list(refused)
        self.detail = detail or {"capture_limited": 2, "tunnel_records": 1, "opaque_tunnels": 0}

    async def fetchrow(self, query, *params):
        if "http_archive_stats" in query:
            return {"attempted": 4, "stored": 4, "failed": 0, "dropped": 0}
        assert "tunnel_records" in query
        return self.detail

    async def fetch(self, query, *params):
        if "scan_capability_actions" in query:
            assert "http_measured" in query
            return self.actions
        if "split_part(url" in query:
            return self.origins
        assert "refused_destinations" in query
        return self.refused


def test_the_reader_states_destinations_and_refusals_from_one_read():
    conn = _StatsConn(
        actions=[],
        origins=[
            {"scheme": "http:", "authority": "10.10.10.100:5002", "calls": 3},
            {"scheme": "http:", "authority": "user:secret@10.10.10.100:5002", "calls": 1},
        ],
        refused=[{"destination": "evil.example.test:80", "attempts": 2}],
    )
    stats = asyncio.run(read_archive_stats(conn, scan_id="scan-1", hunt_run_id=None))
    assert stats["destinations"] == [{"origin": "http://10.10.10.100:5002", "calls": 4}]
    assert stats["destinations_truncated"] is False
    assert stats["refused_destinations"] == [{"destination": "evil.example.test:80", "attempts": 2}]
    assert "secret" not in json.dumps(stats)
    assert stats["unarchived_http_capabilities"] == []


def test_an_encrypted_tunnel_keeps_the_archive_partial_and_says_why():
    stats = {"attempted": 1, "stored": 1, "failed": 0, "dropped": 0, "capture_limited": 0,
             "opaque_tunnels": 1, "unarchived_http_capabilities": []}
    fidelity, detail = archive_fidelity(stats, total=1)
    assert fidelity == "partial"
    assert "1 pinned tunnels carried encrypted traffic" in detail


def test_a_verifier_stopped_before_it_sent_anything_is_not_an_archive_gap():
    """Lab Scan (vampi, 2026-10-14): five verifiers the Scan's time limit settled timed_out with
    zero consumed were named as engine capabilities whose calls went unrecorded."""
    stopped = {"capability_name": "nosqli.verify_batch", "status": "timed_out",
               "http_consumed": 0, "http_measured": True}
    assert scan_action_sent_traffic(stopped) is False
    # One that consumed requests sent them, whatever it ended (soak sqli.verify_batch).
    assert scan_action_sent_traffic({**stopped, "http_consumed": 340}) is True
    # A success is never presumed silent; nor is a row without a measured consumption.
    assert scan_action_sent_traffic({**stopped, "status": "success"}) is True
    assert scan_action_sent_traffic({**stopped, "http_measured": False}) is True


def test_the_url_destination_of_a_tunnel_row_parses_as_the_target_origin():
    capture.start_capture()
    capture.record_tunnel(_fixture_tunnel(scheme="https", port=8443), capability_name="web.probe",
                          tool="httpx")
    url = capture.drain_capture()["calls"][0]["url"]
    assert urllib.parse.urlsplit(url).netloc == "app.example.test:8443"
