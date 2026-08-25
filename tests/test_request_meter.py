import asyncio
from contextlib import contextmanager
import http.server
import os
import sys
import threading
import urllib.request

import httpx
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools import common
from scanner_tools.request_meter import (
    RequestBudgetExceeded,
    RequestDestinationRejected,
    RequestMethodRejected,
    configure_request_meter,
    get_request_meter,
    install_async_client_metering,
)


def teardown_function():
    configure_request_meter(limit=None, target_host=None, mode="off")


@contextmanager
def _redirect_server():
    hits = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            hits.append(self.path)
            if self.path == "/start":
                self.send_response(302)
                self.send_header("Location", "/final")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            return None

    try:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    except PermissionError:
        pytest.skip("test sandbox does not permit a loopback listener")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", hits
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_request_meter_tracks_attempt_completion_retry_and_rejection():
    meter = configure_request_meter(
        limit=2,
        target_host="app.test",
        mode="enforce",
        planned=5,
        reserved=2,
    )

    assert meter.before_request(phase="probe", url="https://app.test/a") is True
    meter.record_completion(phase="probe", url="https://app.test/a", status_code=200)
    assert meter.before_request(phase="probe", url="https://app.test/b", retry=True) is True
    meter.record_completion(phase="probe", url="https://app.test/b", status_code=500)
    with pytest.raises(RequestBudgetExceeded):
        meter.before_request(phase="probe", url="https://app.test/c")

    snapshot = meter.snapshot()
    assert snapshot["planned_requests"] == 5
    assert snapshot["reserved_requests"] == 2
    assert snapshot["attempted_requests"] == 2
    assert snapshot["completed_requests"] == 2
    assert snapshot["retried_requests"] == 1
    assert snapshot["rejected_requests"] == 1
    assert snapshot["successful_requests"] == 1
    assert snapshot["adapter_usage"] == {
        "probe": {
            "attempted": 2,
            "completed": 2,
            "retried": 1,
            "rejected": 1,
            "successful": 1,
        }
    }


def test_request_meter_events_redact_opaque_secret_path_segments():
    secret = "AbCdEf0123456789AbCdEf0123456789"
    meter = configure_request_meter(
        limit=1,
        target_host="app.test",
        mode="enforce",
        planned=1,
        reserved=1,
    )

    assert meter.before_request(
        phase="probe", url=f"https://app.test/reset/{secret}",
    ) is True

    serialized = str(meter.snapshot()["events"])
    assert secret not in serialized
    assert "/reset/<redacted>" in serialized


def test_request_meter_enforces_and_reports_state_changing_reservation():
    meter = configure_request_meter(
        limit=5,
        target_host="app.test",
        mode="enforce",
        planned=5,
        reserved=5,
        state_changing_limit=1,
    )

    assert meter.before_request(
        phase="active", url="https://app.test/items", method="POST",
    ) is True
    with pytest.raises(RequestBudgetExceeded, match="state-changing"):
        meter.before_request(
            phase="active", url="https://app.test/items/1", method="DELETE",
        )
    assert meter.before_request(
        phase="probe", url="https://app.test/items", method="GET",
    ) is True

    snapshot = meter.snapshot()
    assert snapshot["attempted_requests"] == 2
    assert snapshot["state_changing_request_limit"] == 1
    assert snapshot["state_changing_attempted_requests"] == 1
    assert snapshot["state_changing_rejected_requests"] == 1


def test_request_meter_ignores_other_hosts():
    meter = configure_request_meter(
        limit=1, target_host="app.test", mode="enforce", planned=1, reserved=1
    )

    assert meter.before_request(phase="provider", url="https://provider.test/v1") is False
    assert meter.snapshot()["attempted_requests"] == 0


def test_passive_method_policy_cannot_be_disabled_with_budget_mode_off():
    meter = configure_request_meter(
        limit=None,
        target_host="app.test",
        mode="off",
        allowed_methods={"GET", "HEAD", "OPTIONS"},
    )

    assert meter.before_request(
        phase="probe", url="https://app.test/read", method="GET",
    ) is False
    with pytest.raises(RequestMethodRejected):
        meter.before_request(
            phase="probe", url="https://app.test/mutate", method="POST",
        )

    snapshot = meter.snapshot()
    assert snapshot["attempted_requests"] == 0
    assert snapshot["rejected_requests"] == 1
    assert snapshot["method_rejected_requests"] == 1
    assert snapshot["allowed_http_methods"] == ["GET", "HEAD", "OPTIONS"]


def test_passive_method_policy_does_not_apply_to_provider_host():
    meter = configure_request_meter(
        limit=None,
        target_host="app.test",
        mode="off",
        allowed_methods={"GET", "HEAD", "OPTIONS"},
    )
    assert meter.before_request(
        phase="provider", url="https://provider.test/token", method="POST",
    ) is False


def test_frozen_target_binding_rejects_origin_and_dns_drift_before_request():
    resolved = {"app.test": {"192.0.2.10"}}
    meter = configure_request_meter(
        limit=10,
        target_host="app.test",
        mode="enforce",
        allowed_origins={"https://app.test"},
        allowed_addresses={"192.0.2.10"},
        require_destination_scope=True,
        destination_resolver=lambda host: resolved.get(host, set()),
        destination_cache_seconds=0,
    )

    assert meter.before_request(
        phase="probe", url="https://app.test/read", method="GET",
    ) is True
    with pytest.raises(RequestDestinationRejected, match="origin_not_bound"):
        meter.before_request(
            phase="probe", url="http://app.test/read", method="GET",
        )
    resolved["app.test"] = {"192.0.2.99"}
    with pytest.raises(RequestDestinationRejected, match="runtime_dns_out_of_scope"):
        meter.before_request(
            phase="probe", url="https://app.test/again", method="GET",
        )

    snapshot = meter.snapshot()
    assert snapshot["attempted_requests"] == 1
    assert snapshot["destination_rejected_requests"] == 2


def test_request_meter_isolated_between_concurrent_scan_contexts():
    async def scan(host):
        meter = configure_request_meter(
            limit=2, target_host=host, mode="enforce", planned=2, reserved=2,
        )
        await asyncio.sleep(0)
        assert get_request_meter() is meter
        meter.before_request(phase="probe", url=f"https://{host}/one")
        return meter.snapshot()

    async def run_scans():
        return await asyncio.gather(scan("one.test"), scan("two.test"))

    first, second = asyncio.run(run_scans())

    assert first["target_host"] == "one.test"
    assert second["target_host"] == "two.test"
    assert first["attempted_requests"] == second["attempted_requests"] == 1


def test_httpx_hook_enforces_target_budget():
    meter = configure_request_meter(
        limit=1, target_host="app.test", mode="enforce", planned=1, reserved=1
    )
    install_async_client_metering()

    async def run_requests():
        transport = httpx.MockTransport(lambda request: httpx.Response(200, request=request))
        async with httpx.AsyncClient(transport=transport) as client:
            response = await client.get("https://app.test/one")
            assert response.status_code == 200
            with pytest.raises(RequestBudgetExceeded):
                await client.get("https://app.test/two")

    asyncio.run(run_requests())
    assert meter.snapshot()["attempted_requests"] == 1
    assert meter.snapshot()["completed_requests"] == 1
    assert meter.snapshot()["rejected_requests"] == 1


def test_httpx_hook_rejects_passive_post_before_transport():
    meter = configure_request_meter(
        limit=10,
        target_host="app.test",
        mode="compatibility",
        allowed_methods={"GET", "HEAD", "OPTIONS"},
    )
    install_async_client_metering()
    calls = 0

    def transport(request):
        nonlocal calls
        calls += 1
        return httpx.Response(200, request=request)

    async def run_request():
        async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as client:
            with pytest.raises(RequestMethodRejected):
                await client.post("https://app.test/mutate")

    asyncio.run(run_request())
    assert calls == 0
    assert meter.snapshot()["method_rejected_requests"] == 1


def test_all_python_target_clients_share_real_wire_budget_and_redirect_guard():
    import aiohttp
    import requests

    install_async_client_metering()
    with _redirect_server() as (origin, hits):
        for client_name in ("httpx", "aiohttp", "requests", "urllib"):
            hits.clear()
            meter = configure_request_meter(
                limit=1,
                target_host="127.0.0.1",
                mode="enforce",
                planned=1,
                reserved=1,
                allowed_methods={"GET"},
                allowed_origins={origin},
                allowed_addresses={"127.0.0.1"},
                require_destination_scope=True,
            )
            url = origin + "/start"
            if client_name == "httpx":
                async def httpx_request():
                    async with httpx.AsyncClient(trust_env=False) as client:
                        response = await client.get(url, follow_redirects=True)
                        assert response.status_code == 302

                asyncio.run(httpx_request())
            elif client_name == "aiohttp":
                async def aiohttp_request():
                    async with aiohttp.ClientSession(trust_env=False) as client:
                        async with client.get(url, allow_redirects=True) as response:
                            assert response.status == 302

                asyncio.run(aiohttp_request())
            elif client_name == "requests":
                response = requests.get(url, allow_redirects=True, timeout=2)
                assert response.status_code == 302
            else:
                with pytest.raises(RequestBudgetExceeded):
                    urllib.request.urlopen(url, timeout=2)

            snapshot = meter.snapshot()
            assert hits == ["/start"], client_name
            assert snapshot["attempted_requests"] == 1
            assert snapshot["attempted_requests"] <= snapshot["reserved_requests"]
            assert snapshot["limit_exceeded"] is False


def test_ambient_proxy_is_rejected_or_bypassed_before_target_wire(monkeypatch):
    import aiohttp
    import requests

    install_async_client_metering()
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    monkeypatch.setenv("NO_PROXY", "")
    monkeypatch.setenv("no_proxy", "")
    with _redirect_server() as (origin, hits):
        url = origin + "/final"

        for client_name in ("httpx", "aiohttp"):
            meter = configure_request_meter(
                limit=1, target_host="127.0.0.1", mode="enforce",
                planned=1, reserved=1,
                allowed_origins={origin}, allowed_addresses={"127.0.0.1"},
                require_destination_scope=True,
            )
            if client_name == "httpx":
                async def httpx_request():
                    async with httpx.AsyncClient(trust_env=True) as client:
                        await client.get(url)

                operation = httpx_request()
            else:
                async def aiohttp_request():
                    async with aiohttp.ClientSession(trust_env=True) as client:
                        await client.get(url)

                operation = aiohttp_request()
            with pytest.raises(
                RequestDestinationRejected, match="environment_proxy_forbidden",
            ):
                asyncio.run(operation)
            assert meter.snapshot()["attempted_requests"] == 0

        for client_name in ("requests", "urllib"):
            hits.clear()
            meter = configure_request_meter(
                limit=1, target_host="127.0.0.1", mode="enforce",
                planned=1, reserved=1,
                allowed_origins={origin}, allowed_addresses={"127.0.0.1"},
                require_destination_scope=True,
            )
            if client_name == "requests":
                response = requests.get(url, timeout=2)
                assert response.status_code == 200
            else:
                with urllib.request.urlopen(url, timeout=2) as response:
                    assert response.status == 200
            assert hits == ["/final"], client_name
            assert meter.snapshot()["attempted_requests"] == 1


def test_curl_method_inference_covers_implicit_and_explicit_mutations():
    assert common._curl_http_method(["curl", "https://app.test"]) == "GET"
    assert common._curl_http_method(["curl", "-I", "https://app.test"]) == "HEAD"
    assert common._curl_http_method(["curl", "-d", "a=1", "https://app.test"]) == "POST"
    assert common._curl_http_method(["curl", "--upload-file", "body", "https://app.test"]) == "PUT"
    assert common._curl_http_method(["curl", "-X", "DELETE", "https://app.test"]) == "DELETE"


def test_unmetered_network_tool_fails_closed_only_in_enforce_mode():
    meter = configure_request_meter(
        limit=10, target_host="app.test", mode="enforce", planned=10, reserved=10
    )
    out, error, rc = asyncio.run(common.run([
        "nuclei", "-u", "https://app.test",
    ]))

    assert out == ""
    assert rc == 75
    assert "unmetered network tool" in error
    assert meter.snapshot()["rejected_requests"] == 1


@pytest.mark.parametrize("tool", ["tlsx", "nmap", "testssl.sh", "openssl"])
def test_unreserved_tls_and_tcp_tools_fail_closed_in_enforce_mode(tool):
    meter = configure_request_meter(
        limit=10, target_host="app.test", mode="enforce", planned=10, reserved=10
    )
    out, error, rc = asyncio.run(common.run([
        tool, "app.test:443",
    ]))

    assert out == ""
    assert rc == 75
    assert "unmetered network tool" in error
    assert meter.snapshot()["unmetered_tool_invocations"] == 1


def test_local_network_tool_version_probe_does_not_consume_or_reject_budget(monkeypatch):
    meter = configure_request_meter(
        limit=10, target_host="app.test", mode="enforce", planned=10, reserved=10
    )

    class FakeProcess:
        returncode = 0

        async def communicate(self, input=None):
            return b"nuclei v3", b""

    async def fake_exec(*cmd, **kwargs):
        assert cmd == ("nuclei", "-version")
        return FakeProcess()

    monkeypatch.setattr(common.asyncio, "create_subprocess_exec", fake_exec)
    out, error, rc = asyncio.run(common.run(["nuclei", "-version"]))

    assert (out, error, rc) == ("nuclei v3", "", 0)
    assert meter.snapshot()["rejected_requests"] == 0
    assert meter.snapshot()["unmetered_tool_invocations"] == 0


def test_enforcing_curl_disables_hidden_redirect_requests(monkeypatch):
    captured = {}
    configure_request_meter(
        limit=1, target_host="app.test", mode="enforce", planned=1, reserved=1
    )

    class FakeProcess:
        returncode = 0

        async def communicate(self, input=None):
            return b"ok", b""

    async def fake_exec(*cmd, **kwargs):
        captured["cmd"] = list(cmd)
        return FakeProcess()

    monkeypatch.setattr(common.asyncio, "create_subprocess_exec", fake_exec)
    out, error, rc = asyncio.run(common.run([
        "curl", "-sS", "-L", "--max-redirs", "5", "https://app.test/start",
    ]))

    assert (out, error, rc) == ("ok", "", 0)
    assert "-L" not in captured["cmd"]
    assert "--max-redirs" not in captured["cmd"]
