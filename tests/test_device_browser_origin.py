"""Device browser services retain exact-host scope through real Chromium execution."""
import asyncio
from pathlib import Path
import sys
import uuid

import pytest

sys.path[:0] = [str(Path(__file__).resolve().parents[1] / "api")]
from capabilities.browser import browser_capability_adapter
from capabilities.browser_login_worker import prepare_hunt_browser_action
from hunt.target_binding import web_hunt_target
from runtime.capability_registry import CAPABILITY_REGISTRY
from tests.test_hunt_device_traffic import DeviceStore, admit


POLICY = {"active_testing": True, "network_discovery": True,
          "approval_receipt_id": "approval", "scope_receipt_id": "scope"}


@pytest.mark.parametrize("name", ["browser.navigate", "browser.interact"])
def test_real_device_admission_accepts_service_origin(name):
    store = DeviceStore()
    args = {"origin": "http://192.0.2.10:8080", "max_requests": 2}
    if name == "browser.interact":
        args["selector"] = "#details"
    asyncio.run(admit(store, name, args))
    assert store.actions


def prepare(name, args, policy=None):
    target, base = web_hunt_target(
        {"target_kind": "device", "target_id": None, "device_target_id": uuid.UUID(int=2)},
        {"target": {"locator": "127.0.0.1"}, "authorized_target_addresses": ["127.0.0.1"]},
        POLICY,
    )
    return prepare_hunt_browser_action(
        name, target=target, base_url=base, args=args, context={},
        policy=POLICY if policy is None else policy,
    )


@pytest.mark.parametrize("name", ["browser.navigate", "browser.interact"])
def test_device_browser_origin_is_in_contract_and_survives_worker_repreparation(name):
    assert "origin" in CAPABILITY_REGISTRY.require(name).input_schema["properties"]
    args = {"origin": "https://127.0.0.1:8443", "path": "/ui"}
    if name == "browser.interact":
        args["selector"] = "#details"
    admitted, worker = prepare(name, args), prepare(name, args)
    assert admitted.input_digest == worker.input_digest
    assert worker.url == "https://127.0.0.1:8443/ui"
    assert worker.target.allowed_addresses == ("127.0.0.1",)
    assert prepare(name, {k: v for k, v in args.items() if k != "origin"}).origin == "http://127.0.0.1"


@pytest.mark.parametrize("name", ["browser.navigate", "browser.interact"])
@pytest.mark.parametrize("origin", [
    "http://127.0.0.2:8080", "http://localhost:8080", "http://user:pass@127.0.0.1:8080",
    "http://127.0.0.1:8080/path", "http://127.0.0.1:8080?x=1", "http://127.0.0.1:0",
    "file:///tmp/fixture", "http://127.0.0.1:99999",
])
def test_device_browser_rejects_invalid_or_unbound_origin(name, origin):
    with pytest.raises(ValueError):
        prepare(name, {"origin": origin, "selector": "#details"} if name.endswith("interact") else {"origin": origin})


@pytest.mark.parametrize("field", ["active_testing", "network_discovery", "approval_receipt_id", "scope_receipt_id"])
def test_browser_service_override_requires_existing_network_authority(field):
    with pytest.raises(ValueError, match="network discovery authority"):
        prepare("browser.navigate", {"origin": "http://127.0.0.1:8080"}, {**POLICY, field: None})


def test_real_browser_navigation_and_interaction_reach_device_service_port():
    pytest.importorskip("playwright.async_api")

    async def exercise():
        requests = []

        async def serve(reader, writer):
            try:
                request = await reader.readuntil(b"\r\n\r\n")
                requests.append(request.split(b"\r\n", 1)[0])
                body = b'<html><body><a id="details" href="/details">Details</a></body></html>'
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: "
                             + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        async def heartbeat():
            pass

        server = await asyncio.start_server(serve, "127.0.0.1", 0)
        async with server:
            port = server.sockets[0].getsockname()[1]
            assert port != 80
            origin = f"http://127.0.0.1:{port}"
            for name in ("browser.navigate", "browser.interact"):
                args = {"origin": origin, "path": "/", "max_requests": 10}
                if name == "browser.interact":
                    args.update(selector="#details", settle_ms=0)
                prepared = prepare(name, args)
                result = await browser_capability_adapter(name)(prepared).execute(
                    heartbeat=heartbeat, cancelled=lambda: False,
                )
                assert result.status == "success", result.errors
                navigation = next(o for o in result.observations if o["kind"] == "browser_navigation")
                assert navigation["url"] == origin + "/"
                assert navigation["status_code"] == 200
                if name == "browser.interact":
                    interaction = next(o for o in result.observations if o["kind"] == "browser_interaction")
                    assert interaction["url"] == origin + "/details"
            assert b"GET /details HTTP/1.1" in requests

    asyncio.run(exercise())
