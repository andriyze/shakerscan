"""Device browser services retain exact-host scope through real Chromium execution."""
import asyncio
import ast
from pathlib import Path
import sys
import uuid

import pytest

sys.path[:0] = [str(Path(__file__).resolve().parents[1] / "api")]
from capabilities.browser import browser_capability_adapter
from capabilities.browser_login_worker import prepare_hunt_browser_action, browser_worker_policy
from hunt.target_binding import web_hunt_target
from runtime.capability_registry import CAPABILITY_REGISTRY
from runtime.models import ScanPolicy
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


async def worker_prepare(name, args, policy=None):
    """Execute the worker's unchanged binding/preparation/conversion statements.

    Only database authority revalidation is replaced; policy construction and
    origin validation use the production call sites and production objects.
    """
    path = Path(__file__).resolve().parents[1] / "api" / "worker.py"
    tree = ast.parse(path.read_text())
    handler = next(n for n in tree.body if isinstance(n, ast.AsyncFunctionDef)
                   and n.name == "process_canonical_browser_capability_job")
    transaction = next(n for n in ast.walk(handler) if isinstance(n, ast.AsyncWith)
                       and any(isinstance(s, ast.Assign) and any(
                           isinstance(t, ast.Name) and t.id == "context" for t in s.targets)
                           for s in n.body))
    def assigns(statement, name):
        return isinstance(statement, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == name for t in statement.targets)
    start = next(i for i, s in enumerate(transaction.body) if assigns(s, "context"))
    end = next(i for i, s in enumerate(transaction.body) if assigns(s, "expected_input_digest"))
    function = ast.parse("async def execute():\n    pass\n").body[0]
    function.body = transaction.body[start:end] + [ast.Return(value=ast.Tuple(
        elts=[ast.Name(id="prepared", ctx=ast.Load()), ast.Name(id="policy", ctx=ast.Load())], ctx=ast.Load()))]

    async def revalidate(conn, **values):
        assert isinstance(values["policy"], ScanPolicy)

    persisted_policy = dict(POLICY if policy is None else policy)
    persisted_policy["allowed_capabilities"] = [name]
    namespace = {
        "run": {"target_kind": "device", "target_id": None, "device_target_id": uuid.UUID(int=2),
                "context_pack": {"target": {"locator": "127.0.0.1"}, "authorized_target_addresses": ["127.0.0.1"]},
                "policy_json": persisted_policy},
        "capability_name": name, "capability_input": args, "conn": None,
        "_worker_json_object": dict, "_worker_hunt_web_target": web_hunt_target,
        "_revalidate_hunt_action_authority": revalidate,
        "browser_worker_policy": browser_worker_policy,
        "browser_capability_adapter": browser_capability_adapter,
        "prepare_hunt_browser_action": prepare_hunt_browser_action,
    }
    exec(compile(ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[])), str(path), "exec"), namespace)
    return await namespace["execute"]()


@pytest.mark.parametrize("name", ["browser.navigate", "browser.interact"])
def test_device_browser_origin_is_in_contract_and_survives_worker_repreparation(name):
    assert "origin" in CAPABILITY_REGISTRY.require(name).input_schema["properties"]
    args = {"origin": "https://127.0.0.1:8443", "path": "/ui"}
    if name == "browser.interact":
        args["selector"] = "#details"
    admitted = prepare(name, args)
    worker, execution_policy = asyncio.run(worker_prepare(name, args))
    assert isinstance(execution_policy, ScanPolicy)
    assert execution_policy.network_discovery is True
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


def test_browser_service_override_requires_active_testing_authority():
    # Reaching another port on the SAME already-authorized host needs active
    # testing (which the target's standing authorization grants). The host is
    # still pinned, so this never admits a different host.
    without_active = {**POLICY, "active_testing": None}
    with pytest.raises(ValueError, match="active-testing authority"):
        prepare("browser.navigate", {"origin": "http://127.0.0.1:8080"}, without_active)
    with pytest.raises(ValueError, match="active-testing authority"):
        asyncio.run(worker_prepare("browser.navigate", {"origin": "http://127.0.0.1:8080"}, without_active))


@pytest.mark.parametrize("field", ["network_discovery", "approval_receipt_id", "scope_receipt_id"])
def test_browser_service_override_no_longer_requires_network_discovery(field):
    # An authorized active Hunt reaches a service on another port of its exact
    # host without separately being granted network discovery, an approval
    # receipt, or a matching scope receipt.
    admitted = prepare("browser.navigate", {"origin": "http://127.0.0.1:8080"}, {**POLICY, field: None})
    assert admitted.url == "http://127.0.0.1:8080/"
    worker, _ = asyncio.run(worker_prepare("browser.navigate", {"origin": "http://127.0.0.1:8080"}, {**POLICY, field: None}))
    assert worker.url == "http://127.0.0.1:8080/"


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
                prepared, execution_policy = await worker_prepare(name, args)
                assert execution_policy.network_discovery is True
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
