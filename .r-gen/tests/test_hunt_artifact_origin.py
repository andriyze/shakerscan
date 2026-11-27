"""artifact.inspect and javascript.analyze read from the service the call names.

On a network target (``host://H``), ``http.request`` with ``origin`` read a service's
``/openapi.json``, but ``artifact.inspect`` on the same file was refused with "scope: HTTP origin
is outside the frozen target binding" and charged a request. The two artifact capabilities took
no ``origin``, so they always read from the Hunt's registered URL, and a network target's URL
names a host, not an HTTP service. They now take ``origin`` and check it exactly as
``http.request`` does: at admission (same host, active testing for another port, metered as
active) and again at dispatch.

The loopback tests run the real binding, input validation, dispatch check and capability against
a real HTTP server on 127.0.0.1; the admission tests run the real admission lifecycle with the
in-memory store of tests/test_hunt_authz_verification_limit.py.
"""
from __future__ import annotations

import asyncio
import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from capabilities.artifact import analyze_target_javascript, inspect_target_artifact
from capabilities.http import resolve_hunt_http_origin
from hunt.dispatch_authority import HuntDispatchRejected, dispatch_http_target
from hunt.service_binding import (
    ARTIFACT_READ_CAPABILITIES, artifact_origin_required, service_origin_changed,
)
from hunt.target_binding import web_hunt_target
from runtime.capability_registry import CAPABILITY_REGISTRY
from tests.test_hunt_authz_verification_limit import HUNT, AdmissionStore, Lifecycle, admission

OPENAPI = b'{"openapi": "3.0.0", "paths": {"/api/users": {}, "/api/admin/export": {}}}'
BUNDLE = b'fetch("/api/users"); const panel = document.getElementById("p"); panel.innerHTML = x;'


def _network_run(policy):
    """The persisted network Hunt: ``host://127.0.0.1``, no web Scan origins recorded."""
    run = {"target_kind": "network", "target_id": str(uuid.UUID(int=2)), "device_target_id": None}
    context = {
        "target": {"url": "host://127.0.0.1", "kind": "network", "origins": [], "environment": "lab"},
        "authorized_target_addresses": ["127.0.0.1"],
    }
    return run, context, policy


async def _serving(scenario):
    from aiohttp import web

    async def openapi(_request):
        return web.Response(body=OPENAPI, content_type="application/json")

    async def bundle(_request):
        return web.Response(body=BUNDLE, content_type="application/javascript")

    app = web.Application()
    app.router.add_get("/openapi.json", openapi)
    app.router.add_get("/static/app.js", bundle)
    runner = web.AppRunner(app, shutdown_timeout=1)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    try:
        return await scenario(f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}")
    finally:
        await runner.cleanup()


async def _read(name, base, values, policy):
    """The worker's path: validate the Hunt input, check its origin at dispatch, then read."""
    values = CAPABILITY_REGISTRY.validate_hunt_input(name, values)
    binding, target_url = web_hunt_target(*_network_run(policy))
    target = dispatch_http_target(binding, values.get("origin"), policy)
    operation = inspect_target_artifact if name == "artifact.inspect" else analyze_target_javascript
    return await operation(target_url, values, target=target)


ACTIVE = {"active_testing": True}


def test_an_artifact_read_on_a_network_target_reaches_the_named_service():
    async def scenario(base):
        return await _read("artifact.inspect", base, {
            "origin": base, "path": "/openapi.json", "search_terms": ["/api/admin/export"],
        }, ACTIVE)

    result = asyncio.run(_serving(scenario))
    assert result["ok"] is True, result
    assert result["observation"]["search_matches"] == [{"term": "/api/admin/export", "count": 1}]


def test_javascript_analysis_on_a_network_target_reaches_the_named_service():
    async def scenario(base):
        return await _read("javascript.analyze", base, {"origin": base, "path": "/static/app.js"}, ACTIVE)

    result = asyncio.run(_serving(scenario))
    assert result["ok"] is True, result
    assert result["observation"]["routes"] == ["/api/users"]
    assert result["observation"]["client_sink_signals"] == ["innerHTML"]


@pytest.mark.parametrize("name", sorted(ARTIFACT_READ_CAPABILITIES))
def test_without_an_origin_a_network_read_stays_outside_the_binding(name):
    async def scenario(base):
        return await _read(name, base, {"path": "/openapi.json"}, ACTIVE)

    result = asyncio.run(_serving(scenario))
    assert result["ok"] is False
    assert result["error"] == "scope: HTTP origin is outside the frozen target binding"


@pytest.mark.parametrize("name", sorted(ARTIFACT_READ_CAPABILITIES))
def test_another_host_or_a_port_without_active_testing_is_refused_at_dispatch(name):
    with pytest.raises(HuntDispatchRejected):
        asyncio.run(_read(name, "", {"origin": "http://127.0.0.2:8080", "path": "/x"}, ACTIVE))
    with pytest.raises(HuntDispatchRejected, match="active-testing"):
        asyncio.run(_read(name, "", {"origin": "http://127.0.0.1:8080", "path": "/x"}, {}))


# --- Admission: the origin is checked and metered as http.request's ------------------------------

def _store(*, kind="network", active_testing=True):
    store = AdmissionStore()
    store.run["target_kind"] = kind
    store.run["policy_json"].update(active_testing=active_testing)
    store.run["context_pack"] = (
        {"target": {"url": "host://198.51.100.10", "origins": []},
         "authorized_target_addresses": ["198.51.100.10"]}
        if kind == "network" else
        {"target": {"url": "https://fixture.example.test"},
         "authorized_target_addresses": ["192.0.2.20"]}
    )
    return store


async def _admit(store, name, values):
    from hunt import interaction_router as real_router

    values = CAPABILITY_REGISTRY.validate_hunt_input(name, values)
    fn = admission(store)
    fn.__globals__.update(
        web_hunt_target=web_hunt_target, resolve_hunt_http_origin=resolve_hunt_http_origin,
        service_origin_changed=service_origin_changed,
        ARTIFACT_READ_CAPABILITIES=ARTIFACT_READ_CAPABILITIES,
        artifact_origin_required=artifact_origin_required,
        scanner_destination_refusal=real_router.scanner_destination_refusal,
        _hunt_public=lambda *a, **kw: {"capabilities": [{"name": name}]},
    )
    lifecycle = Lifecycle(name)
    lifecycle.specification = CAPABILITY_REGISTRY.require(name)
    lifecycle.placement = lifecycle.specification.hunt_executor
    return await fn(str(HUNT), name, SimpleNamespace(input=values, idempotency_key="artifact-1"), lifecycle)


@pytest.mark.parametrize("name", sorted(ARTIFACT_READ_CAPABILITIES))
def test_a_read_from_another_service_is_admitted_as_an_active_act(name):
    store = _store()
    asyncio.run(_admit(store, name, {"origin": "http://198.51.100.10:5002", "path": "/openapi.json"}))
    assert len(store.actions) == 1
    assert store.run["budget_used_json"].get("active_actions") == 1


@pytest.mark.parametrize("name", sorted(ARTIFACT_READ_CAPABILITIES))
def test_a_read_from_another_service_needs_active_testing(name):
    store = _store(active_testing=False)
    with pytest.raises(HTTPException) as refused:
        asyncio.run(_admit(store, name, {"origin": "http://198.51.100.10:5002", "path": "/openapi.json"}))
    assert refused.value.detail["reason_code"] == "scope_other_service_port"
    assert not store.actions


@pytest.mark.parametrize("name", sorted(ARTIFACT_READ_CAPABILITIES))
def test_a_read_from_another_host_is_refused_at_admission(name):
    store = _store()
    with pytest.raises(HTTPException) as refused:
        asyncio.run(_admit(store, name, {"origin": "http://198.51.100.11:5002", "path": "/openapi.json"}))
    assert refused.value.detail["reason_code"] == "scope_other_host"
    assert not store.actions


@pytest.mark.parametrize("name", sorted(ARTIFACT_READ_CAPABILITIES))
def test_a_network_read_without_an_origin_is_refused_at_no_cost(name):
    store = _store()
    with pytest.raises(HTTPException) as refused:
        asyncio.run(_admit(store, name, {"path": "/openapi.json"}))
    assert refused.value.status_code == 422
    assert refused.value.detail["reason_code"] == "artifact_origin_required"
    message = refused.value.detail["message"]
    assert "needs origin" in message and "http.request" in message
    # Recorded as a refused attempt (settle_refusal), with nothing reserved or charged.
    assert refused.value.recorded and refused.value.kind is None
    assert not store.actions and store.run["budget_used_json"].get("active_actions", 0) == 0


@pytest.mark.parametrize("name", sorted(ARTIFACT_READ_CAPABILITIES))
def test_a_web_target_read_without_an_origin_stays_a_passive_read(name):
    store = _store(kind="web")
    asyncio.run(_admit(store, name, {"path": "/main.js"}))
    assert len(store.actions) == 1
    assert store.run["budget_used_json"].get("active_actions", 0) == 0


def test_retained_steps_keep_the_origin_of_an_artifact_read():
    from hunt.saved_actions import RETAINED_STEP_FIELDS

    for name in ARTIFACT_READ_CAPABILITIES:
        assert "origin" in RETAINED_STEP_FIELDS[name]
        assert "origin" in CAPABILITY_REGISTRY.require(name).input_schema["properties"]
