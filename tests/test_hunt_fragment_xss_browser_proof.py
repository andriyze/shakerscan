"""Hunt XSS browser proof selection and deterministic finding materialization.

The Hunt's xss.verify runs Dalfox, which drops the URL fragment and cannot test a
client-route parameter. The browser prover also handles an explicit deep check of
one server query parameter. The dispatcher accepts its registered runtime identity,
and the materializer turns execution proof into a verified finding.
"""
from __future__ import annotations

import asyncio
import json
import uuid

import pytest

import api.worker as worker
from api.hunt.fragment_xss_proof import hunt_browser_xss_proof_adapter
from api.capabilities.browser import XSSBrowserProofAdapter
from api.hunt.action_dispatcher import (
    HUNT_ACTION_DISPATCHER,
    HuntActionRequest,
    HuntDispatchError,
    RegisteredHuntAdapterFactory,
)
from api.hunt.deterministic_findings import materialize_verified_hunt_findings
from api.runtime.capability_registry import CAPABILITY_REGISTRY
from api.hunt.capability_executor import CapabilityAdapterResult
from api.runtime.models import TargetBinding

TARGET = TargetBinding(
    target_id="10000000-0000-0000-0000-000000000002",
    target_kind="web",
    canonical_host="host.docker.internal",
    allowed_origins=("http://host.docker.internal:3001",),
    allowed_addresses=("127.0.0.1",),
    scope_receipt_id="10000000-0000-0000-0000-000000000003",
)


def test_registry_declares_the_browser_prover_as_an_xss_verify_runtime():
    spec = CAPABILITY_REGISTRY.require("xss.verify")
    assert ("playwright", "1") in spec.adapter_identities()
    assert ("dalfox", "1") in spec.adapter_identities()
    # Two browser actions: navigate the pinned browser and read the DOM proof.
    assert spec.budget_cost["browser_actions"] == 2


def test_worker_routes_a_single_fragment_parameter_to_the_browser_prover():
    spec = CAPABILITY_REGISTRY.require("xss.verify")
    adapter = hunt_browser_xss_proof_adapter(
        capability_name="xss.verify", spec=spec, target=TARGET,
        execution_target="http://host.docker.internal:3001/#/search?q=shakerscan",
        action_id="a1",
    )
    assert adapter is not None and adapter.adapter_name == "playwright"
    assert adapter.adapter_name == "playwright"
    assert adapter.prepared.injection_location == "fragment"
    assert adapter.prepared.parameter_name == "q"


def test_worker_keeps_a_server_visible_parameter_on_the_scanner():
    spec = CAPABILITY_REGISTRY.require("xss.verify")
    # Without an explicit deep request, a server query parameter stays on Dalfox.
    assert hunt_browser_xss_proof_adapter(
        capability_name="xss.verify", spec=spec, target=TARGET,
        execution_target="http://host.docker.internal:3001/search?q=x", action_id="a1",
    ) is None
    # A path with no fragment parameter is not a DOM-XSS proof.
    assert hunt_browser_xss_proof_adapter(
        capability_name="xss.verify", spec=spec, target=TARGET,
        execution_target="http://host.docker.internal:3001/#/dashboard", action_id="a1",
    ) is None


def test_explicit_deep_query_uses_pinned_browser_for_one_parameter():
    spec = CAPABILITY_REGISTRY.require("xss.verify")
    adapter = hunt_browser_xss_proof_adapter(
        capability_name="xss.verify", spec=spec, target=TARGET,
        execution_target="http://host.docker.internal:3001/search?q=x",
        action_id="query-a1", deep_domxss=True,
    )
    assert adapter is not None
    assert adapter.prepared.injection_location == "query"
    assert adapter.prepared.parameter_name == "q"
    assert adapter.prepared.estimated_budget["http_requests"] == 50
    assert hunt_browser_xss_proof_adapter(
        capability_name="xss.verify", spec=spec, target=TARGET,
        execution_target="http://host.docker.internal:3001/search?q=x&next=y",
        action_id="query-a2", deep_domxss=True,
    ) is None
    # Only xss.verify routes to the browser.
    assert hunt_browser_xss_proof_adapter(
        capability_name="sqli.request_verify", spec=spec, target=TARGET,
        execution_target="http://host.docker.internal:3001/#/search?q=1", action_id="a1",
    ) is None


def _adapter(spec):
    class _A:
        capability_name = spec.name
        adapter_name = "playwright"
        adapter_version = "1"

        async def execute(self, *, heartbeat, cancelled):
            await heartbeat()
            return CapabilityAdapterResult(
                status="success",
                observations=({"kind": "xss_browser_proof", "proof_state": "verified"},),
                actual_budget={"browser_actions": 2, "http_requests": 3,
                               "tool_wall_seconds": 2, "agent_actions": 1},
                execution_started=True,
                parser_version="xss-browser-proof/v1",
            )
    return _A()


def test_dispatcher_accepts_the_declared_browser_runtime_for_xss_verify():
    spec = CAPABILITY_REGISTRY.require("xss.verify")
    request = HuntActionRequest(
        hunt_id="hunt-1", action_id="action-1", capability_name="xss.verify",
        target=TARGET, capability_input={"path": "/#/search?q=x"},
        requested_budget={"browser_actions": 2, "http_requests": 400,
                          "tool_wall_seconds": 120, "agent_actions": 1, "active_actions": 1},
    )
    factory = RegisteredHuntAdapterFactory({spec.adapter: lambda _s, _r: _adapter(spec)})
    result = asyncio.run(HUNT_ACTION_DISPATCHER.execute(
        request, factory, heartbeat=lambda: asyncio.sleep(0), cancelled=lambda: False,
    ))
    assert result.status == "success"

    class _Wrong(type(_adapter(spec))):
        adapter_name = "unregistered.runtime"
    bad = RegisteredHuntAdapterFactory({spec.adapter: lambda _s, _r: _Wrong()})
    with pytest.raises(HuntDispatchError, match="outside registry authority"):
        asyncio.run(HUNT_ACTION_DISPATCHER.execute(
            request, bad, heartbeat=lambda: asyncio.sleep(0), cancelled=lambda: False,
        ))


def test_browser_execution_proof_materializes_a_verified_finding():
    class DB:
        async def fetchval(self, query, *args):
            self.query, self.evidence = query, json.loads(args[4])
            self.description, self.tool = args[5], args[6]
            return uuid.uuid4()

        async def execute(self, *args):
            pass

    db = DB()
    ids = asyncio.run(materialize_verified_hunt_findings(
        db, uuid.uuid4(), uuid.uuid4(), uuid.uuid4(),
        "http://host.docker.internal:3001",
        "xss.verify", uuid.uuid4(), {"path": "/#/search?q=shakerscan"},
        [{
            "kind": "xss_browser_proof", "proof_state": "verified",
            "parameter_name": "q",
            "request_url": "http://host.docker.internal:3001/#/search?q=",
            "payload_sha256": "a" * 64,
            "dom_marker_executed": True, "technique": "headless_xss_dom",
        }],
    ))
    assert len(ids) == 1
    assert db.tool == "playwright"
    assert db.evidence["proof_contract"] == "xss_browser_proof/v1"
    assert db.evidence["proof_state"] == "verified"
    assert db.evidence["execution_sink"]["signal"] == "dom_execution"
    assert db.evidence["execution_sink"]["dom_marker_executed"] is True
    # A Dalfox alert proof still materializes under its own contract.
    db2 = DB()
    ids2 = asyncio.run(materialize_verified_hunt_findings(
        db2, uuid.uuid4(), uuid.uuid4(), uuid.uuid4(),
        "http://host.docker.internal:3001",
        "xss.verify", uuid.uuid4(), {"path": "/search"},
        [{
            "kind": "xss_alert", "proof_state": "verified", "param": "q",
            "url": "http://host.docker.internal:3001/search?q=payload",
            "payload_sha256": "b" * 64,
        }],
    ))
    assert len(ids2) == 1
    assert db2.tool == "dalfox"
    assert db2.evidence["proof_contract"] == "dalfox_browser_or_alert_execution/v1"


def test_browser_proof_on_authorized_alternate_port_persists_separately():
    class DB:
        async def fetchval(self, _query, *args):
            self.fingerprint, self.url = args[2], args[3]
            self.evidence = json.loads(args[4])
            return uuid.uuid4()

        async def execute(self, *_args):
            pass

    def proof(port):
        return [{
            "kind": "xss_browser_proof", "proof_state": "verified",
            "parameter_name": "q",
            "request_url": f"http://host.docker.internal:{port}/search?q=",
            "payload_sha256": "a" * 64,
            "dom_marker_executed": True,
        }]

    async def persist(db, observations):
        return await materialize_verified_hunt_findings(
            db, uuid.uuid4(), uuid.uuid4(), uuid.uuid4(),
            "http://host.docker.internal:3001", "xss.verify", uuid.uuid4(),
            {"path": "/search?q=test", "origin": "http://host.docker.internal:3002"},
            observations, allowed_origins=("http://host.docker.internal:3002",),
        )

    primary = DB()
    alternate = DB()
    assert len(asyncio.run(persist(primary, proof(3001)))) == 1
    assert len(asyncio.run(persist(alternate, proof(3002)))) == 1
    assert alternate.url == "http://host.docker.internal:3002/search?q="
    assert alternate.evidence["proof_state"] == "verified"
    assert alternate.fingerprint != primary.fingerprint
    assert asyncio.run(persist(DB(), proof(3003))) == []
