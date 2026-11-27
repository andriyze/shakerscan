"""A Scan with credential profiles crawls with its primary identity (PostgreSQL).

A Scan whose primary profile is static (a bearer token, a header, a cookie), alone or with a
secondary profile, lost both crawls before they started: each settled ``failed / adapter_failed``
with its whole reservation charged, so the XSS, SQLi and NoSQLi families found no candidates. The
session-carrying crawl read the primary sign-in's landing page from ``inputs.auth_primary``, but a
static profile gets no sign-in action of its own (``interactive_auth_input_action_ids``), and the
real control-plane backend refuses to read an action that is not in the plan.

Composed as the local worker composes it: the real ``PostgresScanExecutionBackend`` over the
installed schema, ``ReceiptScanActionExecutor``, ``ScanOrchestrator`` and the real crawl
dispatcher (``DatabaseNeutralScanActionDispatcher``). Fixtures: the sign-in action (its receipt
records an established session, and its session is bound into the worker options as the real
sign-in binds it) and the scanner process runner (it records the launch payload and returns one
parameterized route per crawl). The routes the crawls stored are then compiled into the
continuation's candidate manifest by the real ``build_discovery_continuation_manifests``. No
target is contacted.

Requires ``TARGET_ASSET_TEST_DATABASE_URL`` (a disposable local PostgreSQL).
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import sys
import uuid

import pytest

from tests.test_scan_local_revocation_postgres import (  # noqa: F401  (template_database is a fixture)
    scan_database,
    template_database,
)
from tests.test_target_asset_migration_postgres import _real_asyncpg
import agent_tools  # noqa: E402
import target_authorization  # noqa: E402
from runtime.capability_registry import CAPABILITY_REGISTRY  # noqa: E402
from runtime.models import ScanPolicy, TargetBinding  # noqa: E402
from runtime.receipts import CapabilityReceipt  # noqa: E402
from runtime.scan_credentials import bind_scan_session_headers  # noqa: E402
from scan.action_adapter import DatabaseNeutralScanActionDispatcher  # noqa: E402
from scan.action_plan import ScanAction, ScanActionPlan, interactive_auth_input_action_ids  # noqa: E402
from scan.action_store import PostgresScanActionStore  # noqa: E402
from scan.continuation import (  # noqa: E402
    ScanContinuationAllocation,
    build_discovery_continuation_manifests,
)
from scan.execution_backend import PostgresScanExecutionBackend  # noqa: E402
from scan.manifest_store import PostgresScanManifestStore  # noqa: E402
from scan.orchestrator import ScanOrchestrator  # noqa: E402
from scan.work_manifests import build_endpoint_manifest  # noqa: E402
from scan.worker_action_executor import ReceiptScanActionExecutor  # noqa: E402

HOST = "app.fixture.test"
ORIGIN = f"http://{HOST}:8000"
WORKER = "local:fixture"
PROXY = "socks5://127.0.0.1:41000"
# The capabilities a profile's safe defaults allow, the crawls among them.
ALLOWED = ["auth.session.establish", "http.request", "web.probe", "web.crawl", "web.browser_crawl"]
# What the worker holds for each lane once its identity is resolved (static) or signed in.
IDENTITY = {
    ("primary", "bearer_token"): {"Authorization": "Bearer primary-fixture-token"},
    ("secondary", "bearer_token"): {"Authorization": "Bearer secondary-fixture-token"},
    ("primary", "form_login"): {"Cookie": "hub_session=primary-fixture"},
    ("secondary", "form_login"): {"Cookie": "hub_session=secondary-fixture"},
}
CRAWLS = (("discover.web_crawl", "web.crawl", "katana"),
          ("discover.browser_crawl", "web.browser_crawl", "katana_headless"))
# What each crawl finds in the signed-in area: one route with a query parameter.
ROUTES = {"katana": ("/hub/search?q=fixture", "q"), "katana_headless": ("/hub/orders?id=7", "id")}

SCENARIOS = {
    # Two users, each with a bearer token (the Juice Shop benchmark's two-user Scan).
    "bearer+bearer": ("bearer_token", "bearer_token"),
    "bearer+form_login": ("bearer_token", "form_login"),
    "form_login+bearer": ("form_login", "bearer_token"),
    "form_login+form_login": ("form_login", "form_login"),
    "bearer_primary_only": ("bearer_token", None),
    "form_login_primary_only": ("form_login", None),
    # One profile in the secondary slot: the primary lane is anonymous.
    "bearer_secondary_only": (None, "bearer_token"),
}


@pytest.fixture(scope="module", autouse=True)
def _installed_driver():
    """The shared database fixtures import ``asyncpg`` by name, and a module collected before this
    one may have left a stub there (``sys.modules.setdefault("asyncpg", ...)``). The installed
    driver is in place while this module runs and the stub is put back after, so the result does
    not depend on which modules ran before."""
    with pytest.MonkeyPatch.context() as patch:
        patch.setitem(sys.modules, "asyncpg", _real_asyncpg())
        yield


def _refs(primary, secondary):
    return [{
        "profile_id": str(uuid.uuid4()), "profile_version": 1, "principal_slot": lane,
        "scan_lane": lane, "auth_kind": kind, "principal_label": f"{lane} fixture",
        "allowed_capabilities": list(ALLOWED), "source": "credential_profiles",
    } for lane, kind in (("primary", primary), ("secondary", secondary)) if kind]


def _options(refs):
    """Worker options as the static hydration and the sign-in binding leave them."""
    options = {"resolved_credential_profiles": refs}
    for ref in refs:
        headers = IDENTITY[(ref["scan_lane"], ref["auth_kind"])]
        options = bind_scan_session_headers(options, headers, lane=ref["scan_lane"])
    return options


def _action(action_id, ordinal, capability, args, *, stage, dependencies=(), budget):
    spec = CAPABILITY_REGISTRY.require(capability)
    return dict(
        action_id=action_id, stage=stage, ordinal=ordinal, capability_name=spec.name,
        capability_args=args, input_binding_digest=f"{ordinal + 1:064x}",
        requested_budget=budget,
        placement={
            "schema_version": "scan-action-placement/v1", "eligible_backends": ["local", "broker"],
            "requirements": dict(spec.placement_requirements),
            "adapter_name": spec.adapter, "adapter_version": spec.adapter_version,
        },
        dependencies=tuple(dependencies), required=False, supporting=True,
        output_schema=spec.output_schema,
    )


async def _scan(pool, refs):
    """A persisted Scan whose plan has the sign-in actions the compiler creates for ``refs``."""
    async with pool.acquire() as conn:
        target_id = await conn.fetchval("INSERT INTO targets(url) VALUES($1) RETURNING id", ORIGIN)
        await target_authorization.authorize_target(conn, target_id, approved_by="fixture-owner")
        scan_id = uuid.uuid4()
        await conn.execute(
            """INSERT INTO scans (id,target_id,target_url,status,scan_generation,budget_json,budget_used_json)
               VALUES ($1,$2,$3,'running','canonical',$4::jsonb,'{}'::jsonb)""",
            scan_id, target_id, ORIGIN, json.dumps({
                "max_duration_seconds": 3600, "max_http_requests": 20_000, "max_endpoints": 500,
                "max_browser_actions": 1_000, "max_tcp_ports": 0, "max_tool_wall_seconds": 5_000,
                "max_workers": 1, "max_state_changing_requests": 0, "max_hosts": 1}))
        target = TargetBinding(
            target_id=str(target_id), target_kind="web", canonical_host=HOST,
            allowed_origins=(ORIGIN,), allowed_addresses=("192.0.2.10",),
        )
        endpoints = build_endpoint_manifest(
            scan_id=str(scan_id), target_binding_digest=target.digest,
            surface_manifest={
                "schema_version": "endpoint-manifest/v2", "status": "complete", "reason": None,
                "endpoints": [{
                    "method": "GET", "scheme": "http", "host": HOST, "port": 8000,
                    "normalized_path": "/hub/", "concrete_path": "/hub/", "query_keys": [],
                    "source": "known_endpoints",
                }],
            },
            source_action_ids=("inputs.seed",), auth_lane="primary",
        )
        await PostgresScanManifestStore().persist(conn, manifest=endpoints)
        rows = []
        sign_ins = interactive_auth_input_action_ids(refs)
        for action_id in sign_ins:
            lane = action_id.rsplit("_", 1)[1]
            ref = next(item for item in refs if item["scan_lane"] == lane)
            rows.append(_action(
                action_id, len(rows), "auth.session.establish",
                {"lane": lane, "credential_profile_ref": ref},
                stage="resolve_inputs", budget={"http_requests": 4, "tool_wall_seconds": 30},
            ))
        for action_id, capability, _tool in CRAWLS:
            budget = {"http_requests": 500, "tool_wall_seconds": 150}
            if capability == "web.browser_crawl":
                budget = {"http_requests": 600, "tool_wall_seconds": 150, "browser_actions": 25}
            rows.append(_action(
                action_id, len(rows), capability,
                {"endpoint_manifest_ref": endpoints.reference().canonical_dict(), "read_only": True},
                stage="discover_surface", dependencies=sign_ins, budget=budget,
            ))
        plan = ScanActionPlan(
            scan_id=str(scan_id), execution_plan_digest="b" * 64,
            target_binding_digest=target.digest,
            actions=tuple(ScanAction(target_binding_digest=target.digest, **row) for row in rows),
        )
        await PostgresScanActionStore().persist_plan(conn, plan=plan)
    return target, plan


def _sign_in_receipt(action, target, scan_id):
    """The sign-in fixture: an established session that landed on /hub/."""
    now = datetime.now(timezone.utc).isoformat()
    lane = action.capability_args["lane"]
    return CapabilityReceipt(
        capability_name=action.capability_name, adapter_name=str(action.placement["adapter_name"]),
        adapter_version=str(action.placement["adapter_version"]), target_id=target.target_id,
        scan_id=scan_id, worker_id=WORKER, status="success",
        input_digest=action.action_digest, parser_version=action.output_schema,
        started_at=now, finished_at=now, budget_reserved=action.requested_budget,
        budget_consumed={"http_requests": 2, "tool_wall_seconds": 1}, errors=(),
        observations=({
            "kind": "credential_session", "lane": lane, "status": "established",
            "endpoint_path": "/hub/login", "landing_path": "/hub/",
        },),
    )


async def _run(pool, primary, secondary):
    refs = _refs(primary, secondary)
    target, plan = await _scan(pool, refs)
    launched = {}

    async def process_runner(payload, *, heartbeat):
        await heartbeat()
        launched[payload["tool_name"]] = payload
        process_plan = agent_tools.build_enforced_scanner_plan(
            payload["tool_name"], payload["execution_target"], payload["scanner_options"],
            reserved_budget=payload["_reserved_budget"], pinned_proxy_url=PROXY,
            trusted_headers=payload["trusted_headers"],
        )
        route = ROUTES[payload["tool_name"]][0]
        records = [{
            "kind": "discovered_route", "method": "GET", "url": ORIGIN + route,
            "source": ORIGIN + "/hub/",
        }]
        return {
            "status": "success", "error": None, "partial": False, "timed_out": False,
            "elapsed_seconds": 1, "typed_output": {"records": records, "errors": []},
            "settlement": {"mode": "exact", "actual": 1, "observed_minimum": 1},
            "process_enforcement": process_plan.enforcement_receipt(),
        }

    backend = PostgresScanExecutionBackend(pool=pool, plan=plan, worker_id=WORKER, backend_name="local")
    crawler = DatabaseNeutralScanActionDispatcher(
        target_url=ORIGIN + "/", options=_options(refs), target=target,
        policy=ScanPolicy(active_testing=False), scan_id=plan.scan_id, job_id="job-fixture",
        worker_id=WORKER, plan=plan, backend=backend, process_runner=process_runner,
        cancelled=lambda: False,
    )

    async def dispatcher(action, lease, heartbeat):
        if action.capability_name == "auth.session.establish":
            return _sign_in_receipt(action, target, plan.scan_id)
        return await crawler(action, lease, heartbeat)

    executor = ReceiptScanActionExecutor(
        scan_id=plan.scan_id, target_id=target.target_id, worker_id=WORKER, dispatcher=dispatcher,
    )
    await ScanOrchestrator(backend=backend, executor=executor).run(plan)
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT action_id, status, reason_code FROM scan_capability_actions WHERE scan_id=$1",
            uuid.UUID(plan.scan_id))
    # The continuation compiles the crawls' stored routes into the candidate manifest.
    parent_ids = tuple(item.action_id for item in plan.actions)
    allocation = ScanContinuationAllocation(
        scan_id=plan.scan_id, parent_plan_digest="a" * 64,
        execution_plan_digest=plan.execution_plan_digest,
        target_binding_digest=target.digest, parent_action_ids=parent_ids,
        budget_ceiling={
            "http_requests": 1, "state_changing_requests": 0, "browser_actions": 0,
            "tcp_ports_attempted": 0, "hosts_attempted": 0, "tool_wall_seconds": 1,
        },
        max_endpoint_entries=500, max_candidate_entries=100, allowed_capabilities=(),
    )
    _endpoints, candidates = build_discovery_continuation_manifests(
        allocation=allocation, target_url=ORIGIN + "/", target=target, options=_options(refs),
        action_results={item: await backend.load_result(item) for item in parent_ids},
        observations={item: await backend.load_observations(item) for item in parent_ids},
    )
    actions = {row["action_id"]: (row["status"], row["reason_code"]) for row in rows}
    return plan, actions, launched, candidates


@pytest.mark.parametrize("scenario", sorted(SCENARIOS))
def test_both_crawls_run_with_the_primary_identity(template_database, scenario, capsys):  # noqa: F811
    primary, secondary = SCENARIOS[scenario]

    async def run():
        async with scan_database(template_database) as pool:
            return await _run(pool, primary, secondary)

    plan, actions, launched, candidates = asyncio.run(run())
    raised = [line for line in capsys.readouterr().err.splitlines() if "adapter raised" in line]
    sign_ins = {item.action_id for item in plan.actions if item.capability_name == "auth.session.establish"}
    # The plan has a sign-in action only for an interactive profile.
    assert ("inputs.auth_primary" in sign_ins) is (primary == "form_login")
    for action_id, _capability, tool in CRAWLS:
        assert actions[action_id] == ("success", None), (scenario, actions[action_id], raised)
        payload = launched[tool]
        expected = dict(IDENTITY[("primary", primary)]) if primary else {}
        assert dict(payload["trusted_headers"]) == expected, scenario
        if primary:
            # A session-carrying crawl also starts at the scan's seed on its origin.
            assert "/hub/" in payload["scanner_options"].get("crawl_seed_paths", []), scenario
    assert not raised, raised
    # What both crawls found reaches the verifiers: a candidate for each route's parameter.
    found = {(item["canonical_path"], item["parameter_name"]) for item in candidates.entries}
    assert found >= {("/hub/search", "q"), ("/hub/orders", "id")}, (scenario, found)
