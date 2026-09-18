from dataclasses import replace
import asyncio
import pytest

from api.scan.action_plan import ScanActionPlanCompiler, ScanActionPlanError, ScanActionPlacementError
from api.scan.budget_allocator import allocate_scan_action_plan, ScanBudgetAllocationError
from tests.test_scan_action_compiler import SCAN_ID, _execution, _target
from tests.test_authenticated_assurance import configuration
from tests.test_authenticated_assurance_snapshots import inputs, snapshot


def credentials():
    profile_id = "11111111-1111-4111-8111-111111111111"
    return [{"profile_id": profile_id, "version": 1, "digest": "b" * 64, "lane": "primary",
             "auth_kind": "bearer_token", "authentication_profile_ref": {
                 "profile_id": profile_id, "revision": 1, "configuration_digest": "c" * 64}}]


def compile_plan(**kwargs):
    values = dict(scan_id=SCAN_ID, execution_plan=_execution(include=("recon",), active=False),
        target_binding=_target(), credential_profile_refs=credentials(), action_scope="global")
    values.update(kwargs)
    return ScanActionPlanCompiler().compile(**values)


def test_health_samples_share_action_authority_budget_and_dependencies():
    plan = compile_plan()
    samples = [row for row in plan.actions if "authentication_profile_ref" in row.capability_args]
    assert len(samples) == 6  # Before/after each of the three HTTP baseline actions.
    assert all(row.capability_name == "http.request" and row.required and row.supporting for row in samples)
    assert all(dict(row.requested_budget) == {"http_requests": 1, "tool_wall_seconds": 15} for row in samples)
    assert all(tuple(row.placement["eligible_backends"]) == ("local",) for row in plan.actions)
    by_id = {row.action_id: row for row in plan.actions}
    for row in samples:
        if row.action_id.startswith("health.before."):
            original = row.action_id.removeprefix("health.before.primary.")
            assert row.action_id in by_id[original].dependencies
            assert by_id["health.after.primary." + original].dependencies == (original,)
    assert set(plan.actions[-1].dependencies) == {row.action_id for row in plan.actions[:-1]}
    allocation = allocate_scan_action_plan(plan, _execution().budget)
    assert all(row.admission_status == "planned" for row in allocation.plan.actions if row.action_id in {s.action_id for s in samples})
    assert allocation.allocated["http_requests"] >= 6
    with pytest.raises(ScanBudgetAllocationError):
        allocate_scan_action_plan(plan, replace(_execution().budget, max_http_requests=1, max_state_changing_requests=0))


def test_unverified_consumers_and_remote_health_fail_closed():
    with pytest.raises(ScanActionPlanError, match="unsupported: web.probe"):
        compile_plan(action_scope="full")
    with pytest.raises(ScanActionPlacementError, match="local worker"):
        compile_plan(placement_backends=("broker",))
    refs = credentials()
    refs[0]["authentication_profile_ref"]["revision"] = True
    with pytest.raises(ScanActionPlanError, match="reference is invalid"):
        compile_plan(credential_profile_refs=refs)


def test_legacy_graph_is_unchanged_and_profile_change_changes_plan():
    refs = credentials()
    refs[0].pop("authentication_profile_ref")
    legacy = compile_plan(credential_profile_refs=refs)
    assert not any(row.action_id.startswith("health.") for row in legacy.actions)
    original = compile_plan()
    refs = credentials()
    refs[0]["authentication_profile_ref"]["revision"] = 2
    assert compile_plan(credential_profile_refs=refs).plan_digest != original.plan_digest


def test_health_wall_budget_also_bounds_preflight_waits(configuration):
    from authenticated_assurance.scan_health import ScanHealthAdapter

    async def run():
        cleaned = False
        async def stalled(attempt):
            nonlocal cleaned
            try:
                await asyncio.sleep(60)
            finally:
                cleaned = True
        adapter = ScanHealthAdapter(pinned=snapshot(*inputs(configuration)), observe=stalled,
            requested_budget={"http_requests": 1, "tool_wall_seconds": 1})
        async with asyncio.timeout(2):
            result = await adapter.execute(heartbeat=lambda: asyncio.sleep(0), cancelled=lambda: False)
        assert cleaned and result.timed_out and result.partial
        assert result.actual_budget["http_requests"] == 0
        record = result.observations[0]["record"]
        assert record["state"] == "unknown" and record["reason_code"] == "validation_timeout"
    asyncio.run(run())
