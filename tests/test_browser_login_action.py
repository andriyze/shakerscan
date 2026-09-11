"""Real registry/compiler/dispatcher integration, with offline browser and wire doubles.

No network, real credentials, or offensive capabilities run in this suite.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import asdict, replace
import json
from types import SimpleNamespace
import uuid

import pytest

from capabilities.browser import browser_capability_adapter
from capabilities.browser_login_action import (
    BrowserLoginAdapter, BrowserLoginMaterial, BrowserLoginRuntimeTransport,
)
from capabilities.browser_login import BrowserLoginValues
from capabilities.browser_login_worker import prepare_hunt_browser_action, browser_worker_policy
from runtime.browser_login_contract import (
    BROWSER_LOGIN_CAPABILITY as CAP, BROWSER_LOGIN_BUDGET,
    normalize_browser_login_profile, normalize_browser_login_reference,
)
from runtime.capability_registry import CAPABILITY_REGISTRY
from runtime.credentials import build_credential_secret, parse_credential_secret, public_credential_configuration
from runtime.models import TargetBinding, ScanPolicy
from runtime.request_replay_executor import ReplayTransportResult
from scan.action_plan import ScanActionPlanCompiler, ScanActionPlan, ScanActionPlanError
from scan.action_adapter import DatabaseNeutralScanActionDispatcher, ScanActionAdapterError
from scan.admission_actions import (
    _compile_allocated_scan_action_plan, _compile_scan_admission_action_authority,
)
from scan.budget_allocator import ScanBudgetAllocationError
from scan.contracts import resolve_scan_contract, bind_scan_scope_receipt
from scan.execution_backend import ActionLease
from scan.browser_login import browser_login_scan_limits
from hunt.action_dispatcher import HUNT_ACTION_DISPATCHER, HuntActionRequest, RegisteredHuntAdapterFactory
from request_models import ScanRequest
from tests.test_browser_login_check import Browser, Route, SPEC, VALUES, ORIGIN, SECRET

PROFILE_ID = "11111111-1111-4111-8111-111111111111"
TARGET_ID = "22222222-2222-4222-8222-222222222222"
SCOPE_ID = "33333333-3333-4333-8333-333333333333"
APPROVAL_ID = "44444444-4444-4444-8444-444444444444"
OWNER_ID = "55555555-5555-4555-8555-555555555555"
REF = {"profile_id": PROFILE_ID, "profile_version": 1, "principal_slot": "primary"}
TARGET = TargetBinding(
    target_id=TARGET_ID, target_kind="web", canonical_host="login-fixture.test",
    allowed_origins=(ORIGIN,), allowed_addresses=("192.0.2.1", "192.0.2.2"),
    allowed_root_domains=("login-fixture.test",), scope_receipt_id=SCOPE_ID,
)
POLICY = ScanPolicy(active_testing=True, allow_state_changing_http=True,
                    approval_receipt_id=APPROVAL_ID, scope_receipt_id=SCOPE_ID)
CONFIG = {"schema_version": "browser-login-profile/v1", "workflow": asdict(SPEC),
          "checks": [{"url": ORIGIN + "/help", "visible_selector": "#help"}]}
CONTEXT = {"credential_refs": [{**REF, "source": "credential_profiles", "allowed_capabilities": [CAP]}]}


def prepared(ref=REF):
    return BrowserLoginAdapter.prepare(target=TARGET, base_url=ORIGIN,
                                      args={"as_principal": "primary"}, profile_ref=ref)


class BrowserFixture(Browser):
    async def send(self, url, method="GET"):
        route = Route(url, method)
        async def headers():
            return {"Content-Type": "application/json", "Cookie": "session=private-browser-cookie"}
        route.request.all_headers = headers
        route.request.post_data_buffer = b'{"username":"synthetic-user","password":"SYNTHETIC_PRIVATE_PASSWORD"}' if method == "POST" else None
        await self.handler(route)
        return route


class Sender:
    def __init__(self, *, status=200):
        self.requests = []
        self.status = status

    async def send(self, request, *, target, timeout_seconds, follow_redirects):
        assert follow_redirects is False
        assert len(target.allowed_addresses) == 1
        self.requests.append(request)
        return ReplayTransportResult(
            status_code=self.status if request.method == "POST" else 200,
            connected_address=target.allowed_addresses[0], final_url=request.url,
            response_body=b"synthetic response", response_headers={"Content-Type": "text/html"},
        )


def fixture_adapter(*, flags=None, config=CONFIG, fail_authority_after=None):
    browser = BrowserFixture(**(flags or {}))
    sender = Sender(status=401 if (flags or {}).get("bad_password") else 200)
    authority = []
    async def revalidate():
        authority.append(True)
        if fail_authority_after is not None and len(authority) > fail_authority_after:
            raise ValueError(SECRET)
    @asynccontextmanager
    async def loader():
        yield BrowserLoginMaterial(config, BrowserLoginValues(VALUES.username, VALUES.password), revalidate)
    @asynccontextmanager
    async def browser_factory():
        try:
            yield browser
        finally:
            await browser.close()
    return BrowserLoginAdapter(prepared(), credential_loader=loader, policy=POLICY,
                               browser_factory=browser_factory, sender=sender), browser, sender, authority


async def noop():
    pass


def test_registry_is_one_credential_gated_browser_action_without_raw_inputs():
    spec = CAPABILITY_REGISTRY.require(CAP)
    assert spec.risk_tier == "credential" and spec.requires_active_approval
    assert spec.hunt_executor == "worker_browser"
    assert spec.budget_cost == BROWSER_LOGIN_BUDGET
    assert spec.placement_requirements["state_changing_http"] is True
    assert browser_capability_adapter(CAP) is BrowserLoginAdapter
    assert spec.planner_contract()["input_schema"]["properties"].keys() == {"as_principal"}
    assert HUNT_ACTION_DISPATCHER.has_placement(CAP, "worker_browser")


@pytest.mark.parametrize("extra", [{"password": SECRET}, {"workflow": CONFIG}, {"profile_ref": REF}, {"session_ref": PROFILE_ID}])
def test_hunt_cannot_supply_credentials_workflow_or_override_profile(extra):
    with pytest.raises(ValueError):
        prepare_hunt_browser_action(CAP, target=TARGET, base_url=ORIGIN,
            args={"as_principal": "primary", **extra}, context=CONTEXT, policy=POLICY)


def test_hunt_and_worker_bind_the_same_persisted_profile_version():
    item = prepare_hunt_browser_action(CAP, target=TARGET, base_url=ORIGIN,
            args={"as_principal": "primary"}, context=CONTEXT, policy=asdict(POLICY))
    assert item.input_digest == prepared().input_digest
    assert prepared({**REF, "profile_version": 2}).input_digest != item.input_digest
    with pytest.raises(ValueError):
        prepare_hunt_browser_action(CAP, target=TARGET, base_url=ORIGIN,
            args={"as_principal": "primary"}, context={"credential_refs": []}, policy=POLICY)


@pytest.mark.parametrize("field", ["active_testing", "allow_state_changing_http", "scope_receipt_id", "approval_receipt_id"])
def test_new_action_requires_both_permissions_and_bound_approval(field):
    policy = replace(POLICY, **{field: False if field.endswith("testing") or field.endswith("http") else None})
    with pytest.raises(ValueError):
        BrowserLoginAdapter(prepared(), credential_loader=lambda: None, policy=policy)


def test_old_browser_worker_actions_keep_their_read_only_policy():
    assert browser_worker_policy("browser.navigate", policy=asdict(POLICY), target=TARGET).allow_state_changing_http is False
    assert browser_worker_policy(CAP, policy=asdict(POLICY), target=TARGET).allow_state_changing_http is True


def test_saved_profile_roundtrip_is_private_and_no_script_or_step_channel_exists():
    encoded = build_credential_secret("form_login", username=VALUES.username, secret=SECRET,
                                      endpoint_url="/login", browser_login=CONFIG)
    decoded = parse_credential_secret("form_login", encoded)
    assert decoded["browser_login"] == normalize_browser_login_profile(CONFIG)
    public = public_credential_configuration(decoded)
    assert public["browser_login_configured"] is True
    for text in [SECRET, VALUES.username, ORIGIN, "#private-account"]:
        assert text not in json.dumps(public)
    with pytest.raises(ValueError):
        normalize_browser_login_profile({**CONFIG, "script": "anything"})


@pytest.mark.parametrize("field,value", [("max_requests", 129), ("max_requests", True), ("timeout_ms", 120001), ("max_response_bytes", 3*1024*1024)])
def test_saved_flow_cannot_exceed_the_registered_reservation(field, value):
    with pytest.raises(ValueError):
        normalize_browser_login_profile({**CONFIG, "workflow": {**CONFIG["workflow"], field: value}})


def test_scan_public_selection_is_secret_free_and_forces_a_single_worker():
    request = ScanRequest(target=ORIGIN, browser_login_profile_ids=[PROFILE_ID], advanced={"max_http_requests": 500})
    assert browser_login_scan_limits(request) == {"max_http_requests": 500, "include_families": [], "exclude_families": [], "force_single_worker": True}
    assert request.advanced.force_single_worker is False  # no caller-model mutation
    with pytest.raises(ValueError):
        ScanRequest(target=ORIGIN, browser_login_profile_ids=[PROFILE_ID], browser_login=CONFIG)
    with pytest.raises(Exception, match="single local worker"):
        browser_login_scan_limits(ScanRequest(target=ORIGIN, browser_login_profile_ids=[PROFILE_ID], options={"parallel": True}))


def contract():
    resolved = resolve_scan_contract(budget_profile="balanced",
        policy={"active_testing": True, "allow_state_changing_http": True,
                "include_families": ["recon"], "preset": "custom"},
        advanced={"force_single_worker": True}, approval_receipt_id=APPROVAL_ID)
    return bind_scan_scope_receipt(resolved, SCOPE_ID)


def compile_plan(refs=(REF,), **changes):
    return ScanActionPlanCompiler().compile(
        scan_id=OWNER_ID, execution_plan=contract().execution_plan, target_binding=TARGET,
        browser_login_profile_refs=refs, **changes)


def test_scan_compiler_creates_required_once_only_qa_and_no_native_auth_for_qa_profile():
    plan = compile_plan()
    actions = [item for item in plan.actions if item.capability_name == CAP]
    assert len(actions) == 1 and actions[0].action_id == "qa.browser_login_primary"
    assert actions[0].required and not actions[0].supporting
    assert actions[0].capability_args["profile_ref"] == REF
    assert actions[0].placement["eligible_backends"] == ("local",)
    assert "qa.browser_login_primary" in plan.actions[-1].dependencies
    assert not any(item.capability_name == "auth.session.establish" for item in plan.actions)
    assert not any(item.capability_name == CAP for item in compile_plan(refs=()).actions)
    assert compile_plan(refs=({**REF, "profile_version": 2},)).plan_digest != plan.plan_digest


@pytest.mark.parametrize("profile", ["fast", "balanced", "thorough", "deep"])
@pytest.mark.parametrize("count", [1, 2])
def test_real_admission_funds_each_selected_qa_once_without_continuation_authority(profile, count):
    selected = [REF, {**REF, "profile_id": "66666666-6666-4666-8666-666666666666",
                      "principal_slot": "secondary"}][:count]
    resolved = bind_scan_scope_receipt(resolve_scan_contract(
        budget_profile=profile,
        policy={"active_testing": True, "allow_state_changing_http": True,
                "include_families": ["recon"], "preset": "custom"},
        advanced={"force_single_worker": True}, approval_receipt_id=APPROVAL_ID,
    ), SCOPE_ID)
    parent, continuation = _compile_scan_admission_action_authority(
        scan_id=OWNER_ID, scan_contract=resolved, target_binding=TARGET,
        browser_login_profile_refs=selected,
    )
    qa = [action for action in parent.actions if action.capability_name == CAP]
    assert len(qa) == count
    assert all(action.required and dict(action.requested_budget) == BROWSER_LOGIN_BUDGET
               for action in qa)
    assert continuation is not None
    assert continuation.parent_plan_digest == parent.plan_digest
    assert CAP not in continuation.allowed_capabilities
    assert CAP not in continuation.required_capabilities
    for dimension, limit in resolved.budget.ledger_limits().items():
        admitted = sum(action.requested_budget.get(dimension, 0) for action in parent.actions)
        assert admitted + continuation.budget_ceiling.get(dimension, 0) <= limit
    direct = _compile_allocated_scan_action_plan(
        scan_id=OWNER_ID, scan_contract=resolved, target_binding=TARGET,
        browser_login_profile_refs=selected,
    )
    assert {action.action_id for action in qa} <= set(direct.actions[-1].dependencies)


@pytest.mark.parametrize("limits", [
    {"max_browser_actions": 31}, {"max_state_changing_requests": 0},
])
def test_admission_never_silently_drops_or_underfunds_selected_login_qa(limits):
    resolved = bind_scan_scope_receipt(resolve_scan_contract(
        budget_profile="balanced",
        policy={"active_testing": True, "allow_state_changing_http": True,
                "include_families": ["recon"], "preset": "custom"},
        advanced={"force_single_worker": True, **limits}, approval_receipt_id=APPROVAL_ID,
    ), SCOPE_ID)
    with pytest.raises(ScanBudgetAllocationError):
        _compile_scan_admission_action_authority(
            scan_id=OWNER_ID, scan_contract=resolved, target_binding=TARGET,
            browser_login_profile_refs=[REF],
        )


@pytest.mark.parametrize("changes", [{"continuation_round": 1}, {"action_scope": "endpoint"}, {"placement_backends": ("broker",)}])
def test_qa_cannot_reappear_in_continuation_or_remote_execution(changes):
    with pytest.raises(ScanActionPlanError):
        compile_plan(**changes)


def test_actual_scan_dispatch_runs_shared_adapter_and_produces_only_qa_receipt():
    full_plan = compile_plan()
    action = next(item for item in full_plan.actions if item.capability_name == CAP)
    plan = ScanActionPlan(scan_id=OWNER_ID, execution_plan_digest=full_plan.execution_plan_digest,
                         target_binding_digest=TARGET.digest, actions=(action,))
    adapter, browser, sender, authority = fixture_adapter()
    dispatcher = DatabaseNeutralScanActionDispatcher(
        target_url=ORIGIN, options={}, target=TARGET, policy=POLICY,
        scan_id=OWNER_ID, job_id=str(uuid.uuid4()), worker_id="worker:qa", plan=plan,
        backend=SimpleNamespace(), process_runner=noop, cancelled=lambda: False,
        browser_login_adapter_factory=lambda selected, current: adapter,
    )
    lease = SimpleNamespace(worker_id="worker:qa")
    result = asyncio.run(dispatcher(action, lease, noop))
    assert result.status == "success"
    assert browser.closed and len(sender.requests) == 6
    assert len(authority) == len(sender.requests) + 2
    assert sum(item.method == "POST" for item in sender.requests) == 1
    assert result.observations[0]["kind"] == "browser_login_qa"
    text = json.dumps(result.canonical_dict())
    for private in [SECRET, VALUES.username, "private-browser-cookie", "#private-account", "synthetic response"]:
        assert private not in text
    assert "candidate" not in text and "proof_state" not in text


def test_actual_hunt_dispatch_uses_same_operation_and_settles_counters():
    adapter, browser, sender, _ = fixture_adapter()
    request = HuntActionRequest(hunt_id=OWNER_ID, action_id=str(uuid.uuid4()),
        capability_name=CAP, target=TARGET, capability_input={"as_principal": "primary"},
        requested_budget={**BROWSER_LOGIN_BUDGET, "agent_actions": 1, "active_actions": 1})
    result = asyncio.run(HUNT_ACTION_DISPATCHER.execute(
        request, factory=RegisteredHuntAdapterFactory({"playwright.login_check": lambda spec, req: adapter}),
        heartbeat=noop, cancelled=lambda: False))
    assert result.status == "success" and browser.closed
    assert result.actual_budget["http_requests"] == 6
    assert result.actual_budget["state_changing_requests"] == 1
    assert result.actual_budget["agent_actions"] == result.actual_budget["active_actions"] == 1


@pytest.mark.parametrize("flags", [{"bad_password": True}, {"mfa": True}, {"expires": True}, {"qa_assertion_missing": True}, {"protected_public_marker": True}])
def test_shared_action_never_reports_success_after_failed_auth_or_qa(flags):
    adapter, browser, sender, _ = fixture_adapter(flags=flags)
    result = asyncio.run(adapter.execute(heartbeat=noop, cancelled=lambda: False))
    assert result.status != "success" and browser.closed
    assert result.observations[0]["authentication_verified"] is False
    assert sum(item.method == "POST" for item in sender.requests) <= 1
    assert SECRET not in repr(result)


def test_authority_revocation_blocks_next_request_and_never_retries_login():
    adapter, browser, sender, authority = fixture_adapter(fail_authority_after=3)
    result = asyncio.run(adapter.execute(heartbeat=noop, cancelled=lambda: False))
    assert result.status == "failed" and browser.closed
    assert len(sender.requests) == 2
    assert not any(item.method == "POST" for item in sender.requests)
    assert SECRET not in repr(result)


def test_local_dispatch_rejects_missing_worker_credential_bridge():
    plan = compile_plan()
    action = next(item for item in plan.actions if item.capability_name == CAP)
    dispatcher = DatabaseNeutralScanActionDispatcher(
        target_url=ORIGIN, options={}, target=TARGET, policy=POLICY,
        scan_id=OWNER_ID, job_id=str(uuid.uuid4()), worker_id="worker:qa", plan=plan,
        backend=SimpleNamespace(), process_runner=noop, cancelled=lambda: False,
    )
    with pytest.raises(ScanActionAdapterError, match="local credential-enabled worker"):
        asyncio.run(dispatcher(action, SimpleNamespace(worker_id="worker:qa"), noop))
