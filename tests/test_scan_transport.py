"""Unit rules for choosing the origin of a target entered without a scheme (scan/transport.py)."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))
sys.path.insert(1, str(ROOT / "scanner"))

from runtime.models import TargetBinding  # noqa: E402
from scan.contracts import bind_scan_scope_receipt, resolve_scan_contract  # noqa: E402
from scan.action_plan import ScanActionPlanCompiler  # noqa: E402
from scan.action_adapter import (  # noqa: E402
    DatabaseNeutralScanActionDispatcher,
    ScanActionAdapterError,
)
from scan.capability_execution import ScanCapabilityContractError  # noqa: E402
from scan.transport import (  # noqa: E402
    REDIRECTS_OFF_ORIGIN,
    REDIRECTS_TO_FROZEN_ORIGIN,
    RESPONDED,
    TRANSPORT_ACTION_ID,
    UNREACHABLE,
    binding_admits_both_schemes,
    choose_effective_origin,
    classify_attempt,
    probe_transport,
    scheme_less_target,
    transport_candidates,
)
from scan.work_manifests import build_canonical_passive_nuclei_template_manifest  # noqa: E402


def _binding(*origins, host="app.example.test"):
    return TargetBinding(
        target_id="t-1", target_kind="web", canonical_host=host,
        allowed_origins=origins, allowed_addresses=("93.184.215.14",),
        allowed_root_domains=("example.test",), scope_receipt_id="scope-1",
    )


BOTH = _binding("http://app.example.test", "https://app.example.test")


def test_candidates_come_only_from_frozen_origins_https_first():
    assert transport_candidates("app.example.test", BOTH) == (
        "https://app.example.test", "http://app.example.test",
    )
    assert transport_candidates("https://app.example.test", BOTH) is None, "explicit is exact"
    ported = _binding("http://app.example.test:8080", "https://app.example.test:8080")
    assert transport_candidates("app.example.test:8080", ported) == (
        "https://app.example.test:8080", "http://app.example.test:8080",
    )
    port80 = _binding("http://app.example.test", "https://app.example.test:80")
    assert transport_candidates("app.example.test:80", port80) == (
        "https://app.example.test:80", "http://app.example.test",
    )


@pytest.mark.parametrize("bare", [
    "other.example.test", "app.example.test:9999", "user@app.example.test",
    "app.example.test/admin", "app.example.test?x=1",
])
def test_candidates_never_widen_the_binding(bare):
    assert transport_candidates(bare, BOTH) == ()


def test_classification_never_follows_a_redirect():
    frozen = ("https://app.example.test", "http://app.example.test")
    to_https = classify_attempt(
        "http://app.example.test",
        {"response": {"status": 301, "location": "https://app.example.test/"}},
        frozen_origins=frozen,
    )
    assert to_https["outcome"] == REDIRECTS_TO_FROZEN_ORIGIN
    elsewhere = classify_attempt(
        "https://app.example.test",
        {"response": {"status": 302, "location": "https://login.example.test/"}},
        frozen_origins=frozen,
    )
    assert elsewhere["outcome"] == REDIRECTS_OFF_ORIGIN
    same = classify_attempt(
        "https://app.example.test",
        {"response": {"status": 302, "location": "/login"}}, frozen_origins=frozen,
    )
    assert same["outcome"] == RESPONDED, "a redirect within the origin is the application"
    down = classify_attempt(
        "https://app.example.test", {"error": "request_error:ConnectError"}, frozen_origins=frozen,
    )
    assert down == {
        "origin": "https://app.example.test", "status": None,
        "outcome": UNREACHABLE, "error": "request_error:ConnectError",
    }


def test_choice_prefers_the_application_then_a_reachable_redirect_then_nothing():
    app_on_http = [
        {"origin": "https://a", "outcome": UNREACHABLE},
        {"origin": "http://a", "outcome": RESPONDED},
    ]
    assert choose_effective_origin(app_on_http) == "http://a"
    only_forwards = [
        {"origin": "https://a", "outcome": UNREACHABLE},
        {"origin": "http://a", "outcome": REDIRECTS_TO_FROZEN_ORIGIN},
    ]
    assert choose_effective_origin(only_forwards) == "http://a"
    assert choose_effective_origin([
        {"origin": "https://a", "outcome": UNREACHABLE},
        {"origin": "http://a", "outcome": UNREACHABLE},
    ]) is None, "an unreachable application is not silently assigned HTTPS"


def test_probing_stops_at_the_first_origin_that_serves_the_application():
    sent = []

    async def request(origin):
        sent.append(origin)
        return {"request": {}, "response": {"status": 200}}

    attempts, _raw = asyncio.run(probe_transport(
        ("https://app.example.test", "http://app.example.test"), request,
    ))
    assert sent == ["https://app.example.test"]
    assert attempts[0]["outcome"] == RESPONDED


def test_scheme_less_target_keeps_the_authority():
    assert scheme_less_target("https://app.example.test") == "app.example.test"
    assert scheme_less_target("https://app.example.test:8443/x") == "app.example.test:8443"
    assert scheme_less_target("http://[fd12::7]:8080") == "[fd12::7]:8080"


def _plan(binding):
    contract = bind_scan_scope_receipt(
        resolve_scan_contract(budget_profile="fast", policy={"active_testing": False}), "scope-1",
    )
    templates = build_canonical_passive_nuclei_template_manifest(
        scan_id="00000000-0000-4000-8000-000000000001", target_binding_digest=binding.digest,
    )
    return contract, ScanActionPlanCompiler().compile(
        scan_id="00000000-0000-4000-8000-000000000001",
        execution_plan=contract.execution_plan, target_binding=binding,
        template_manifest_ref=templates.reference().canonical_dict(),
    )


def test_the_plan_waits_for_transport_only_when_both_schemes_are_frozen():
    assert binding_admits_both_schemes(BOTH)
    _contract, plan = _plan(BOTH)
    ids = [action.action_id for action in plan.actions]
    assert ids[0] == TRANSPORT_ACTION_ID
    transport = plan.actions[0]
    assert transport.required and transport.dependencies == ()
    assert transport.requested_budget == {"http_requests": 2, "tool_wall_seconds": 20}
    for action in plan.actions[1:]:
        assert action.dependencies, f"{action.action_id} could run before the origin is chosen"

    explicit = _binding("https://app.example.test")
    assert not binding_admits_both_schemes(explicit)
    _contract, exact_plan = _plan(explicit)
    assert TRANSPORT_ACTION_ID not in {action.action_id for action in exact_plan.actions}


def _dispatcher(binding, plan, contract, target):
    from runtime.models import ScanPolicy

    policy = contract.execution_plan.policy
    return DatabaseNeutralScanActionDispatcher(
        target_url=target, options={}, target=binding,
        policy=ScanPolicy(**{
            **contract.execution_plan.canonical_dict()["policy"],
            "include_families": tuple(policy.include_families),
            "exclude_families": tuple(policy.exclude_families),
        }),
        scan_id=plan.scan_id, job_id="job-1", worker_id="worker-1", plan=plan,
        backend=object(), process_runner=None, cancelled=lambda: False,
    )


def test_the_dispatcher_defers_a_bare_target_and_never_guesses():
    contract, plan = _plan(BOTH)
    dispatcher = _dispatcher(BOTH, plan, contract, "app.example.test")
    assert dispatcher.target_url is None, "the origin is chosen by transport.resolve"

    single = _binding("https://app.example.test")
    single_contract, single_plan = _plan(single)
    adopted = _dispatcher(single, single_plan, single_contract, "app.example.test")
    assert adopted.target_url == "https://app.example.test/", "one frozen origin: nothing to choose"

    with pytest.raises(ScanCapabilityContractError):
        _dispatcher(BOTH, plan, contract, "other.example.test")


def test_a_bare_target_without_transport_resolve_in_its_plan_is_refused():
    explicit = _binding("https://app.example.test")
    contract, plan_without_transport = _plan(explicit)
    dispatcher = _dispatcher(explicit, plan_without_transport, contract, "https://app.example.test")
    dispatcher.target_url = None
    with pytest.raises(ScanActionAdapterError, match="transport.resolve"):
        asyncio.run(dispatcher._load_transport_resolution(required=True))
