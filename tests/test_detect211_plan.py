"""The CORS probes and the open-redirect batch are planned, with the authority they need."""

from __future__ import annotations

from capabilities.tls_legacy_probe import PROBE_COUNT
from runtime.capability_registry import CAPABILITY_REGISTRY
from scan.action_plan import ScanActionPlanCompiler
from scan.capability_execution import TLS_CONNECTIONS_PER_PAIR, scan_tls_capability_allocation
from scan.contracts import scan_family_capabilities
from scan.posture_findings import CORS_PROBE_ACTIONS
from tests.toplevel_scan_fixtures import SCAN_ID, compiler_target as _target, execution as _execution


def _compile(include, active):
    return ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID, execution_plan=_execution(include=include, active=active),
        target_binding=_target(), action_scope="full",
    )


def test_every_scan_sends_the_two_read_only_cors_probes_after_the_baseline():
    for plan in (_compile(("sensitive_exposure",), False), _compile(("xss",), True)):
        by_id = {action.action_id: action for action in plan.actions}
        for action_id, origin in CORS_PROBE_ACTIONS.items():
            action = by_id[action_id]
            assert action.capability_name == "http.request"
            assert action.capability_args["cors_probe_origin"] == origin
            assert action.capability_args["method"] == "GET"
            assert "baseline.http" in action.dependencies
            assert "state_changing_requests" not in action.requested_budget


def test_the_redirect_batch_runs_only_under_the_active_xss_family():
    assert "redirect.verify_batch" in scan_family_capabilities("xss")
    spec = CAPABILITY_REGISTRY.require("redirect.verify_batch")
    assert spec.required_approval == "active_testing" and spec.risk_tier == "active"
    assert "open_redirect_proof" in spec.evidence_contract
    active = [a for a in _compile(("xss",), True).actions if a.capability_name == "redirect.verify_batch"]
    assert active and active[0].action_id == "verify.redirect" and active[0].required is False
    assert "state_changing_requests" not in active[0].requested_budget
    assert not [a for a in _compile(("xss",), False).actions if a.capability_name == "redirect.verify_batch"]
    assert not [a for a in _compile(("sqli",), True).actions if a.capability_name == "redirect.verify_batch"]


def test_the_tls_reservation_pays_for_the_legacy_probes():
    assert TLS_CONNECTIONS_PER_PAIR == 4 + PROBE_COUNT
    assert CAPABILITY_REGISTRY.require("tls.inspect").budget_cost["tcp_ports_attempted"] == TLS_CONNECTIONS_PER_PAIR
    allocation = scan_tls_capability_allocation({"max_tcp_ports": 100, "max_tool_wall_seconds": 100}, origin_count=2)
    assert allocation["tcp_ports_attempted"] == 2 * TLS_CONNECTIONS_PER_PAIR


def test_a_tcp_budget_short_of_the_legacy_probes_degrades_tls_instead_of_skipping_it():
    from scan.capability_execution import TLS_HANDSHAKE_CONNECTIONS_PER_PAIR
    # Two pairs at ten connections need 20; a budget of 12 still pays for the handshakes.
    degraded = scan_tls_capability_allocation({"max_tcp_ports": 12, "max_tool_wall_seconds": 100}, origin_count=2)
    assert degraded["tcp_ports_attempted"] == 2 * TLS_HANDSHAKE_CONNECTIONS_PER_PAIR
    # Below the handshakes the action is skipped, and the caller reports why.
    assert scan_tls_capability_allocation({"max_tcp_ports": 7, "max_tool_wall_seconds": 100}, origin_count=2) is None


def test_the_planned_tls_reservation_degrades_with_a_small_tcp_grant():
    from dataclasses import replace
    from scan.capability_execution import TLS_HANDSHAKE_CONNECTIONS_PER_PAIR
    full = _compile(("sensitive_exposure",), False)
    pairs = next(a for a in full.actions if a.capability_name == "tls.inspect").capability_args
    count = pairs["origin_count"] * pairs["address_count"]
    assert next(a for a in full.actions if a.capability_name == "tls.inspect").requested_budget[
        "tcp_ports_attempted"] == count * TLS_CONNECTIONS_PER_PAIR
    plan = _execution(include=("sensitive_exposure",), active=False)
    small = replace(plan, budget=replace(plan.budget, max_tcp_ports=count * TLS_CONNECTIONS_PER_PAIR - 1))
    compiled = ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID, execution_plan=small, target_binding=_target(), action_scope="full",
    )
    tls = next(a for a in compiled.actions if a.capability_name == "tls.inspect")
    assert tls.requested_budget["tcp_ports_attempted"] == count * TLS_HANDSHAKE_CONNECTIONS_PER_PAIR
