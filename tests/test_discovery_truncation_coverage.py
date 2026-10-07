"""Discovery is sized to what it emits, and a truncated discovery is a coverage gap.

Soak scan 60ce4f23 (shakerscan.com, Balanced, passive preset): `web.crawl` was stopped
`output_truncated` after 21 of its 300 seconds -- the 768 KB output allowance its
1,500-request reservation bought at 512 bytes per request was full long before the crawl
spent its time, because katana writes a JSONL line for every link of every page -- and
the parser then read only the first 1,500 lines, keeping 165 distinct routes. The Scan
still reported `coverage: complete`, because the crawl is optional and nothing turned a
truncated discovery into a gap. Its passive template pack also ran against the base origin
alone (7 requests): a passive-only Scan never ran the discovery continuation, so the pack
never reached the routes discovery found.
"""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from api.scan.action_plan import ScanActionPlan
from api.scan.capability_result import CapabilityResultReason, CapabilityResultStatus
from api.scan.finalizer import finalize_scan_report
from tests.test_scan_orchestrator import SCAN_ID, _action, _result


def _report(crawl_status, crawl_reason, *, capability="web.crawl"):
    baseline = _action("baseline.http", 0)
    crawl = replace(
        _action("discover.web_crawl", 1, capability_name=capability),
        required=False, action_digest=None,
    )
    final = _action("finalize.report", 2, dependencies=(baseline.action_id, crawl.action_id))
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64, actions=(baseline, crawl, final),
    )
    results = {
        baseline.action_id: _result(baseline, status=CapabilityResultStatus.SUCCESS),
        crawl.action_id: _result(crawl, status=crawl_status, reason=crawl_reason),
    }
    return finalize_scan_report(
        plan=plan, target_url="https://app.example.test",
        action_results=results, observations={},
    )


@pytest.mark.parametrize("status, reason", [
    (CapabilityResultStatus.PARTIAL, CapabilityResultReason.OUTPUT_TRUNCATED),
    (CapabilityResultStatus.TIMED_OUT, CapabilityResultReason.TIMED_OUT),
    (CapabilityResultStatus.PARTIAL, CapabilityResultReason.HTTP_REQUEST_BUDGET_EXHAUSTED),
    (CapabilityResultStatus.SKIPPED, CapabilityResultReason.INSUFFICIENT_PLAN_BUDGET),
    (CapabilityResultStatus.PARTIAL, CapabilityResultReason.CRAWLER_MEMORY_BOUND_EXCEEDED),
])
def test_a_discovery_cut_short_by_its_budget_is_a_coverage_gap(status, reason):
    coverage = _report(status, reason)["coverage"]

    assert coverage["status"] == "partial", "coverage must not read complete"
    assert "discovery_truncated" in coverage["reasons"]
    assert coverage["truncated_discovery_actions"] == ["discover.web_crawl"]
    # Surface the plan never examined makes the grade provisional, as unscheduled
    # manifest work already does; the report and the explanation agree on it.
    assert coverage["grade_reliability"]["reliable"] is False
    assert "discovery_truncated" in coverage["grade_reliability"]["reasons"]


@pytest.mark.parametrize("status, reason, capability", [
    (CapabilityResultStatus.SUCCESS, None, "web.crawl"),
    # A document the parser could only partly model, or a hint file never published,
    # is not discovery cut short by budget.
    (CapabilityResultStatus.PARTIAL, CapabilityResultReason.PARSER_FAILED, "web.spec_ingest"),
    (CapabilityResultStatus.PARTIAL, CapabilityResultReason.SOURCE_NOT_PUBLISHED, "web.spec_ingest"),
    (CapabilityResultStatus.SKIPPED, CapabilityResultReason.NOT_APPLICABLE, "web.crawl"),
])
def test_complete_or_non_budget_discovery_outcomes_leave_coverage_alone(status, reason, capability):
    coverage = _report(status, reason, capability=capability)["coverage"]

    assert coverage["status"] == "complete"
    assert "discovery_truncated" not in coverage["reasons"]
    assert coverage["truncated_discovery_actions"] == []


def test_the_gap_has_an_operator_label():
    from api.scan.explanation import _REASON_LABELS

    assert "discovery" in _REASON_LABELS["discovery_truncated"].lower()


# --- the crawl's output allowance and parse window ----------------------------------------


def test_a_crawl_is_allowed_the_output_its_pages_emit():
    import agent_tools

    held = {"http_requests": 1_500}
    crawl = agent_tools.agent_tool_output_bytes(held, floor=80_000, tool="katana")
    browser = agent_tools.agent_tool_output_bytes(held, floor=80_000, tool="katana_headless")
    other = agent_tools.agent_tool_output_bytes(held, floor=80_000, tool="ffuf")

    assert other == 1_500 * agent_tools.AGENT_TOOL_OUTPUT_BYTES_PER_REQUEST, "unchanged"
    # The soak crawl filled 768 KB after at most ~105 fetches: over 7 KB per page.
    assert crawl == browser == min(
        agent_tools.AGENT_TOOL_OUTPUT_BYTES_CEILING, 1_500 * 8_192,
    )
    assert crawl >= 7_300 * 1_000
    assert agent_tools.agent_tool_output_bytes({"http_requests": 1}, floor=80_000, tool="katana") == 80_000


def test_the_whole_retained_crawl_output_is_read_for_distinct_routes():
    import agent_tools

    navigation = [
        json.dumps({"request": {"method": "GET", "endpoint": f"https://app.example.test/nav/{index % 40}",
                                "source": "https://app.example.test/"}})
        for index in range(3_000)
    ]
    deep = [
        json.dumps({"request": {"method": "GET", "endpoint": f"https://app.example.test/docs/page-{index}",
                                "source": "https://app.example.test/docs"}})
        for index in range(200)
    ]
    offsite = [
        json.dumps({"request": {"method": "GET", "endpoint": f"https://elsewhere.test/{index}"}})
        for index in range(500)
    ]
    parsed = agent_tools.parse_scanner_output(
        "katana", "\n".join(navigation + offsite + deep), allowed_host="app.example.test",
    )
    urls = {record["url"] for record in parsed["records"]}

    assert len([url for url in urls if "/docs/page-" in url]) == 200
    assert len([url for url in urls if "/nav/" in url]) == 40
    assert not any("elsewhere.test" in url for url in urls)


def test_distinct_crawl_routes_stay_bounded():
    import agent_tools

    lines = [
        json.dumps({"request": {"method": "GET", "endpoint": f"https://app.example.test/r/{index}"}})
        for index in range(agent_tools.MAX_TOOL_RECORDS + 300)
    ]
    parsed = agent_tools.parse_scanner_output("katana", "\n".join(lines), allowed_host="app.example.test")
    assert len(parsed["records"]) == agent_tools.MAX_TOOL_RECORDS


# --- the passive pack reaches the discovered surface ----------------------------------------


def test_a_passive_scan_runs_its_template_pack_over_the_discovered_surface():
    from api.scan.admission_actions import _compile_scan_admission_action_authority
    from api.scan.action_plan import batch_profile_shape
    from api.scan.contracts import resolve_scan_contract
    from api.scan.continuation_rounds import compile_next_continuation
    from api.scan.work_manifests import build_canonical_scan_nuclei_template_manifest
    from tests.test_continuation_rounds import _settle_round_fixture
    from tests.test_scan_continuation import _target

    target = _target()
    contract = resolve_scan_contract(budget_profile="balanced")
    assert contract.policy.active_testing is False
    template = build_canonical_scan_nuclei_template_manifest(
        scan_id=SCAN_ID, target_binding_digest=target.digest, include_active=False,
    )
    parent, allocation = _compile_scan_admission_action_authority(
        scan_id=SCAN_ID, scan_contract=contract, target_binding=target,
        template_manifest_ref=template.reference().canonical_dict(),
    )
    assert allocation is not None
    fixture = dict(
        parent_plan=parent, allocation=allocation, parent_results={},
        execution_plan=contract.execution_plan, target=target,
        target_url="https://app.example.test", observations={}, request_manifests=(),
        options={
            "template_manifest_ref": template.reference().canonical_dict(),
            "custom_endpoints": [f"GET /docs/page-{index}" for index in range(40)],
        },
    )
    _settle_round_fixture(fixture)

    first = compile_next_continuation(**fixture, revision_number=1)

    appended = first.plan.actions[len(parent.actions):]
    passive = [action for action in appended if action.capability_name == "templates.passive_batch"]
    size, shape = batch_profile_shape("balanced", "templates.passive_batch")
    assert passive, "the pack must reach the discovered routes"
    assert passive[0].capability_args["slice"] == {"start": 0, "count": size}
    assert passive[0].requested_budget["http_requests"] == shape["http_requests"]
    assert sum(action.capability_args["slice"]["count"] for action in passive) > 1
    assert not any(
        action.capability_name in {"xss.verify_batch", "sqli.verify_batch", "templates.active_batch"}
        for action in appended
    )


def _d1_admission(endpoint_paths=("/",)):
    """E2E D-1's exact submission: fast, passive, max_endpoints 40, single worker."""
    from api.runtime.models import TargetBinding
    from api.scan.admission_actions import _compile_scan_admission_action_authority
    from api.scan.contracts import resolve_scan_contract
    from api.scan.work_manifests import (
        build_canonical_scan_nuclei_template_manifest, build_endpoint_manifest,
    )

    target = TargetBinding(
        target_id="d1", target_kind="web", canonical_host="juice-shop.test",
        allowed_origins=("http://juice-shop.test:3000",), allowed_addresses=("192.0.2.40",),
        allowed_root_domains=("juice-shop.test",),
    )
    contract = resolve_scan_contract(
        budget_profile="fast", policy={"active_testing": False},
        advanced={"max_endpoints": 40, "force_single_worker": True},
    )
    template = build_canonical_scan_nuclei_template_manifest(
        scan_id=SCAN_ID, target_binding_digest=target.digest, include_active=False,
    )
    endpoints = build_endpoint_manifest(
        scan_id=SCAN_ID, target_binding_digest=target.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2", "status": "complete", "reason": None,
            "endpoints": [{
                "method": "GET", "scheme": "http", "host": "juice-shop.test", "port": 3000,
                "normalized_path": path, "concrete_path": path, "query_keys": [],
                "source": "target",
            } for path in endpoint_paths],
        },
        source_action_ids=("discover.web_probe",),
    )
    plan, allocation = _compile_scan_admission_action_authority(
        scan_id=SCAN_ID, scan_contract=contract, target_binding=target,
        endpoint_manifest_ref=endpoints.reference().canonical_dict(),
        template_manifest_ref=template.reference().canonical_dict(),
    )
    return plan, allocation, contract, target, template


def test_the_reviewed_passive_pack_stays_a_required_baseline_of_every_passive_scan():
    """Breadth over discovery is additional work; the base-origin pack is never deferred.

    E2E D-1 looks for `passive.templates` holding exactly 7 requests / 30 seconds and
    requires it to succeed. Deferring the pack into the continuation removed it from the
    admission plan, so a passive Scan could complete without it whenever discovery found
    nothing or no round was funded.
    """
    from api.scan.continuation_rounds import compile_next_continuation
    from tests.test_continuation_rounds import _settle_round_fixture

    plan, allocation, contract, target, template = _d1_admission()
    baseline = [a for a in plan.actions if a.capability_name == "templates.passive_batch"]
    assert [a.action_id for a in baseline] == ["passive.templates"]
    assert baseline[0].required is True
    assert dict(baseline[0].requested_budget) == {"http_requests": 7, "tool_wall_seconds": 30}
    assert allocation is not None

    fixture = dict(
        parent_plan=plan, allocation=allocation, parent_results={},
        execution_plan=contract.execution_plan, target=target,
        target_url="http://juice-shop.test:3000", observations={}, request_manifests=(),
        options={
            "template_manifest_ref": template.reference().canonical_dict(),
            "custom_endpoints": [f"GET /page-{chr(97 + i)}" for i in range(20)],
        },
    )
    _settle_round_fixture(fixture)
    first = compile_next_continuation(**fixture, revision_number=1)
    breadth = [
        a for a in first.plan.actions[len(plan.actions):]
        if a.capability_name == "templates.passive_batch"
    ]
    assert breadth, "discovered routes still get the pack as additional breadth"
    assert not any(a.required for a in breadth), "breadth can never fail the Scan"
