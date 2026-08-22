from __future__ import annotations

import copy
import os
import sys

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from runtime.models import ScanBudget, ScanPolicy, TargetBinding
from scan.execution import ScanExecutionPlan
from scan.executor import (
    NATIVE_SCAN_STAGES,
    NativeScanExecutionError,
    build_native_scan_execution,
    validate_native_scan_execution_payload,
)
from scan.jobs import ScanShardAuthority, ScanShardBudget


def _plan(*, active=False, network=False, include=(), exclude=()):
    return ScanExecutionPlan(
        policy=ScanPolicy(
            active_testing=active,
            allow_state_changing_http=active,
            network_discovery=network,
            subdomain_discovery=True,
            include_families=include,
            exclude_families=exclude,
            approval_receipt_id="approval-1" if (active or network) else None,
        ),
        budget_profile="balanced",
        budget=ScanBudget(1200, 5000, 2000, 200, 5000, 900, 4),
    )


def _build(plan, options):
    return build_native_scan_execution(
        plan,
        options,
        target_binding=TargetBinding(
            target_id="target-1",
            target_kind="web",
            canonical_host="example.test",
            allowed_origins=("https://example.test",),
            allowed_addresses=("192.0.2.10",),
            allowed_root_domains=("example.test",),
            scope_receipt_id=plan.policy.scope_receipt_id,
        ),
    )


def test_native_scan_uses_one_fixed_stage_graph_for_passive_and_active_policy():
    passive = _build(_plan(), {})
    active = _build(_plan(active=True, network=True), {})

    assert [item["name"] for item in passive.stage_rows()] == list(NATIVE_SCAN_STAGES)
    assert [item["name"] for item in active.stage_rows()] == list(NATIVE_SCAN_STAGES)
    assert passive.stage_rows()[3]["enabled"] is False
    assert passive.stage_rows()[5]["enabled"] is False
    assert active.stage_rows()[3]["enabled"] is True
    assert active.stage_rows()[5]["enabled"] is True
    assert passive.payload()["runtime_budget"]["tcp_ports_attempted"] == 1
    assert validate_native_scan_execution_payload(active.payload()) == active.payload()

    discovery = _build(
        _plan(active=True, network=True), {"discovery_manifest_only": True},
    )
    assert discovery.stage_rows()[3] == {
        "name": "discover_network",
        "enabled": False,
        "reason": "discovery_manifest_only",
    }
    assert active.normalize_options({})["network_discovery"] is False


def test_placed_discovery_shard_owns_network_stage_outside_scanner_subprocess():
    plan = _plan(active=True, network=True)
    authority = ScanShardAuthority(
        parent_scan_id="parent-1",
        parent_execution_plan_digest=plan.digest,
        options_digest="d" * 64,
        shard_index=-1,
        shard_count=0,
        shard_label="discovery",
        sub_budget=ScanShardBudget(120, 50, 10, 0, 10, 60, 1),
        parallel_discovery=True,
    )
    execution = _build(plan, {
        "canonical_shard_authority": authority.payload(),
        "parallel_discovery": True,
        "skip_global_checks": True,
    })

    assert execution.stage_rows()[3] == {
        "name": "discover_network",
        "enabled": True,
        "reason": "worker_capability_stage",
    }
    assert execution.normalize_options({})["network_discovery"] is False


def test_native_scan_removes_legacy_behavior_selectors_after_admission():
    execution = _build(_plan(active=True), {
        "scan_type": "compatibility-value",
        "quick": True,
        "thorough": True,
        "exploit_depth": True,
        "nuclei": True,
        "oob_callback_url": "https://callback.invalid",
        "sqli_extract_max": 999,
        "custom_endpoints": ["GET /v1/items"],
    })
    normalized = execution.normalize_options({
        "scan_type": "compatibility-value",
        "quick": True,
        "thorough": True,
        "exploit_depth": True,
        "nuclei": True,
        "oob_callback_url": "https://callback.invalid",
        "sqli_extract_max": 999,
        "custom_endpoints": ["GET /v1/items"],
    })

    assert not {
        "scan_type", "quick", "thorough", "exploit_depth", "nuclei",
        "oob_callback_url", "sqli_extract_max",
    } & set(normalized)
    assert normalized["active"] is True
    assert normalized["custom_endpoints"] == ["GET /v1/items"]
    assert normalized["native_scan_execution"]["execution_plan_digest"] == execution.execution_plan.digest


def test_native_scan_rejects_internal_family_assignment_outside_policy():
    with pytest.raises(NativeScanExecutionError, match="exceeds canonical Scan policy"):
        _build(
            _plan(active=True, include=("sqli",)),
            {"asm_check_family": "xss"},
        )

    allowed = _build(
        _plan(active=True, include=("sqli",), exclude=("xss",)),
        {"asm_check_family": "sqli"},
    )
    assert allowed.focused_family == "sqli"


def test_native_scan_execution_tampering_fails_closed():
    payload = _build(_plan(), {}).payload()
    changed = copy.deepcopy(payload)
    changed["stages"][2]["enabled"] = False
    with pytest.raises(NativeScanExecutionError, match="digest"):
        validate_native_scan_execution_payload(changed)


def test_native_scan_envelope_binds_reserved_runtime_budget():
    execution = _build(_plan(active=True), {}).with_runtime_budget({
        "http_requests": 80,
        "state_changing_requests": 3,
        "browser_actions": 4,
        "tcp_ports_attempted": 0,
        "hosts_attempted": 20,
        "tool_wall_seconds": 45,
    })
    payload = execution.payload()
    normalized = execution.normalize_options({})

    assert payload["runtime_budget"]["http_requests"] == 80
    assert normalized["custom_budget"]["request_max"] == 80
    assert normalized["custom_budget"]["browser_max_pages"] == 4
    assert normalized["custom_budget"]["max_urls"] == 20
    assert normalized["custom_budget"]["phase4_max_seconds"] == 45
    assert normalized["request_budget_reserved"] == 80
    assert validate_native_scan_execution_payload(payload) == payload

    with pytest.raises(NativeScanExecutionError, match="exceeds its authority"):
        execution.with_runtime_budget({
            **payload["runtime_budget"],
            "http_requests": 5_001,
        })

    with pytest.raises(NativeScanExecutionError, match="exceeds HTTP"):
        execution.with_runtime_budget({
            **payload["runtime_budget"],
            "http_requests": 2,
            "state_changing_requests": 3,
        })

    with pytest.raises(NativeScanExecutionError, match="target binding"):
        build_native_scan_execution(_plan(), {})

    changed = copy.deepcopy(payload)
    changed["target_binding"]["allowed_origins"] = ["https://other.test"]
    changed["execution_digest"] = payload["execution_digest"]
    with pytest.raises(NativeScanExecutionError, match="digest"):
        validate_native_scan_execution_payload(changed)


def test_native_scan_binds_shard_sub_budget_and_rejects_scope_coercion():
    plan = _plan(active=True)
    authority = ScanShardAuthority(
        parent_scan_id="parent-1",
        parent_execution_plan_digest=plan.digest,
        options_digest="a" * 64,
        shard_index=0,
        shard_count=2,
        shard_label="sqli:0",
        sub_budget=ScanShardBudget(300, 250, 100, 0, 0, 120, 1),
    )
    execution = _build(plan, {
        "canonical_shard_authority": authority.payload(),
        "asm_check_family": "sqli",
        "skip_global_checks": True,
        "focused_endpoints_only": True,
        "zero_rediscovery": True,
    })

    assert execution.payload()["execution_budget"] == authority.sub_budget.payload()
    assert execution.normalize_options({})["custom_budget"]["request_max"] == 250
    assert validate_native_scan_execution_payload(execution.payload()) == execution.payload()

    with pytest.raises(NativeScanExecutionError, match="must be a boolean"):
        _build(plan, {"skip_global_checks": "false"})


def test_native_scan_envelope_reuses_plan_ceiling_validation():
    payload = _build(_plan(), {}).payload()
    changed = copy.deepcopy(payload)
    changed["execution_plan"]["budget"]["max_workers"] = 129
    changed["execution_plan_digest"] = "0" * 64
    core = {key: value for key, value in changed.items() if key != "execution_digest"}
    import hashlib
    import json
    changed["execution_digest"] = hashlib.sha256(json.dumps(
        core, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")).hexdigest()

    with pytest.raises(NativeScanExecutionError, match="between 1 and 128"):
        validate_native_scan_execution_payload(changed)

    changed = copy.deepcopy(payload)
    changed["execution_plan"]["budget"]["max_http_requests"] += 1
    changed["execution_digest"] = payload["execution_digest"]
    with pytest.raises(NativeScanExecutionError, match="digest"):
        validate_native_scan_execution_payload(changed)
