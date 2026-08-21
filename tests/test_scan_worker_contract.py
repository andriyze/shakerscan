from __future__ import annotations

import copy
import os
import sys

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from scan.contracts import resolve_scan_contract
from scan.worker_contract import (
    WorkerScanContractError,
    resolve_worker_scan_admission,
)


def _options(*, active=False, network=False, subdomains=False, state_change=False):
    approval = "approval-1" if network or state_change else None
    contract = resolve_scan_contract(
        budget_profile="balanced",
        policy={
            "active_testing": active,
            "network_discovery": network,
            "subdomain_discovery": subdomains,
            "allow_state_changing_http": state_change,
        },
        approval_receipt_id=approval,
    )
    result = contract.option_metadata()
    result["scan_type"] = contract.execution_scan_type
    return result


def test_passive_canonical_job_is_admitted_as_one_scan_with_deep_backing():
    admission = resolve_worker_scan_admission(_options())
    assert admission.canonical is True
    assert admission.plan is not None
    assert admission.plan.engine == "scan"
    assert admission.backing_scan_type == "deep"
    assert admission.canonical_overrides() == {
        "scan_type": "deep",
        "active": False,
        "network_discovery": False,
        "subfinder": False,
        "budget_profile": "balanced",
        "quick": False,
        "thorough": False,
    }


def test_active_canonical_job_derives_full_backing_from_policy_only():
    options = _options(active=True, network=True, subdomains=True)
    admission = resolve_worker_scan_admission(options)
    assert admission.backing_scan_type == "full"
    normalized = admission.normalize_options({**options, "custom_endpoints": ["/api"]})
    assert normalized["scan_type"] == "full"
    assert normalized["active"] is True
    assert normalized["network_discovery"] is True
    assert normalized["subfinder"] is True
    assert normalized["custom_endpoints"] == ["/api"]


def test_any_v2_marker_requires_the_complete_contract_and_prevents_downgrade():
    with pytest.raises(WorkerScanContractError, match="incomplete"):
        resolve_worker_scan_admission({"scan_generation": "v2", "scan_type": "deep"})
    with pytest.raises(WorkerScanContractError, match="incomplete"):
        resolve_worker_scan_admission({"scan_execution_plan": {}, "scan_type": "standard"})


def test_plan_or_digest_tampering_is_rejected():
    options = _options()
    changed = copy.deepcopy(options)
    changed["scan_execution_plan"]["budget"]["max_http_requests"] += 1
    with pytest.raises(WorkerScanContractError, match="digest mismatch"):
        resolve_worker_scan_admission(changed)

    changed = copy.deepcopy(options)
    changed["scan_execution_plan_digest"] = "0" * 64
    with pytest.raises(WorkerScanContractError, match="digest mismatch"):
        resolve_worker_scan_admission(changed)


def test_recomputed_oversized_plan_is_rejected_by_worker_ceiling():
    options = _options()
    changed = copy.deepcopy(options)
    changed["scan_execution_plan"]["budget"]["max_workers"] = 129
    changed["resolved_scan_budget"]["max_workers"] = 129
    with pytest.raises(WorkerScanContractError, match="max_workers must be between"):
        resolve_worker_scan_admission(changed)


def test_flattened_snapshots_and_compatibility_alias_must_match_plan():
    options = _options(active=True)
    changed = copy.deepcopy(options)
    changed["scan_policy"]["active_testing"] = False
    with pytest.raises(WorkerScanContractError, match="flattened scan_policy"):
        resolve_worker_scan_admission(changed)

    changed = copy.deepcopy(options)
    changed["resolved_scan_budget"]["max_workers"] = 3
    with pytest.raises(WorkerScanContractError, match="flattened resolved_scan_budget"):
        resolve_worker_scan_admission(changed)

    changed = copy.deepcopy(options)
    changed["scan_compatibility"]["legacy_executor_alias"] = "deep"
    with pytest.raises(WorkerScanContractError, match="scan_compatibility"):
        resolve_worker_scan_admission(changed)


def test_caller_cannot_reintroduce_smart_aggressive_or_quick_execution():
    active = _options(active=True)
    active["scan_type"] = "smart"
    with pytest.raises(WorkerScanContractError, match="caller-controlled scan_type"):
        resolve_worker_scan_admission(active)

    passive = _options()
    passive["quick"] = True
    with pytest.raises(WorkerScanContractError, match="quick/thorough"):
        resolve_worker_scan_admission(passive)


def test_unknown_plan_policy_and_budget_fields_fail_closed():
    for section, field in (
        ("scan_execution_plan", "secret_mode"),
        ("policy", "planner_override"),
        ("budget", "unlimited_requests"),
    ):
        options = _options()
        changed = copy.deepcopy(options)
        target = changed["scan_execution_plan"]
        if section != "scan_execution_plan":
            target = target[section]
        target[field] = True
        with pytest.raises(WorkerScanContractError, match="fields are invalid"):
            resolve_worker_scan_admission(changed)


def test_state_changing_and_network_authority_fail_closed_at_worker_boundary():
    options = _options(active=True, state_change=True)
    changed = copy.deepcopy(options)
    changed["scan_execution_plan"]["policy"]["approval_receipt_id"] = None
    changed["scan_policy"]["approval_receipt_id"] = None
    with pytest.raises(WorkerScanContractError, match="approval receipt"):
        resolve_worker_scan_admission(changed)

    options = _options(active=True, network=True)
    changed = copy.deepcopy(options)
    changed["scan_execution_plan"]["policy"]["active_testing"] = False
    with pytest.raises(WorkerScanContractError, match="network_discovery requires active_testing"):
        resolve_worker_scan_admission(changed)


def test_public_and_flattened_legacy_flags_cannot_conflict_with_plan():
    options = _options(active=True)
    options["public"] = True
    with pytest.raises(WorkerScanContractError, match="public execution"):
        resolve_worker_scan_admission(options)

    options = _options(active=True)
    options["active"] = False
    with pytest.raises(WorkerScanContractError, match="active conflicts"):
        resolve_worker_scan_admission(options)


def test_legacy_jobs_remain_isolated_and_do_not_claim_canonical_authority():
    legacy = resolve_worker_scan_admission({"scan_type": "smart"})
    assert legacy.canonical is False
    assert legacy.backing_scan_type == "smart"
    assert legacy.plan is None
    assert legacy.canonical_overrides() == {}

    default = resolve_worker_scan_admission({})
    assert default.canonical is False
    assert default.backing_scan_type == "standard"


def test_legacy_source_metadata_must_agree_with_translated_plan():
    contract = resolve_scan_contract(legacy_scan_type="smart")
    options = contract.option_metadata()
    options["scan_type"] = contract.execution_scan_type
    admission = resolve_worker_scan_admission(options)
    assert admission.legacy_source == "smart"
    assert admission.backing_scan_type == "full"

    changed = copy.deepcopy(options)
    changed["legacy_scan_type"] = "quick"
    with pytest.raises(WorkerScanContractError, match="legacy_scan_type metadata conflicts"):
        resolve_worker_scan_admission(changed)
