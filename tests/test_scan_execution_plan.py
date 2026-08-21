from __future__ import annotations

import json
import os
import sys

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from runtime.models import ScanBudget, ScanPolicy
from scan.execution import (
    SCAN_ENGINE,
    SCAN_EXECUTION_SCHEMA,
    ScanExecutionPlan,
)


def _budget(**overrides):
    values = {
        "max_duration_seconds": 1_200,
        "max_http_requests": 5_000,
        "max_endpoints": 2_000,
        "max_browser_actions": 200,
        "max_tcp_ports": 5_000,
        "max_tool_wall_seconds": 900,
        "max_workers": 4,
    }
    values.update(overrides)
    return ScanBudget(**values)


def test_plan_is_json_safe_stable_and_has_one_engine_identity():
    plan = ScanExecutionPlan(
        policy=ScanPolicy(include_families=("xss", "sqli")),
        budget_profile="balanced",
        budget=_budget(),
    )
    public = plan.canonical_dict()
    encoded = json.dumps(public, sort_keys=True)

    assert public["schema_version"] == SCAN_EXECUTION_SCHEMA
    assert public["engine"] == SCAN_ENGINE == "scan"
    assert public["policy"]["include_families"] == ["xss", "sqli"]
    assert len(plan.digest) == 64
    assert plan.digest == ScanExecutionPlan(
        policy=ScanPolicy(include_families=("xss", "sqli")),
        budget_profile="balanced",
        budget=_budget(),
    ).digest
    assert "quick" not in encoded
    assert "standard" not in encoded
    assert "deep" not in encoded
    assert "full" not in encoded
    assert "aggressive" not in encoded
    assert "smart" not in encoded


def test_policy_and_budget_changes_change_digest_without_changing_engine():
    passive = ScanExecutionPlan(ScanPolicy(), "balanced", _budget())
    active = ScanExecutionPlan(
        ScanPolicy(active_testing=True, approval_receipt_id="approval-1"),
        "balanced",
        _budget(),
    )
    larger = ScanExecutionPlan(
        ScanPolicy(), "balanced", _budget(max_http_requests=7_500)
    )

    assert {passive.engine, active.engine, larger.engine} == {"scan"}
    assert len({passive.digest, active.digest, larger.digest}) == 3


def test_plan_rejects_alternate_engine_or_schema_identity():
    with pytest.raises(ValueError, match="engine"):
        ScanExecutionPlan(ScanPolicy(), "balanced", _budget(), engine="smart")
    with pytest.raises(ValueError, match="schema_version"):
        ScanExecutionPlan(
            ScanPolicy(), "balanced", _budget(), schema_version="scan-execution-plan/v2"
        )
    with pytest.raises(ValueError, match="budget_profile"):
        ScanExecutionPlan(ScanPolicy(), "", _budget())
