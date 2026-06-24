"""R6a: three-tier probe production-safety classification + effective filter.

Before this, every probe defaulted safe_for_production=True, so the planner's
production filter removed nothing. Now the tier is derived and the filter
actually drops non_production_only probes in production mode.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from ai_gate.models import Probe  # noqa: E402
from ai_gate.planner import classify_production_safety, plan_probe_pack  # noqa: E402


def _p(**kw):
    base = {"id": "p", "family": "x", "title": "t", "prompt": "hi"}
    base.update(kw)
    return Probe(**base)


def test_classify_tiers():
    assert classify_production_safety(_p(family="tool_abuse", technique="dangerous_tool_execute")) == "non_production_only"
    assert classify_production_safety(_p(family="misc", technique="memory_write")) == "non_production_only"
    assert classify_production_safety(_p(safe_for_production=False)) == "non_production_only"
    assert classify_production_safety(_p(family="prompt_injection", technique="direct_override")) == "production_review"
    assert classify_production_safety(_p(family="misc", severity_if_success="critical")) == "production_review"
    assert classify_production_safety(_p(family="prompt_leakage", technique="direct_question", severity_if_success="low")) == "production_safe"


def test_production_filter_is_effective():
    prod = plan_probe_pack("shaker-agent-abuse", "standard", production_mode=True)
    nonprod = plan_probe_pack("shaker-agent-abuse", "standard", production_mode=False)
    # The whole point of R6a: the filter actually removes something now.
    assert prod.manifest["blocked_for_production_count"] >= 1
    assert len(prod.probes) < len(nonprod.probes)
    blocked = set(prod.manifest["blocked_for_production_probe_ids"])
    assert blocked and blocked.isdisjoint({p.id for p in prod.probes})
    assert nonprod.manifest["blocked_for_production_count"] == 0


def test_manifest_reports_safety_tiers():
    plan = plan_probe_pack("shaker-agent-abuse", "standard")
    tiers = plan.manifest["production_safety_tiers"]
    assert set(tiers) == {"production_safe", "production_review", "non_production_only"}
    # tiers partition every planned probe (non-production: nothing blocked)
    assert sum(tiers.values()) == len(plan.probes)
    assert "production_review_probe_ids" in plan.manifest
