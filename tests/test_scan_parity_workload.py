"""The parity gate must actually compare the active work it claims to compare.

Setting only ``active_testing`` leaves the preset at its passive default, so a
policy that excludes both Nuclei families resolves to recon alone. The gate then
compares two recon-only scans: it cannot detect active parity drift, and it
passes for exactly the topology it exists to qualify.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

from api.scan.contracts import SCAN_V2_FAMILY_NAMES, resolve_scan_contract


_SCRIPT = Path(__file__).resolve().parent / "e2e" / "run_scan_parity.py"


def _families():
    source = _SCRIPT.read_text(encoding="utf-8")
    namespace: dict = {}
    start = source.index("PARITY_ACTIVE_FAMILIES = [")
    end = source.index("]", start) + 1
    exec(source[start:end], namespace)
    return list(namespace["PARITY_ACTIVE_FAMILIES"])


def test_the_parity_lane_declares_only_canonical_families():
    unknown = sorted(set(_families()) - set(SCAN_V2_FAMILY_NAMES))
    assert not unknown, f"parity lane names families the contract cannot run: {unknown}"


def test_the_parity_lane_resolves_to_real_active_work():
    contract = resolve_scan_contract(
        budget_profile="balanced",
        policy={
            "active_testing": True,
            "allow_state_changing_http": True,
            "preset": "custom",
            "include_families": _families(),
            "exclude_families": [],
        },
        approval_receipt_id="a" * 32,
    )
    resolved = set(contract.policy.include_families)
    # Recon alone is the failure mode this guard exists for.
    assert resolved != {"recon"}
    for family in ("xss", "sqli"):
        assert family in resolved, f"parity lane does not exercise {family}"


def test_active_testing_alone_still_resolves_to_the_passive_preset():
    """Documents why the explicit preset is required, not incidental."""
    contract = resolve_scan_contract(
        budget_profile="balanced",
        policy={
            "active_testing": True,
            "allow_state_changing_http": True,
            "exclude_families": ["nuclei_passive", "nuclei_active", "bola"],
        },
        approval_receipt_id="a" * 32,
    )
    assert contract.policy.include_families == ("recon",)
    assert contract.execution_plan.family_preset == "passive"


def test_the_submitted_parity_policy_is_the_declared_one():
    """The submission must carry the exact include list, not rebuild its own."""
    source = _SCRIPT.read_text(encoding="utf-8")
    submit = source[source.index("def _submit("):source.index("def _completed(")]
    assert '"preset": "custom"' in submit
    assert '"include_families": PARITY_ACTIVE_FAMILIES' in submit
