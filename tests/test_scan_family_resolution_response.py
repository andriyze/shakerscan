"""Preview and submission say how include_families resolved (soak N45).

`include_families` adds to the preset, named or implied, and is exact only under `custom`
(tests/test_scan_v2_contract.py pins that contract). A client that sent `active_testing: true`
with `include_families: ["sensitive_exposure"]`, meaning "only exposure", got the standard active
set -- XSS and SQLi included, the most intrusive families -- and the only hint in the response
was `preset: standard_active`. Both responses now return the resolved families, the mode and
the families the preset added.
"""

from __future__ import annotations

import asyncio

from api.scan.contracts import resolve_scan_contract
from api.scan.read_router import ScanFamilyPreviewRequest, preview_scan_contract


def _preview(**policy):
    return asyncio.run(preview_scan_contract(ScanFamilyPreviewRequest(**policy)))


def test_an_implied_preset_states_the_families_it_added():
    preview = _preview(active_testing=True, include_families=["sensitive_exposure"])
    assert preview["preset"] == preview["family_preset"] == "standard_active"
    assert preview["requested_families"] == ["sensitive_exposure"]
    assert preview["resolved_families"] == [
        "recon", "nuclei_passive", "xss", "sqli", "sensitive_exposure",
    ]
    assert preview["include_families_mode"] == "added_to_preset"
    assert preview["families_added_by_preset"] == ["recon", "nuclei_passive", "xss", "sqli"]


def test_custom_is_exact_and_adds_nothing():
    preview = _preview(
        active_testing=True, preset="custom", include_families=["sensitive_exposure"],
    )
    assert preview["resolved_families"] == ["sensitive_exposure"]
    assert preview["include_families_mode"] == "exact"
    assert preview["families_added_by_preset"] == []


def test_the_resolved_families_are_always_returned():
    for policy in ({}, {"active_testing": True}, {"preset": "passive"}):
        preview = _preview(**policy)
        assert preview["resolved_families"], policy
        assert preview["families_added_by_preset"] == preview["resolved_families"]


def test_submission_returns_the_same_resolution_as_preview():
    from api.scan.contracts import scan_family_resolution

    contract = resolve_scan_contract(policy={
        "active_testing": True, "include_families": ["sensitive_exposure"],
    })
    assert scan_family_resolution(contract) == {
        "family_preset": "standard_active",
        "requested_families": ["sensitive_exposure"],
        "resolved_families": ["recon", "nuclei_passive", "xss", "sqli", "sensitive_exposure"],
        "include_families_mode": "added_to_preset",
        "families_added_by_preset": ["recon", "nuclei_passive", "xss", "sqli"],
    }


def test_the_submit_response_spreads_the_resolution():
    """`POST /scans` builds its response in api.py; the resolution is part of it."""
    from pathlib import Path

    source = Path(__file__).resolve().parents[1].joinpath("api", "api.py").read_text()
    assert "'budget_profile': scan_contract.budget_profile, **scan_family_resolution(scan_contract)," in source
