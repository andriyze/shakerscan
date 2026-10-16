"""A verify Scan runs exactly the checks an Exposure candidate names, and nothing else active."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from runtime.models import ScanPolicy
from scan import verify_admission, verify_templates
from scan.nuclei_template_index import clear_index_cache, resolve_active_nuclei_selection
from scan.work_manifests import (
    CANONICAL_NUCLEI_TEMPLATE_BUNDLE_COMMIT,
    CANONICAL_NUCLEI_TEMPLATE_BUNDLE_SHA256,
    ScanWorkManifestError,
    build_canonical_scan_nuclei_template_manifest,
    build_template_manifest,
    canonical_nuclei_options_for_manifest,
)
import tests.test_nuclei_active_batch_wiring as wiring

FIXTURES = wiring.FIXTURES
VERIFY = ("django-debug-exposure", "put-method-enabled", "squid-analysis-report-generator")


def _verify_manifest(ids=VERIFY):
    return build_canonical_scan_nuclei_template_manifest(
        scan_id="11111111-1111-4111-8111-111111111111", target_binding_digest=wiring.TARGET.digest,
        include_active=True, verify_template_ids=ids,
    )


def test_verify_manifest_replaces_the_active_pack_with_the_named_checks():
    manifest = _verify_manifest()
    ids = {entry["template_id"] for entry in manifest.entries}
    assert set(VERIFY) <= ids
    assert "nuclei-active-safe-v1" not in ids and all("canonical" not in i for i in ids)
    options = canonical_nuclei_options_for_manifest(manifest, action_id="active.templates")
    assert options["verify_template_ids"] == ",".join(sorted(VERIFY))
    assert options["severity"] == "info,low,medium,high,critical"
    # The passive baseline is unchanged by a verify request.
    passive = canonical_nuclei_options_for_manifest(manifest, action_id="passive.templates")
    assert "verify_template_ids" not in passive


def test_a_verify_entry_not_bound_to_the_pinned_bundle_is_refused():
    manifest = _verify_manifest(("squid-analysis-report-generator",))
    rows = [dict(entry) for entry in manifest.entries]
    for row in rows:
        if list(row["tags"]) == ["cve-verify"]:
            row["template_digest"] = "0" * 64
    forged = build_template_manifest(
        scan_id=manifest.scan_id, target_binding_digest=manifest.target_binding_digest,
        source_action_ids=manifest.source_action_ids, templates=rows, batch_size=len(rows),
    )
    with pytest.raises(ScanWorkManifestError):
        canonical_nuclei_options_for_manifest(forged, action_id="active.templates")


def test_verify_entries_cannot_ride_along_with_the_active_pack():
    normal = build_canonical_scan_nuclei_template_manifest(
        scan_id="11111111-1111-4111-8111-111111111111", target_binding_digest=wiring.TARGET.digest,
        include_active=True,
    )
    rows = [dict(entry) for entry in normal.entries] + verify_templates.verify_template_rows(
        ["squid-analysis-report-generator"], bundle_commit=CANONICAL_NUCLEI_TEMPLATE_BUNDLE_COMMIT,
        bundle_sha256=CANONICAL_NUCLEI_TEMPLATE_BUNDLE_SHA256)
    mixed = build_template_manifest(
        scan_id=normal.scan_id, target_binding_digest=normal.target_binding_digest,
        source_action_ids=normal.source_action_ids, templates=rows, batch_size=len(rows),
    )
    with pytest.raises(ScanWorkManifestError):
        canonical_nuclei_options_for_manifest(mixed, action_id="active.templates")


def test_exact_selection_still_drops_intrusive_and_unauthorized_mutating_templates():
    clear_index_cache()
    selection = resolve_active_nuclei_selection(
        str(FIXTURES), allow_state_changing_http=False, only_template_ids=",".join(VERIFY))
    assert selection.template_ids == ("squid-analysis-report-generator",)
    assert selection.intrusive_excluded == 1
    authorized = resolve_active_nuclei_selection(
        str(FIXTURES), allow_state_changing_http=True, only_template_ids=",".join(VERIFY))
    assert set(authorized.template_ids) == {"django-debug-exposure", "squid-analysis-report-generator"}
    missing = resolve_active_nuclei_selection(
        str(FIXTURES), allow_state_changing_http=True, only_template_ids="cve-2099-0001")
    assert missing.skip and missing.skip_reason == "no_eligible_nuclei_templates"


def _drive_verify(monkeypatch, ids, **kwargs):
    monkeypatch.setattr(
        wiring, "build_canonical_nuclei_template_manifest",
        lambda scan_id, target_binding_digest: build_canonical_scan_nuclei_template_manifest(
            scan_id=scan_id, target_binding_digest=target_binding_digest,
            include_active=True, verify_template_ids=ids),
    )
    clear_index_cache()
    return wiring._drive(monkeypatch, **kwargs)


def test_verify_scan_worker_receives_only_the_named_get_checks(monkeypatch):
    receipt, captured = _drive_verify(
        monkeypatch, VERIFY,
        policy=ScanPolicy(active_testing=True, approval_receipt_id="approval-1"),
        requested_budget={"http_requests": 120, "tool_wall_seconds": 45},
    )
    assert receipt.status == "success"
    assert captured["scanner_options"]["template_ids"] == "squid-analysis-report-generator"
    assert captured["scanner_options"]["nuclei_active_state_changing"] is False


def test_verify_scan_with_state_changing_authority_runs_the_named_post_check(monkeypatch):
    receipt, captured = _drive_verify(
        monkeypatch, ("django-debug-exposure",),
        policy=ScanPolicy(active_testing=True, allow_state_changing_http=True, approval_receipt_id="approval-1"),
        requested_budget={"http_requests": 120, "state_changing_requests": 120, "tool_wall_seconds": 45},
    )
    assert receipt.status == "success"
    assert captured["scanner_options"]["template_ids"] == "django-debug-exposure"


def test_verify_scan_whose_check_is_absent_from_the_bundle_records_a_gap(monkeypatch):
    receipt, _captured = _drive_verify(
        monkeypatch, ("cve-2099-0001",),
        policy=ScanPolicy(active_testing=True, approval_receipt_id="approval-1"),
        requested_budget={"http_requests": 120, "tool_wall_seconds": 45},
    )
    assert receipt.status == "skipped"
    assert "no_eligible_nuclei_templates" in receipt.errors


def _plan(active=True, families=("nuclei_passive", "nuclei_active")):
    return SimpleNamespace(
        policy=ScanPolicy(active_testing=active, include_families=tuple(families)),
        resolved_families=tuple(families),
    )


def _snapshot():
    return {"status": "available", "snapshot_sha256": "a" * 64, "advisories": [
        {"cve": "CVE-2021-41773", "checks": [{"kind": "nuclei_template", "id": "cve-2021-41773"}]},
    ]}


def _admit(values, plan):
    verify_admission._CHECK_IDS.clear()
    return asyncio.run(verify_admission.admit_verify_templates(values, plan, load_snapshot=_snapshot))


def test_admission_accepts_only_known_checks_on_an_active_template_scan():
    assert _admit([], _plan()) == {}
    assert _admit(["CVE-2021-41773"], _plan()) == {"verify_templates": ["cve-2021-41773"]}
    for values, plan, error in (
        (["cve-2021-41773"], _plan(active=False), "verify_templates_need_active_templates"),
        (["cve-2021-41773"], _plan(families=("nuclei_passive",)), "verify_templates_need_active_templates"),
        (["http-missing-security-headers"], _plan(), "verify_templates_not_a_known_check"),
        (["../etc/passwd"], _plan(), "verify_templates_invalid"),
        ([f"cve-2021-{n}" for n in range(11)], _plan(), "verify_templates_invalid"),
        ("cve-2021-41773", _plan(), "verify_templates_invalid"),
    ):
        with pytest.raises(HTTPException) as refused:
            _admit(values, plan)
        assert refused.value.status_code == 422
        assert refused.value.detail["error"] == error


def test_a_verify_scan_compiles_one_active_template_step_bound_to_its_verify_manifest():
    import tests.test_scan_action_compiler as compiler_tests

    manifest = compiler_tests.build_canonical_scan_nuclei_template_manifest(
        scan_id=compiler_tests.SCAN_ID, target_binding_digest=compiler_tests._target().digest,
        include_active=True, verify_template_ids=("squid-analysis-report-generator",),
    )
    plan = compiler_tests.ScanActionPlanCompiler().compile(
        scan_id=compiler_tests.SCAN_ID,
        execution_plan=compiler_tests._execution(include=("nuclei_active",)),
        target_binding=compiler_tests._target(),
        template_manifest_ref=manifest.reference().canonical_dict(),
    )
    active = [item for item in plan.actions if item.capability_name == "templates.active_batch"]
    assert active and all(
        item.capability_args["template_manifest_ref"] == manifest.reference().canonical_dict()
        for item in active)
    assert not any(item.capability_name.startswith(("xss.", "sqli.")) for item in plan.actions)


def test_shard_children_rebuild_the_same_verify_set():
    from runtime.models import TargetBinding
    from scan.contracts import resolve_scan_contract
    from scan.jobs import CanonicalScanJob
    import worker

    contract = resolve_scan_contract(budget_profile="fast", policy={
        "active_testing": True, "preset": "custom", "include_families": ["nuclei_active"]})
    parent = CanonicalScanJob.create(
        job_id="parent-job", scan_id="parent-scan", execution_plan=contract.execution_plan,
        target=TargetBinding(
            target_id="target-1", target_kind="web", canonical_host="example.test",
            allowed_origins=("https://example.test",), allowed_addresses=("192.0.2.10",),
            allowed_root_domains=("example.test",)),
    )
    options, manifests = worker._compile_parallel_child_work_manifests(
        child_scan_id="22222222-2222-4222-8222-222222222223", target_url="https://example.test",
        parent_job=parent, selected_shard=1, endpoints=("GET /",),
        child_options={"custom_budget": {"request_max": 50, "max_urls": 20},
                       "verify_templates": ["squid-analysis-report-generator"]},
    )
    templates = manifests[-1]
    assert options["template_manifest_ref"] == templates.reference().canonical_dict()
    assert canonical_nuclei_options_for_manifest(templates, action_id="active.templates")[
        "verify_template_ids"] == "squid-analysis-report-generator"


OOB_ONLY_TEMPLATE = """\
# Test fixture (not an upstream template): a check that can only match through an
# out-of-band interaction, which Scan never enables (-no-interactsh).
id: oob-only-check
info:
  name: OOB-only check fixture
  author: shakerscan-tests
  severity: critical
  tags: cve,oast,fixture
http:
  - method: GET
    path:
      - "{{BaseURL}}/?callback={{interactsh-url}}"
    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "dns"
"""


def test_a_check_that_needs_out_of_band_interaction_is_never_run_as_a_verify_check(tmp_path):
    import shutil

    shutil.copytree(FIXTURES, tmp_path / "templates")
    (tmp_path / "templates" / "http" / "oob-only-check.yaml").write_text(OOB_ONLY_TEMPLATE)
    clear_index_cache()
    only_oob = resolve_active_nuclei_selection(
        str(tmp_path / "templates"), allow_state_changing_http=True, only_template_ids="oob-only-check")
    assert only_oob.skip and only_oob.skip_reason == "verify_checks_need_oob_interaction"
    mixed = resolve_active_nuclei_selection(
        str(tmp_path / "templates"), allow_state_changing_http=False,
        only_template_ids="oob-only-check,squid-analysis-report-generator")
    assert mixed.template_ids == ("squid-analysis-report-generator",) and mixed.oob_excluded == 1
    # The general active pack is unchanged: OOB templates are only dropped for a verify Scan.
    general = resolve_active_nuclei_selection(
        str(tmp_path / "templates"), allow_state_changing_http=False, tags="oast", severities="critical")
    assert general.template_ids == ("oob-only-check",)
    clear_index_cache()
