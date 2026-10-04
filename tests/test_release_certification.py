from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.certify_release_receipt import CertificationError, certify_receipt
from scripts.release_deployment_subject import BINDING_SCHEMA, SNAPSHOT_SCHEMA, bind_receipt
from scripts.release_image_inventory import RELEASE_IMAGES
from scripts.validate_promotion_receipt import (
    PromotionReceiptError,
    validate_certification_checks,
)


SOURCE = "a" * 40
IMAGES = {
    name: f"sha256:{index:064x}"
    for index, name in enumerate(("scanner", "api", "ui", "signer", "model_intake"), start=1)
}


def _write(tmp_path: Path, name: str, value: dict) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _deployment_binding(revision: str = SOURCE) -> dict:
    snapshot = {
        "schema_version": SNAPSHOT_SCHEMA, "verification": "docker_inspect",
        "source_revision": revision, "version": "9.9.9", "image_built": True,
        "images": IMAGES,
        "image_inspections": {
            image["key"]: {
                "image_id": f"sha256:{index + 100:064x}",
                "repo_digests": [f"{image['repository']}@{IMAGES[image['key']]}"]
            } for index, image in enumerate(RELEASE_IMAGES)
        },
        "containers": [{
            "service": image["compose_services"][0], "container_id": f"{index + 200:064x}",
            "image_id": f"sha256:{index + 100:064x}", "running": True,
        } for index, image in enumerate(RELEASE_IMAGES)],
    }
    return {"schema_version": BINDING_SCHEMA, "before": snapshot, "after": snapshot}


def _fault_subject(revision: str = SOURCE) -> dict:
    """The identity a fault producer reads from the API image's release manifest."""
    return {
        "schema_version": "shakerscan-fault-receipt-subject/v1",
        "source_revision": revision,
        "scanner_version": "9.9.9",
        "image_built": True,
        "images": IMAGES,
        "deployment_binding": _deployment_binding(revision),
    }


def _evidence(tmp_path: Path):
    candidate = {
        "schema_version": "shakerscan-release-candidate/v1",
        "runtime_manifest_sha256": "5" * 64,
        "version": "9.9.9",
        "candidate_sha": SOURCE,
        "candidate_tag": f"candidate-{SOURCE}-123",
        "images": IMAGES,
        "provenance": {"verified": True, "issuer": "github-actions-sigstore"},
    }
    checks = {
        "previous_stable_runtime_migrations_twice": "pass",
        "database_restart_preserved_state": "pass",
        "backup_restore_rollback_boundary": "pass",
    }
    upgrade = {
        "schema_version": "stateful-upgrade-acceptance/v2",
        "status": "pass",
        "baseline": {"version": "2.1.0"},
        "candidate": {
            "source_sha": SOURCE,
            "images": {key: IMAGES[key] for key in ("scanner", "api", "ui", "model_intake")},
        },
        "rollback_boundary": "pre-upgrade pg_dump restore",
        "checks": checks,
    }
    preservation = {
        "schema_version": "release-preservation-receipt/v1",
        "status": "pass",
        "source_sha": SOURCE,
        "images": dict(sorted(IMAGES.items())),
        "scope_exclusions": [],
    }
    e2e = {
        "schema_version": "shakerscan-e2e-scorecard/v1",
        "gate": "pass",
        # The subject the runner records from the live stack, so a scorecard cannot certify a
        # candidate it never tested.
        "subject": {
            "schema_version": "shakerscan-e2e-subject/v1",
            "source_revision": SOURCE,
            "images": dict(sorted(IMAGES.items())),
            "image_built": True,
            "deployment_binding": _deployment_binding(),
        },
        "areas": [
            {
                "area": area,
                "gate": "pass",
                "rows": ([{
                    "name": "H-18 adaptive real-target methodology produces a verified finding",
                    "passed": True,
                    "skipped": False,
                    "detail": "",
                }] if area == "hunt" else []),
            }
            for area in ("platform", "ai_gate", "dast", "hunt", "model_intake")
        ],
    }
    external_values = {
        "dast_quality": {
            "passed": True,
            "regression_gates_passed": True,
            "quality_bar_passed": True,
            "quality_bar_enforced": True,
            "release_quality_contract_passed": True,
            "quality_release_dispositions": [],
            # The benchmark reads the deployment it measured from the live API and records the
            # worker fleet it ran on; certification binds both to the candidate.
            "subject": {
                "schema_version": "shakerscan-benchmark-subject/v1",
                "source_revision": SOURCE,
                "identity_stable": True,
                "image_built": True,
                "images": IMAGES,
                "deployment_binding": _deployment_binding(),
            },
            "fleet_uniform": True,
        },
        "fault_cancellation": {
            "schema_version": "scan-cancellation-race-receipt/v1", "passed": True,
            "subject": _fault_subject(),
        },
        "fault_reservation_identity": {
            "schema_version": "scan-reservation-identity-receipt/v1", "passed": True,
            "subject": _fault_subject(),
        },
        "fault_action_resume": {
            "schema_version": "scan-action-resume-receipt/v1", "passed": True,
            "subject": _fault_subject(),
        },
        "real_fleet_parity": {
            "source_revision": SOURCE, "consistent": True,
            "all_artifacts_truthful": True,
        },
        "model_intake_physical": {"candidate_sha": SOURCE, "status": "pass"},
        "device_physical": {"candidate_sha": SOURCE, "status": "pass"},
    }
    external_evidence = {
        key: (value, _write(tmp_path, f"{key}.json", value))
        for key, value in external_values.items()
    }
    paths = {
        "candidate_path": _write(tmp_path, "candidate.json", candidate),
        "upgrade_path": _write(tmp_path, "upgrade.json", upgrade),
        "preservation_path": _write(tmp_path, "preservation.json", preservation),
        "e2e_path": _write(tmp_path, "e2e.json", e2e),
        "external_evidence": external_evidence,
    }
    return candidate, upgrade, preservation, e2e, paths


def test_certification_binds_exact_manifests_and_all_acceptance_evidence(tmp_path):
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    receipt = certify_receipt(
        candidate=candidate,
        upgrade=upgrade,
        preservation=preservation,
        e2e=e2e,
        source_sha=SOURCE,
        **paths,
    )
    assert receipt["schema_version"] == "shakerscan-release-candidate/v2"
    assert receipt["certification"]["status"] == "pass"
    assert receipt["certification"]["images"] == dict(sorted(IMAGES.items()))
    assert len(receipt["receipt_sha256"]) == 64
    assert set(receipt["certification"]["evidence_sha256"]) == {
        "uncertified_candidate_receipt",
        "stateful_upgrade_receipt_2_1_0",
        "preservation_receipt",
        "exact_manifest_e2e_scorecard",
        *paths["external_evidence"].keys(),
    }
    assert receipt["certification"]["checks"]["complete_dast_quality_bar"] == "pass"
    validate_certification_checks(receipt)


def test_release_cli_contract_requires_both_upgrade_baselines(tmp_path):
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    with pytest.raises(CertificationError, match="cover exactly these baselines"):
        certify_receipt(
            candidate=candidate,
            upgrade=upgrade,
            preservation=preservation,
            e2e=e2e,
            source_sha=SOURCE,
            required_upgrade_baselines={"2.1.0", "0.8.18"},
            **paths,
        )


def test_optional_physical_boundaries_are_recorded_as_not_run(tmp_path):
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    paths["external_evidence"].pop("real_fleet_parity")
    paths["external_evidence"].pop("model_intake_physical")
    paths["external_evidence"].pop("device_physical")
    receipt = certify_receipt(
        candidate=candidate,
        upgrade=upgrade,
        preservation=preservation,
        e2e=e2e,
        source_sha=SOURCE,
        **paths,
    )
    assert receipt["certification"]["scope_exclusions"] == [
        "real_fleet_parity", "model_intake_physical", "device_physical",
    ]
    assert receipt["certification"]["checks"]["real_fleet_parity"] == (
        "not_run_optional_boundary"
    )
    validate_certification_checks(receipt)


def test_promotion_rejects_unaccepted_or_mismatched_check_states(tmp_path):
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    receipt = certify_receipt(
        candidate=candidate, upgrade=upgrade, preservation=preservation, e2e=e2e,
        source_sha=SOURCE, **paths,
    )
    receipt["certification"]["checks"]["fault_cancellation"] = "accepted_shortfall"
    with pytest.raises(PromotionReceiptError, match="fault_cancellation"):
        validate_certification_checks(receipt)


def test_promotion_rejects_optional_not_run_without_matching_scope_exclusion(tmp_path):
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    receipt = certify_receipt(
        candidate=candidate, upgrade=upgrade, preservation=preservation, e2e=e2e,
        source_sha=SOURCE, **paths,
    )
    receipt["certification"]["checks"]["real_fleet_parity"] = (
        "not_run_optional_boundary"
    )
    with pytest.raises(PromotionReceiptError, match="scope exclusions"):
        validate_certification_checks(receipt)


def test_a_dast_shortfall_cannot_certify(tmp_path):
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    dast, dast_path = paths["external_evidence"]["dast_quality"]
    dast["quality_bar_passed"] = False
    dast["quality_release_dispositions"] = [{
        "status": "accepted_shortfall",
        "valid": True,
        "accepted_failed_gates": ["quality:min_expected_recall"],
        "observed_failed_gates": ["quality:min_expected_recall"],
    }]
    paths["external_evidence"]["dast_quality"] = (
        dast, _write(tmp_path, dast_path.name, dast),
    )
    with pytest.raises(CertificationError, match="complete DAST quality bar"):
        certify_receipt(
            candidate=candidate,
            upgrade=upgrade,
            preservation=preservation,
            e2e=e2e,
            source_sha=SOURCE,
            **paths,
        )


def test_release_owner_can_waive_a_measured_quality_shortfall_as_declared_debt(tmp_path):
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    dast, dast_path = paths["external_evidence"]["dast_quality"]
    # The shape --enforce-quality produces on a real shortfall: the bar was measured
    # and the regression gates held, but passed/contract/full-bar are all False.
    dast["passed"] = False
    dast["release_quality_contract_passed"] = False
    dast["quality_bar_passed"] = False
    dast["regression_gates_passed"] = True
    dast["quality_bar_enforced"] = True
    # The scorecard's real key; the receipt used to read "recall" and record None.
    dast["targets"] = [{"expected_recall": 0.44, "quality_gates": []}]
    paths["external_evidence"]["dast_quality"] = (
        dast, _write(tmp_path, dast_path.name, dast),
    )
    receipt = certify_receipt(
        candidate=candidate,
        upgrade=upgrade,
        preservation=preservation,
        e2e=e2e,
        source_sha=SOURCE,
        waive_dast_quality=True,
        **paths,
    )
    checks = receipt["certification"]["checks"]
    assert receipt["certification"]["status"] == "pass"
    assert checks["complete_dast_quality_bar"] == "waived_declared_debt"
    assert checks["dast_release_quality_contract"] == "waived_declared_debt"
    waiver = next(
        item for item in receipt["certification"]["scope_exclusions"]
        if isinstance(item, dict) and item.get("boundary") == "complete_dast_quality_bar"
    )
    assert waiver["state"] == "waived_declared_debt"
    assert waiver["measured_recall"] == 0.44
    assert waiver["quality_bar_enforced"] is True


def test_a_waiver_still_requires_the_regression_gates_and_enforcement(tmp_path):
    # A waiver accepts a shortfall against the complete bar; it must never let the
    # regression floor decay or the bar go unmeasured.
    for defect in ("regression_gates_passed", "quality_bar_enforced"):
        candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
        dast, dast_path = paths["external_evidence"]["dast_quality"]
        dast["quality_bar_passed"] = False
        dast[defect] = False
        paths["external_evidence"]["dast_quality"] = (
            dast, _write(tmp_path, dast_path.name, dast),
        )
        with pytest.raises(CertificationError, match="regression gates or quality-bar enforcement"):
            certify_receipt(
                candidate=candidate,
                upgrade=upgrade,
                preservation=preservation,
                e2e=e2e,
                source_sha=SOURCE,
                waive_dast_quality=True,
                **paths,
            )


@pytest.mark.parametrize("defect", ("scanner_digest", "source", "e2e", "preservation"))
def test_certification_fails_closed_on_cross_candidate_or_failed_evidence(tmp_path, defect):
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    if defect == "scanner_digest":
        upgrade["candidate"]["images"]["scanner"] = "sha256:" + "f" * 64
    elif defect == "source":
        upgrade["candidate"]["source_sha"] = "b" * 40
    elif defect == "e2e":
        e2e["gate"] = "fail"
    else:
        preservation["status"] = "fail"
    with pytest.raises(CertificationError):
        certify_receipt(
            candidate=candidate,
            upgrade=upgrade,
            preservation=preservation,
            e2e=e2e,
            source_sha=SOURCE,
            **paths,
        )


# --- The E2E scorecard must have tested THIS candidate -----------------------------------------
# The candidate, upgrade and preservation receipts each bind the source they ran against. The E2E
# scorecard carried no identity at all, so a run dispatched from one revision could exercise a
# different deployment and then qualify the first.

def test_an_e2e_scorecard_without_a_subject_cannot_certify(tmp_path):
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    e2e.pop("subject")
    paths["e2e_path"] = _write(tmp_path, "e2e.json", e2e)
    with pytest.raises(CertificationError, match="does not identify the deployment"):
        certify_receipt(
            candidate=candidate, upgrade=upgrade, preservation=preservation, e2e=e2e,
            source_sha=SOURCE, **paths,
        )


def test_an_e2e_scorecard_from_another_revision_cannot_certify(tmp_path):
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    e2e["subject"]["source_revision"] = "b" * 40
    paths["e2e_path"] = _write(tmp_path, "e2e.json", e2e)
    with pytest.raises(CertificationError, match="tested a different source revision"):
        certify_receipt(
            candidate=candidate, upgrade=upgrade, preservation=preservation, e2e=e2e,
            source_sha=SOURCE, **paths,
        )


def test_an_e2e_scorecard_from_other_images_cannot_certify(tmp_path):
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    e2e["subject"]["images"] = dict(sorted({**IMAGES, "ui": "f" * 64}.items()))
    paths["e2e_path"] = _write(tmp_path, "e2e.json", e2e)
    with pytest.raises(CertificationError, match="final release image digests"):
        certify_receipt(
            candidate=candidate, upgrade=upgrade, preservation=preservation, e2e=e2e,
            source_sha=SOURCE, **paths,
        )


@pytest.mark.parametrize("field", ("images", "deployment_binding", "image_built"))
def test_an_e2e_scorecard_without_verified_image_binding_cannot_certify(tmp_path, field):
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    e2e["subject"].pop(field)
    paths["e2e_path"] = _write(tmp_path, "e2e.json", e2e)
    with pytest.raises(CertificationError):
        certify_receipt(
            candidate=candidate, upgrade=upgrade, preservation=preservation, e2e=e2e,
            source_sha=SOURCE, **paths,
        )


def test_an_e2e_scorecard_without_real_target_hunt_proof_cannot_certify(tmp_path):
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    hunt = next(item for item in e2e["areas"] if item["area"] == "hunt")
    hunt["rows"][0]["skipped"] = True
    paths["e2e_path"] = _write(tmp_path, "e2e.json", e2e)
    with pytest.raises(CertificationError, match="adaptive real-target"):
        certify_receipt(
            candidate=candidate, upgrade=upgrade, preservation=preservation,
            e2e=e2e, source_sha=SOURCE, **paths,
        )


def test_the_certification_records_the_subject_binding_as_a_check(tmp_path):
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    result = certify_receipt(
        candidate=candidate, upgrade=upgrade, preservation=preservation, e2e=e2e,
        source_sha=SOURCE, **paths,
    )
    assert result["certification"]["checks"]["e2e_subject_binding"] == "pass"


def _add_xfail_row(e2e: dict, area: str, name: str, reason: str) -> None:
    """Append a declared-debt XFAIL row (loud, non-gating) to one area."""
    row = {
        "name": name, "passed": True, "skipped": False,
        "xfail": True, "xpass": False, "reason": reason, "detail": "attempted=0",
    }
    next(item for item in e2e["areas"] if item["area"] == area)["rows"].append(row)


def test_an_unauthorized_e2e_xfail_row_fails_certification(tmp_path):
    # An XFAIL keeps its area gate green (passed=True), so certification must reject
    # it explicitly unless the release authorized the debt -- otherwise a debt marker
    # would silently mask a red check.
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    _add_xfail_row(e2e, "dast", "D-2 SQLi attempted real candidates", "bounded body-injection debt")
    paths["e2e_path"] = _write(tmp_path, "e2e.json", e2e)
    with pytest.raises(CertificationError, match="declared-debt xfails"):
        certify_receipt(
            candidate=candidate, upgrade=upgrade, preservation=preservation,
            e2e=e2e, source_sha=SOURCE, **paths,
        )


def test_release_owner_can_waive_named_e2e_debt_and_it_is_recorded(tmp_path):
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    _add_xfail_row(e2e, "dast", "D-2 SQLi attempted real candidates", "bounded body-injection debt")
    paths["e2e_path"] = _write(tmp_path, "e2e.json", e2e)
    receipt = certify_receipt(
        candidate=candidate, upgrade=upgrade, preservation=preservation,
        e2e=e2e, source_sha=SOURCE, waive_e2e_declared_debt=True, **paths,
    )
    assert receipt["certification"]["status"] == "pass"
    debt = next(
        item for item in receipt["certification"]["scope_exclusions"]
        if isinstance(item, dict)
        and item.get("boundary") == "installed_stack_e2e_declared_debt"
    )
    assert debt["state"] == "waived_declared_debt"
    names = {row["check"] for row in debt["checks"]}
    assert "D-2 SQLi attempted real candidates" in names
    assert all(row["reason"] for row in debt["checks"])


def test_an_xfail_h18_row_is_not_genuine_proof_without_the_waiver(tmp_path):
    # H-18 as a declared-debt XFAIL carries passed=True but is NOT the adaptive
    # verified-finding proof. Unwaived, certification must still demand a genuine pass.
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    hunt = next(item for item in e2e["areas"] if item["area"] == "hunt")
    hunt["rows"][0].update({"xfail": True, "xpass": False, "reason": "adaptive xss debt"})
    paths["e2e_path"] = _write(tmp_path, "e2e.json", e2e)
    with pytest.raises(CertificationError, match="adaptive real-target"):
        certify_receipt(
            candidate=candidate, upgrade=upgrade, preservation=preservation,
            e2e=e2e, source_sha=SOURCE, **paths,
        )


def test_waived_h18_debt_certifies_and_is_recorded(tmp_path):
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    hunt = next(item for item in e2e["areas"] if item["area"] == "hunt")
    hunt["rows"][0].update({"xfail": True, "xpass": False, "reason": "adaptive xss debt"})
    paths["e2e_path"] = _write(tmp_path, "e2e.json", e2e)
    receipt = certify_receipt(
        candidate=candidate, upgrade=upgrade, preservation=preservation,
        e2e=e2e, source_sha=SOURCE, waive_e2e_declared_debt=True, **paths,
    )
    assert receipt["certification"]["status"] == "pass"
    debt = next(
        item for item in receipt["certification"]["scope_exclusions"]
        if isinstance(item, dict)
        and item.get("boundary") == "installed_stack_e2e_declared_debt"
    )
    assert any("H-18" in row["check"] for row in debt["checks"])


@pytest.mark.parametrize("manifest", [None, "", "not-a-digest", "5" * 63])
def test_a_candidate_without_a_runtime_manifest_digest_cannot_certify(tmp_path, manifest):
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    candidate = dict(candidate)
    if manifest is None:
        candidate.pop("runtime_manifest_sha256")
    else:
        candidate["runtime_manifest_sha256"] = manifest
    with pytest.raises(CertificationError, match="runtime manifest"):
        certify_receipt(
            candidate=candidate, upgrade=upgrade, preservation=preservation, e2e=e2e,
            source_sha=SOURCE, **paths,
        )


def test_the_certification_records_the_runtime_manifest_digest(tmp_path):
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    receipt = certify_receipt(
        candidate=candidate, upgrade=upgrade, preservation=preservation, e2e=e2e,
        source_sha=SOURCE, **paths,
    )
    assert receipt["runtime_manifest_sha256"] == "5" * 64
    assert receipt["certification"]["runtime_manifest_sha256"] == "5" * 64


def _debt_preservation(preservation: dict) -> dict:
    return {
        **preservation,
        "declared_debt_controls": [{
            "control": "model_intake.trust_expiry", "checks": ["MI-6 durable trust-anchor lifecycle"],
            "reason": "preview surface outside the shipping scope",
        }],
    }


def test_preservation_declared_debt_requires_the_e2e_debt_waiver(tmp_path):
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    with pytest.raises(CertificationError, match="preservation receipt records declared-debt"):
        certify_receipt(
            candidate=candidate, upgrade=upgrade, preservation=_debt_preservation(preservation),
            e2e=e2e, source_sha=SOURCE, **paths,
        )
    receipt = certify_receipt(
        candidate=candidate, upgrade=upgrade, preservation=_debt_preservation(preservation),
        e2e=e2e, source_sha=SOURCE, waive_e2e_declared_debt=True, **paths,
    )
    record = next(
        item for item in receipt["certification"]["scope_exclusions"]
        if isinstance(item, dict) and item["boundary"] == "mature_subsystem_preservation_declared_debt"
    )
    assert record["controls"][0]["control"] == "model_intake.trust_expiry"
    validate_certification_checks(receipt)


def test_promotion_accepts_waived_dast_quality_only_with_its_scope_record(tmp_path):
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    dast_path = paths["external_evidence"]["dast_quality"][1]
    shortfall = {**paths["external_evidence"]["dast_quality"][0], "passed": False,
                 "quality_bar_passed": False, "release_quality_contract_passed": False}
    dast_path.write_text(json.dumps(shortfall), encoding="utf-8")
    paths["external_evidence"]["dast_quality"] = (shortfall, dast_path)
    receipt = certify_receipt(
        candidate=candidate, upgrade=upgrade, preservation=preservation, e2e=e2e,
        source_sha=SOURCE, waive_dast_quality=True, **paths,
    )
    assert receipt["certification"]["checks"]["complete_dast_quality_bar"] == "waived_declared_debt"
    validate_certification_checks(receipt)

    stripped = json.loads(json.dumps(receipt))
    stripped["certification"]["scope_exclusions"] = [
        item for item in stripped["certification"]["scope_exclusions"]
        if not (isinstance(item, dict) and item.get("boundary") == "complete_dast_quality_bar")
    ]
    with pytest.raises(PromotionReceiptError, match="no scope-exclusion record"):
        validate_certification_checks(stripped)

    half = json.loads(json.dumps(receipt))
    half["certification"]["checks"]["dast_release_quality_contract"] = "pass"
    with pytest.raises(PromotionReceiptError, match="waived together"):
        validate_certification_checks(half)

    unknown = json.loads(json.dumps(receipt))
    unknown["certification"]["scope_exclusions"].append({"boundary": "made_up", "state": "waived_declared_debt"})
    with pytest.raises(PromotionReceiptError, match="unknown or unwaived"):
        validate_certification_checks(unknown)


# --- The DAST and fault receipts must have run against THIS candidate --------------------------
# They were accepted on pass flags and schema alone, so a scorecard or fault receipt produced on
# another deployment or an older build certified this candidate as readily as its own.

FAULT_KEYS = ("fault_cancellation", "fault_reservation_identity", "fault_action_resume")
FOREIGN_DIGEST = "sha256:" + "f" * 64


def _replace_external(tmp_path, paths, key, value):
    path = paths["external_evidence"][key][1]
    paths["external_evidence"][key] = (value, _write(tmp_path, path.name, value))


def _certify(candidate, upgrade, preservation, e2e, paths, **kwargs):
    return certify_receipt(
        candidate=candidate, upgrade=upgrade, preservation=preservation, e2e=e2e,
        source_sha=SOURCE, **paths, **kwargs,
    )


@pytest.mark.parametrize("key", ("dast_quality", *FAULT_KEYS))
def test_a_receipt_without_a_subject_cannot_certify(tmp_path, key):
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    value = dict(paths["external_evidence"][key][0])
    value.pop("subject")
    _replace_external(tmp_path, paths, key, value)
    with pytest.raises(CertificationError, match="does not identify the deployment"):
        _certify(candidate, upgrade, preservation, e2e, paths)


@pytest.mark.parametrize("key", ("dast_quality", *FAULT_KEYS))
@pytest.mark.parametrize("revision", ("b" * 40, None, "unknown"))
def test_a_receipt_from_another_revision_cannot_certify(tmp_path, key, revision):
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    value = json.loads(json.dumps(paths["external_evidence"][key][0]))
    if revision is None:
        value["subject"].pop("source_revision")
    else:
        value["subject"]["source_revision"] = revision
    _replace_external(tmp_path, paths, key, value)
    with pytest.raises(CertificationError, match="different source revision"):
        _certify(candidate, upgrade, preservation, e2e, paths)


@pytest.mark.parametrize("key", ("dast_quality", *FAULT_KEYS))
@pytest.mark.parametrize("images", (
    None,
    {"api": IMAGES["api"]},
    {"api": FOREIGN_DIGEST},
    {**IMAGES, "scanner": FOREIGN_DIGEST},
    {"not_a_release_image": IMAGES["api"]},
    {},
    "sha256:" + "1" * 64,
))
def test_a_receipt_from_other_image_digests_cannot_certify(tmp_path, key, images):
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    value = json.loads(json.dumps(paths["external_evidence"][key][0]))
    value["subject"]["images"] = images
    _replace_external(tmp_path, paths, key, value)
    with pytest.raises(CertificationError, match="final release image digests"):
        _certify(candidate, upgrade, preservation, e2e, paths)


@pytest.mark.parametrize("key", ("dast_quality", *FAULT_KEYS))
@pytest.mark.parametrize("images", (dict(IMAGES),))
def test_a_receipt_recording_the_candidate_digests_certifies(tmp_path, key, images):
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    value = json.loads(json.dumps(paths["external_evidence"][key][0]))
    value["subject"]["images"] = images
    _replace_external(tmp_path, paths, key, value)
    receipt = _certify(candidate, upgrade, preservation, e2e, paths)
    assert receipt["certification"]["status"] == "pass"


@pytest.mark.parametrize("key", ("dast_quality", *FAULT_KEYS))
@pytest.mark.parametrize("field", ("images", "deployment_binding", "image_built"))
def test_a_source_only_or_uninspected_receipt_cannot_certify(tmp_path, key, field):
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    value = json.loads(json.dumps(paths["external_evidence"][key][0]))
    value["subject"].pop(field)
    _replace_external(tmp_path, paths, key, value)
    with pytest.raises(CertificationError):
        _certify(candidate, upgrade, preservation, e2e, paths)


@pytest.mark.parametrize("key", ("dast_quality", *FAULT_KEYS))
def test_environment_revision_without_an_image_built_runtime_cannot_certify(tmp_path, key):
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    value = json.loads(json.dumps(paths["external_evidence"][key][0]))
    value["subject"]["image_built"] = False
    _replace_external(tmp_path, paths, key, value)
    with pytest.raises(CertificationError, match="image-built"):
        _certify(candidate, upgrade, preservation, e2e, paths)


@pytest.mark.parametrize("key", ("dast_quality", *FAULT_KEYS))
def test_a_receipt_with_candidate_digest_claims_but_a_foreign_container_cannot_certify(tmp_path, key):
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    value = json.loads(json.dumps(paths["external_evidence"][key][0]))
    value["subject"]["deployment_binding"]["after"]["containers"][0]["image_id"] = FOREIGN_DIGEST
    _replace_external(tmp_path, paths, key, value)
    with pytest.raises(CertificationError, match="running container"):
        _certify(candidate, upgrade, preservation, e2e, paths)


@pytest.mark.parametrize("fleet_uniform", (False, None))
def test_a_dast_receipt_measured_on_a_stale_fleet_cannot_certify(tmp_path, fleet_uniform):
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    value = dict(paths["external_evidence"]["dast_quality"][0])
    if fleet_uniform is None:
        value.pop("fleet_uniform")
    else:
        value["fleet_uniform"] = fleet_uniform
    _replace_external(tmp_path, paths, "dast_quality", value)
    with pytest.raises(CertificationError, match="stale or mixed worker fleet"):
        _certify(candidate, upgrade, preservation, e2e, paths)


def _load_script(path: Path, name: str):
    import importlib.util
    import sys

    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _produce_dast_receipt(tmp_path, monkeypatch, revisions):
    """Run the real benchmark entry point as installed_stack_smoke.sh does, against a fake API.

    ``revisions`` is what /health reports on each read (start of run, end of run): an image-built
    stack reports the source revision baked into its release manifest.
    """
    import sys

    benchmark = _load_script(
        Path(__file__).resolve().parents[1] / "scripts" / "benchmark_targets.py",
        "benchmark_receipt_producer_under_test",
    )
    reads = iter(revisions)

    def fake_get(url, timeout=30):
        assert url.endswith("/health"), url
        return {"source_revision": next(reads), "build_fingerprint": "f" * 64,
                "scanner_version": "9.9.9"}

    monkeypatch.setattr(benchmark, "OUT_DIR", str(tmp_path / "runs"))
    monkeypatch.setattr(benchmark, "_get", fake_get)
    monkeypatch.setattr(benchmark, "check_fleet", lambda api: (True, {"count": 1, "stale": 0}))
    monkeypatch.setattr(benchmark, "run_target", lambda name, *a, **k: {
        "target": name, "passed": True, "gates": [], "expected_recall": 0.33,
        "quality_gates": [
            {"gate": "quality:min_expected_recall", "pass": True, "detail": "0.33 >= 0.33"},
        ],
        "quality_passed": True, "quality_enforced_passed": True,
        "quality_release_contract": {"status": "full_bar", "valid": True},
    })
    # A caller's digest assertion must never be recorded as observed deployment identity.
    monkeypatch.setenv("SHAKERSCAN_RELEASE_IMAGE_DIGESTS", json.dumps(IMAGES))
    monkeypatch.setattr(sys, "argv", [
        "benchmark_targets.py", "juice_shop", "--api", "http://127.0.0.1:38001", "--auth",
        "--enforce-quality", "--target-url", "juice_shop=http://juice-shop:3000",
        "--auth-target-url", "juice_shop=http://127.0.0.1:44001",
    ])
    assert benchmark.main() == 0
    return json.loads((tmp_path / "runs" / "benchmark-juice_shop.json").read_text())


def test_the_benchmark_produces_a_dast_receipt_that_certifies_its_own_candidate(
    tmp_path, monkeypatch,
):
    dast = _produce_dast_receipt(tmp_path, monkeypatch, [SOURCE, SOURCE])
    assert dast["subject"]["source_revision"] == SOURCE
    assert dast["subject"]["identity_stable"] is True
    assert "images" not in dast["subject"]
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    binding = _deployment_binding()
    dast = bind_receipt(dast, binding["before"], binding["after"], candidate)
    _replace_external(tmp_path, paths, "dast_quality", dast)
    assert _certify(candidate, upgrade, preservation, e2e, paths)["certification"]["status"] == "pass"


@pytest.mark.parametrize("revisions", (["b" * 40, "b" * 40], [SOURCE, "b" * 40], ["unknown"] * 2))
def test_a_benchmark_run_on_another_or_changing_deployment_cannot_certify(
    tmp_path, monkeypatch, revisions,
):
    dast = _produce_dast_receipt(tmp_path, monkeypatch, revisions)
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    _replace_external(tmp_path, paths, "dast_quality", dast)
    with pytest.raises(CertificationError, match="different source revision"):
        _certify(candidate, upgrade, preservation, e2e, paths)


@pytest.mark.parametrize("script,key", (
    ("run_scan_cancellation_race.py", "fault_cancellation"),
    ("run_scan_reservation_identity.py", "fault_reservation_identity"),
    ("run_scan_action_resume.py", "fault_action_resume"),
))
def test_fault_producers_bind_their_receipts_to_the_runtime_release_manifest(
    tmp_path, monkeypatch, script, key,
):
    module = _load_script(
        Path(__file__).resolve().parents[1] / "tests" / "e2e" / script, f"{key}_producer_under_test",
    )
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    schema = paths["external_evidence"][key][0]["schema_version"]

    # Inside the API image: the baked release manifest names the candidate.
    manifest = tmp_path / "release-manifest.json"
    manifest.write_text(json.dumps({"version": "9.9.9", "source_revision": SOURCE}))
    monkeypatch.setenv("SHAKERSCAN_RELEASE_MANIFEST", str(manifest))
    subject = module._receipt_subject()
    assert subject["source_revision"] == SOURCE and subject["image_built"] is True
    binding = _deployment_binding()
    value = bind_receipt(
        {"schema_version": schema, "passed": True, "subject": subject},
        binding["before"], binding["after"], candidate,
    )
    _replace_external(tmp_path, paths, key, value)
    assert _certify(candidate, upgrade, preservation, e2e, paths)["certification"]["status"] == "pass"

    # A runtime built from another revision cannot certify this candidate.
    manifest.write_text(json.dumps({"version": "9.9.9", "source_revision": "b" * 40}))
    _replace_external(tmp_path, paths, key, {
        "schema_version": schema, "passed": True, "subject": module._receipt_subject(),
    })
    with pytest.raises(CertificationError, match="different source revision"):
        _certify(candidate, upgrade, preservation, e2e, paths)

    # A source-checkout diagnostic may name GIT_COMMIT but remains ineligible for a release.
    monkeypatch.setenv("SHAKERSCAN_RELEASE_MANIFEST", str(tmp_path / "absent.json"))
    monkeypatch.setenv("GIT_COMMIT", SOURCE)
    diagnostic = module._receipt_subject()
    assert diagnostic["source_revision"] == SOURCE and diagnostic["image_built"] is False
    _replace_external(tmp_path, paths, key, {
        "schema_version": schema, "passed": True, "subject": diagnostic,
    })
    with pytest.raises(CertificationError, match="image-built"):
        _certify(candidate, upgrade, preservation, e2e, paths)

    # An unidentifiable runtime records no revision and certifies nothing.
    monkeypatch.setenv("SHAKERSCAN_RELEASE_MANIFEST", str(tmp_path / "absent.json"))
    monkeypatch.delenv("GIT_COMMIT", raising=False)
    unidentified = module._receipt_subject()
    assert "source_revision" not in unidentified
    _replace_external(tmp_path, paths, key, {
        "schema_version": schema, "passed": True, "subject": unidentified,
    })
    with pytest.raises(CertificationError, match="different source revision"):
        _certify(candidate, upgrade, preservation, e2e, paths)


def test_a_waiver_never_excuses_a_foreign_dast_receipt(tmp_path):
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    value = json.loads(json.dumps(paths["external_evidence"]["dast_quality"][0]))
    value.update({"passed": False, "quality_bar_passed": False,
                  "release_quality_contract_passed": False})
    value["subject"]["source_revision"] = "b" * 40
    _replace_external(tmp_path, paths, "dast_quality", value)
    with pytest.raises(CertificationError, match="different source revision"):
        _certify(candidate, upgrade, preservation, e2e, paths, waive_dast_quality=True)
