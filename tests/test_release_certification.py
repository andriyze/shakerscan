from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.certify_release_receipt import CertificationError, certify_receipt


SOURCE = "a" * 40
IMAGES = {
    name: f"sha256:{index:064x}"
    for index, name in enumerate(("scanner", "api", "ui", "signer"), start=1)
}


def _write(tmp_path: Path, name: str, value: dict) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _evidence(tmp_path: Path):
    candidate = {
        "schema_version": "shakerscan-release-candidate/v1",
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
        "candidate": {
            "source_sha": SOURCE,
            "images": {key: IMAGES[key] for key in ("scanner", "api", "ui")},
        },
        "rollback_boundary": "pre-upgrade pg_dump restore",
        "checks": checks,
    }
    preservation = {
        "schema_version": "release-preservation-receipt/v1",
        "status": "pass",
        "source_sha": SOURCE,
        "images": dict(sorted(IMAGES.items())),
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
        },
        "areas": [
            {"area": area, "gate": "pass", "rows": []}
            for area in ("platform", "model_intake", "ai_gate", "dast", "hunt")
        ],
    }
    external_values = {
        "dast_quality": {"passed": True, "quality_bar_passed": True},
        "fault_acceptance": {
            "candidate_sha": SOURCE, "promotion_authorized": False,
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
        "stateful_upgrade_receipt",
        "preservation_receipt",
        "exact_manifest_e2e_scorecard",
        *paths["external_evidence"].keys(),
    }


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


def test_the_certification_records_the_subject_binding_as_a_check(tmp_path):
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    result = certify_receipt(
        candidate=candidate, upgrade=upgrade, preservation=preservation, e2e=e2e,
        source_sha=SOURCE, **paths,
    )
    assert result["certification"]["checks"]["e2e_subject_binding"] == "pass"
