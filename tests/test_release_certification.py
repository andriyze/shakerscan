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
        "candidate": {"source_sha": SOURCE, "image_digest": IMAGES["scanner"]},
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
        "areas": [
            {"area": area, "gate": "pass", "rows": []}
            for area in ("platform", "model_intake", "ai_gate", "dast", "hunt")
        ],
    }
    paths = {
        "candidate_path": _write(tmp_path, "candidate.json", candidate),
        "upgrade_path": _write(tmp_path, "upgrade.json", upgrade),
        "preservation_path": _write(tmp_path, "preservation.json", preservation),
        "e2e_path": _write(tmp_path, "e2e.json", e2e),
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
    }


@pytest.mark.parametrize("defect", ("scanner_digest", "source", "e2e", "preservation"))
def test_certification_fails_closed_on_cross_candidate_or_failed_evidence(tmp_path, defect):
    candidate, upgrade, preservation, e2e, paths = _evidence(tmp_path)
    if defect == "scanner_digest":
        upgrade["candidate"]["image_digest"] = "sha256:" + "f" * 64
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
