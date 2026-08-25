import json

import pytest

from scripts.write_v2_candidate_acceptance import (
    CandidateAcceptanceError,
    build_receipt,
)


SHA = "a" * 40
IMAGE = "sha256:" + "b" * 64
IMAGES = {name: IMAGE for name in ("scanner", "api", "ui", "signer")}
TOOLS = {"docker": "28", "node": "24", "npm": "11", "python": "3.12"}


def _manifest(tmp_path):
    path = tmp_path / "templates.json"
    path.write_text(json.dumps({
        "schema_version": "template-manifest/v1",
        "manifest_digest": "c" * 64,
    }), encoding="utf-8")
    return path


def test_nonpublishing_receipt_binds_exact_images_workflow_and_evidence(tmp_path):
    evidence = tmp_path / "e2e.json"
    evidence.write_text('{"gate":"pass"}\n', encoding="utf-8")

    receipt = build_receipt(
        source_sha=SHA,
        workflow_sha="d" * 40,
        images=IMAGES,
        tool_versions=TOOLS,
        template_manifest_path=_manifest(tmp_path),
        evidence_paths={"full_e2e": evidence},
    )

    assert receipt["status"] == "pass"
    assert receipt["publication"] == "none"
    assert receipt["promotion_authorized"] is False
    assert receipt["images"] == IMAGES
    assert receipt["candidate_sha"] == SHA
    assert len(receipt["evidence_sha256"]["full_e2e"]) == 64
    assert len(receipt["receipt_sha256"]) == 64


@pytest.mark.parametrize(
    ("images", "tools"),
    [
        ({"scanner": IMAGE}, TOOLS),
        (IMAGES, {"docker": "28"}),
        ({**IMAGES, "api": "latest"}, TOOLS),
    ],
)
def test_candidate_receipt_fails_closed_on_incomplete_identity(
    tmp_path, images, tools,
):
    evidence = tmp_path / "evidence.json"
    evidence.write_text("{}", encoding="utf-8")

    with pytest.raises(CandidateAcceptanceError):
        build_receipt(
            source_sha=SHA,
            workflow_sha="d" * 40,
            images=images,
            tool_versions=tools,
            template_manifest_path=_manifest(tmp_path),
            evidence_paths={"e2e": evidence},
        )


def test_candidate_receipt_rejects_noncanonical_template_manifest(tmp_path):
    manifest = tmp_path / "templates.json"
    manifest.write_text(json.dumps({
        "schema_version": "template-manifest/v0",
        "manifest_digest": "c" * 64,
    }), encoding="utf-8")
    evidence = tmp_path / "evidence.json"
    evidence.write_text("{}", encoding="utf-8")

    with pytest.raises(CandidateAcceptanceError, match="schema"):
        build_receipt(
            source_sha=SHA,
            workflow_sha="d" * 40,
            images=IMAGES,
            tool_versions=TOOLS,
            template_manifest_path=manifest,
            evidence_paths={"e2e": evidence},
        )
