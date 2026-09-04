"""`build-on-main` must produce the same certifiable candidate a release build does, and nothing more.

Workstream 2 of the post-2.0.1 plan builds the five release images once per image-affecting main commit so cutting a
release is a certify-only step. This is additive: the release candidate still owns certification and
the promotion workflows still own publication. These tests pin the safety envelope of the new
producer -- it validates its own SHA, publishes no version tag or `latest`, and shares the exact
build steps the release path uses -- so a later change cannot quietly turn it into a publisher.
"""

from __future__ import annotations

import pathlib

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
BUILD_ON_MAIN = WORKFLOWS / "build-on-main.yml"
REUSABLE = WORKFLOWS / "_build-images.yml"
CANDIDATE = WORKFLOWS / "release-candidate.yml"


def _doc(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _on(document):
    return document.get("on", document.get(True))


def test_build_on_main_runs_only_for_image_affecting_main_changes():
    on = _on(_doc(BUILD_ON_MAIN))
    assert on["push"]["branches"] == ["main"]
    paths = on["push"]["paths"]
    for path in ("!**/*.md", "!docs/**", "!tests/**", "!.github/**", "!LICENSE"):
        assert path in paths
    for path in (
        ".github/workflows/_build-images.yml",
        ".github/workflows/build-on-main.yml",
        ".github/workflows/release-candidate.yml",
    ):
        assert paths.index(path) > paths.index("!.github/**")
    # A manual re-build is available for a specific SHA.
    assert "sha" in on["workflow_dispatch"]["inputs"]


def test_build_on_main_validates_its_sha_before_using_it_as_a_ref():
    text = BUILD_ON_MAIN.read_text(encoding="utf-8")
    # The only external input is the dispatch SHA; it is read through an env var and validated to
    # 40 hex and to main-ancestry before it can reach a checkout ref (no ref injection).
    assert "INPUT_SHA: ${{ github.event.inputs.sha }}" in text
    assert 'if [[ ! "$candidate_sha" =~ ^[0-9a-f]{40}$ ]]; then' in text
    assert 'git merge-base --is-ancestor "$candidate_sha" origin/main' in text
    assert "${{ github.event.inputs.sha }}" not in text.split("run:", 1)[1] or "INPUT_SHA" in text


def test_build_on_main_never_publishes_a_version_tag_release_or_latest():
    text = BUILD_ON_MAIN.read_text(encoding="utf-8") + REUSABLE.read_text(encoding="utf-8")
    assert "gh release create" not in text
    assert 'imagetools create -t "${SCANNER_IMAGE}:${VERSION}"' not in text
    assert ":latest" not in text
    # The only tag either file writes is the immutable candidate tag.
    assert "candidate-${{ inputs.candidate_sha }}-${{ github.run_id }}" in REUSABLE.read_text(encoding="utf-8")


def test_build_on_main_calls_the_shared_build_and_grants_it_attestation_rights():
    document = _doc(BUILD_ON_MAIN)
    build = document["jobs"]["build"]
    assert build["uses"] == "./.github/workflows/_build-images.yml"
    assert build["secrets"] == "inherit"
    # Provenance attestation needs id-token and attestations write, granted by the caller.
    for permission in ("id-token", "attestations"):
        assert build["permissions"][permission] == "write"


def test_the_shared_build_writes_the_uncertified_receipt_the_release_path_reuses():
    text = REUSABLE.read_text(encoding="utf-8")
    document = _doc(REUSABLE)
    assert list(_on(document)) == ["workflow_call"]
    # Same receipt schema and artifact-name shape the certify job downloads by version and SHA.
    assert "shakerscan-release-candidate/v1" in text
    assert "release-candidate-uncertified-${{ inputs.version }}-${{ inputs.candidate_sha }}" in text
    assert "runtime_manifest_sha256" in text
    for image in ("scanner", "api", "ui", "signer", "model_intake"):
        assert f"{image}_digest:" in text


def test_the_shared_build_matches_the_candidates_build_construction():
    """The pre-built image must be identical in construction to what the release candidate builds."""
    reusable = REUSABLE.read_text(encoding="utf-8")
    candidate = CANDIDATE.read_text(encoding="utf-8")
    # The load-bearing build inputs are byte-identical to the candidate's own build jobs.
    for token in (
        "file: scanner/Dockerfile",
        "file: scanner/Dockerfile.api",
        "file: ui/Dockerfile",
        "file: api/model_intake_signer.Dockerfile",
        "file: scanner/Dockerfile.model-intake",
        "SCANNER_RUNTIME_IMAGE=${{ env.SCANNER_IMAGE }}@${{ steps.scanner.outputs.digest }}",
        "push-by-digest=true,name-canonical=true,push=true",
    ):
        assert token in reusable, token
        assert token in candidate, token
    # Both build native per platform, attest five subjects, and verify the signatures.
    assert reusable.count("provenance: mode=max") == 5
    assert reusable.count("sbom: true") == 5
    assert reusable.count("gh attestation verify") == 5
    assert "ubuntu-24.04-arm" in reusable


def test_release_candidate_reuses_only_an_attested_exact_sha_image_set():
    candidate = CANDIDATE.read_text(encoding="utf-8")
    document = _doc(CANDIDATE)
    meta = document["jobs"]["meta"]
    assert meta["outputs"]["prebuilt_run_id"] == "${{ steps.prebuilt.outputs.run_id }}"
    assert "gh run list --workflow=build-on-main.yml --branch main" in candidate
    assert '--commit "$CANDIDATE_SHA" --status success' in candidate
    assert ".runtime_manifest_sha256 == $runtime_manifest" in candidate
    assert candidate.count("gh attestation verify") >= 10
    for job_name in ("build-runtime", "build-ui", "build-signer"):
        assert document["jobs"][job_name]["if"] == "needs.meta.outputs.prebuilt_run_id == ''"
    validate = document["jobs"]["validate"]
    pull_step = next(
        step for step in validate["steps"]
        if step["name"] == "Pull exact reusable scanner and API manifests"
    )
    assert pull_step["if"] == "needs.meta.outputs.prebuilt_run_id != ''"
    merge = document["jobs"]["merge"]
    assert "validate" in merge["needs"]
    assert "needs.meta.outputs.prebuilt_run_id != ''" in merge["if"]
    assert any(step["name"] == "Download reusable exact-SHA receipt" for step in merge["steps"])


def test_build_on_main_and_the_reusable_build_parse_and_declare_jobs():
    for path in (BUILD_ON_MAIN, REUSABLE):
        document = _doc(path)
        assert _on(document), path.name
        assert document.get("jobs"), path.name
