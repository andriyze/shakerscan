from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CANDIDATE = ROOT / ".github" / "workflows" / "release-candidate.yml"
PROMOTION = ROOT / ".github" / "workflows" / "release.yml"
STABLE = ROOT / ".github" / "workflows" / "promote-stable.yml"
CODEQL = ROOT / ".github" / "workflows" / "codeql.yml"


def test_candidate_build_cannot_publish_release_or_stable_aliases():
    text = CANDIDATE.read_text(encoding="utf-8")

    assert "push:\n    tags:" not in text
    assert "candidate-${{ needs.meta.outputs.candidate_sha }}-${{ github.run_id }}" in text
    assert "gh release create" not in text
    assert 'imagetools create -t "${SCANNER_IMAGE}:${VERSION}"' not in text
    assert 'imagetools create -t "${SCANNER_IMAGE}:latest"' not in text
    assert "shakerscan-release-candidate/v1" in text
    assert "shakerscan-release-candidate/v2" in text
    assert "e2e_run_id:" in text
    assert "codeql_run_id:" in text
    assert "parity_run_id:" in text
    assert 'verify_run "$E2E_RUN_ID" "E2E (full release gate)"' in text
    assert 'verify_run "$CODEQL_RUN_ID" "CodeQL"' in text
    assert 'verify_run "$PARITY_RUN_ID" "V2 Scan parity (real fleet)"' in text
    assert "Verify signed candidate provenance" in text
    assert "final-multiarch-image-digests" in text
    assert "release-candidate-uncertified-" in text
    assert "Certify final manifest digests" in text
    assert "scripts/certify_release_receipt.py" in text
    assert "INSTALLED_STACK_SMOKE_E2E" in text
    assert "CANDIDATE_IMAGE_DIGEST" in text


def test_codeql_matrix_concurrency_is_scoped_to_the_matrix_job():
    text = CODEQL.read_text(encoding="utf-8")
    job_marker = "  analyze:\n"
    job_start = text.index(job_marker)

    assert "concurrency:" not in text[:job_start]
    assert "    concurrency:\n" in text[job_start:]
    assert "group: codeql-${{ github.ref }}-${{ matrix.language }}" in text[job_start:]


def test_release_promotion_reuses_candidate_digests_without_physical_gate():
    text = PROMOTION.read_text(encoding="utf-8")

    assert "environment: release-promotion" not in text
    assert "candidate_run_id:" in text
    assert "acceptance_receipt_sha256:" not in text
    assert "ACCEPTANCE_NODE_COUNT" not in text
    assert 'shakerscan_fleet_acceptance_v1' not in text
    assert "gh run download" in text
    assert 'actual="$(docker buildx imagetools inspect' in text
    assert 'docker buildx imagetools create -t "${image}:${VERSION}" "${image}@${expected}"' in text
    assert 'existing="$(docker buildx imagetools inspect' in text
    assert "docker build " not in text
    assert ":latest" not in text
    assert "Reverify signed candidate provenance" in text
    assert 'shakerscan-release-candidate/v2' in text
    assert '.certification.status == "pass"' in text


def test_stable_channel_is_separate_last_step():
    text = STABLE.read_text(encoding="utf-8")

    assert "environment: stable-promotion" not in text
    assert "smoke_receipt_sha256:" in text
    assert "install/STABLE_VERSION" in text
    assert "public-smoke-receipt.json" in text
    assert "sha256sum --check --strict" in text
    assert "shakerscan-public-smoke/v1" in text
    for check in (
        "clean_install",
        "ui_api_identity",
        "worker_identity",
        "model_intake_local_session",
        "model_intake_browser_session",
        "firecracker_command",
    ):
        assert f".checks.{check}" in text
    assert 'imagetools create -t "${image}:latest"' in text
    assert "docker build " not in text


def test_clean_candidate_build_retries_only_pinned_base_downloads():
    workflow = CANDIDATE.read_text(encoding="utf-8")
    dockerfile = (ROOT / "scanner" / "Dockerfile").read_text(encoding="utf-8")
    pinned_bases = [
        line.removeprefix("FROM ").split(" AS ", 1)[0]
        for line in dockerfile.splitlines()
        if line.startswith("FROM golang:") or line.startswith("FROM mcr.microsoft.com/playwright/")
    ]

    assert len(pinned_bases) == 2
    assert all("@sha256:" in image for image in pinned_bases)
    assert all(image in workflow for image in pinned_bases)
    assert "scripts/retry-command.sh docker build" not in workflow
    assert "scripts/retry-command.sh scripts/selftest-model-intake-guest.sh" not in workflow
    assert workflow.count("scripts/retry-command.sh timeout 300 docker pull") == 2
