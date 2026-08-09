from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"


def test_stable_release_latest_promotion_is_derived_and_serialized():
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "group: shakerscan-release-publication" in text
    assert "push_latest:" not in text.split("jobs:", 1)[0]
    assert 'if [[ "$version" =~ ^[0-9]+\\.[0-9]+\\.[0-9]+$ ]]' in text
    assert 'push_latest="true"' in text
    assert "Refusing to move latest backward" in text


def test_every_release_image_verifies_latest_matches_version_digest():
    text = WORKFLOW.read_text(encoding="utf-8")

    assert text.count('latest_digest="$(docker buildx imagetools inspect') == 4
    assert text.count("&& !found {print $2; found=1}") == 8
    assert "{print $2; exit}" not in text
    assert text.count('[[ -n "$version_digest" && "$version_digest" == "$latest_digest" ]]') == 4


def test_manual_release_records_candidate_and_workflow_provenance():
    text = WORKFLOW.read_text(encoding="utf-8")

    assert 'workflow_sha: ${{ steps.meta.outputs.workflow_sha }}' in text
    assert 'echo "workflow_sha=${{ github.workflow_sha }}"' in text
    assert text.count("com.shakerscan.release.workflow-revision=${{ needs.meta.outputs.workflow_sha }}") == 4
    assert "Candidate source commit" in text
    assert "Release workflow commit" in text
