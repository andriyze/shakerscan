"""Release digest bindings come from inspected running images, never caller assertions."""
from __future__ import annotations

from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from scripts import release_deployment_subject as binding


SOURCE = "a" * 40
IMAGES = {image["key"]: f"sha256:{index + 1:064x}"
          for index, image in enumerate(binding.RELEASE_IMAGES)}
CANDIDATE = {"candidate_sha": SOURCE, "version": "9.9.9", "images": IMAGES}


def _docker(monkeypatch, *, foreign_worker=False, image_built=True):
    records, inspected = [], {}
    for index, image in enumerate(binding.RELEASE_IMAGES):
        reference = f"{image['repository']}@{IMAGES[image['key']]}"
        image_id = f"sha256:{index + 100:064x}"
        inspected[reference] = [{"Id": image_id, "RepoDigests": ["docker.io/" + reference]}]
        records.append({
            "Id": f"{index + 200:064x}", "Image": image_id, "State": {"Running": True},
            "Config": {"Env": ["SECRET=must-not-be-exported"], "Labels": {
                "com.docker.compose.service": "worker" if image["key"] == "scanner"
                else image["compose_services"][0],
            }},
        })
    # Every replica matters; a fresh API and first worker cannot hide an older second worker.
    records.append(deepcopy(records[0]))
    records[-1]["Id"] = "f" * 64
    if foreign_worker:
        records[-1]["Image"] = "sha256:" + "f" * 64
    calls = []

    def run(args, **kwargs):
        assert kwargs["check"] is True and kwargs["capture_output"] is True
        calls.append(args)
        if args[1] == "compose":
            assert args[-2:] == ["ps", "--quiet"]
            output = "\n".join(record["Id"] for record in records)
        elif args[1] == "inspect":
            assert set(args[2:]) == {record["Id"] for record in records}
            output = json.dumps(records)
        elif args[1:3] == ["image", "inspect"]:
            output = json.dumps(inspected[args[3]])
        elif args[1] == "exec":
            assert args[2] == records[1]["Id"]
            assert args[3:] == ["python3", "/app/release_identity.py"]
            output = json.dumps({"source_revision": SOURCE, "version": "9.9.9",
                                 "image_built": image_built})
        else:
            raise AssertionError(args)
        return SimpleNamespace(stdout=output)

    monkeypatch.setattr(binding.subprocess, "run", run)
    return calls, records, inspected


def test_capture_checks_digest_images_against_every_running_container_and_redacts_env(monkeypatch):
    calls, _, _ = _docker(monkeypatch)
    snapshot = binding.capture_snapshot(CANDIDATE, ["compose", "--project-name", "release"])
    assert len(snapshot["containers"]) == 6
    assert snapshot["images"] == IMAGES and snapshot["image_built"] is True
    assert "SECRET" not in json.dumps(snapshot) and "Config" not in json.dumps(snapshot)
    assert sum(args[1:3] == ["image", "inspect"] for args in calls) == len(IMAGES)


def test_capture_rejects_a_stale_second_worker_even_when_candidate_digest_tags_exist(monkeypatch):
    _docker(monkeypatch, foreign_worker=True)
    with pytest.raises(binding.DeploymentBindingError, match="running container"):
        binding.capture_snapshot(CANDIDATE, ["compose"])


def test_capture_rejects_environment_identity_without_an_image_manifest(monkeypatch):
    _docker(monkeypatch, image_built=False)
    with pytest.raises(binding.DeploymentBindingError, match="image-built"):
        binding.capture_snapshot(CANDIDATE, ["compose"])


def test_capture_rejects_a_digest_reference_that_docker_did_not_observe(monkeypatch):
    _, _, inspected = _docker(monkeypatch)
    next(iter(inspected.values()))[0]["RepoDigests"] = ["another/repository@" + IMAGES["scanner"]]
    with pytest.raises(binding.DeploymentBindingError, match="candidate digest"):
        binding.capture_snapshot(CANDIDATE, ["compose"])


def test_bind_adds_verified_deployment_images_to_diagnostic_receipt(monkeypatch):
    _docker(monkeypatch)
    before = binding.capture_snapshot(CANDIDATE, ["compose"])
    after = deepcopy(before)
    # A legitimate lifecycle recreation still uses the same candidate platform image.
    after["containers"][0]["container_id"] = "e" * 64
    diagnostic = {"passed": True, "subject": {"source_revision": SOURCE, "identity_stable": True}}
    receipt = binding.bind_receipt(diagnostic, before, after, CANDIDATE)
    assert "images" not in diagnostic["subject"]
    assert receipt["subject"]["images"] == IMAGES
    assert receipt["subject"]["image_built"] is True
    binding.validate_binding(receipt["subject"]["deployment_binding"], CANDIDATE)


@pytest.mark.parametrize("mutation", ("foreign_revision", "unbuilt", "changing", "false_images"))
def test_binding_cannot_launder_an_unrelated_or_unbuilt_diagnostic(monkeypatch, mutation):
    _docker(monkeypatch)
    snapshot = binding.capture_snapshot(CANDIDATE, ["compose"])
    subject = {"source_revision": SOURCE}
    if mutation == "foreign_revision":
        subject["source_revision"] = "b" * 40
    elif mutation == "unbuilt":
        subject["image_built"] = False
    elif mutation == "changing":
        subject["identity_stable"] = False
    else:
        subject["images"] = {"api": IMAGES["api"]}
    with pytest.raises(binding.DeploymentBindingError):
        binding.bind_receipt({"subject": subject}, snapshot, snapshot, CANDIDATE)


@pytest.mark.parametrize("mutation", ("missing_image", "missing_service", "wrong_digest", "unbuilt"))
def test_both_boundaries_must_cover_the_complete_exact_deployment(monkeypatch, mutation):
    _docker(monkeypatch)
    before = binding.capture_snapshot(CANDIDATE, ["compose"])
    after = deepcopy(before)
    if mutation == "missing_image":
        after["image_inspections"].pop("ui")
    elif mutation == "missing_service":
        after["containers"] = [c for c in after["containers"] if c["service"] != "ui"]
    elif mutation == "wrong_digest":
        after["images"]["ui"] = "sha256:" + "f" * 64
    else:
        after["image_built"] = False
    with pytest.raises(binding.DeploymentBindingError):
        binding.bind_receipt({"subject": {"source_revision": SOURCE}}, before, after, CANDIDATE)


def test_release_smoke_binds_e2e_dast_and_fault_receipts_from_candidate_path():
    """The behavioral verifier above must be reached by the real acceptance runner."""
    from pathlib import Path
    import yaml

    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / ".github/workflows/release-candidate.yml").read_text())
    steps = [step for job in workflow["jobs"].values() for step in job.get("steps", [])]
    smoke = next(step for step in steps if "make installed-stack-smoke" in step.get("run", ""))
    assert smoke["env"]["INSTALLED_STACK_SMOKE_CANDIDATE_RECEIPT"].endswith(
        "/artifacts/uncertified/release-candidate-receipt.json"
    )
    script = (root / "scripts/installed_stack_smoke.sh").read_text()
    for receipt in ('$scorecard_path', '$recall_path', '$fault_receipt'):
        assert f'bind_release_receipt "{receipt}"' in script
