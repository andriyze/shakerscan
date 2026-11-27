#!/usr/bin/env python3
"""Bind release acceptance receipts to images observed on the running Docker stack.

The release workflow supplies a candidate receipt, never an asserted digest environment value.
Inspect both the digest-addressed images and the running containers before and after testing.
Only content-free Docker identity fields are retained; container environments are never exported.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Mapping

try:
    from release_image_inventory import RELEASE_IMAGES
except ModuleNotFoundError:
    from scripts.release_image_inventory import RELEASE_IMAGES


SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
SOURCE_SHA = re.compile(r"^[0-9a-f]{40}$")
IMAGE_KEYS = {image["key"] for image in RELEASE_IMAGES}
SERVICE_KEYS = {
    service: image["key"] for image in RELEASE_IMAGES for service in image["compose_services"]
}
SNAPSHOT_SCHEMA = "shakerscan-running-release-images/v1"
BINDING_SCHEMA = "shakerscan-release-deployment-binding/v1"


class DeploymentBindingError(ValueError):
    pass


def _repository_ref(value: str) -> str:
    return value.removeprefix("docker.io/")


def validate_snapshot(snapshot: Mapping[str, Any], candidate: Mapping[str, Any]) -> None:
    """Validate the inspected identity chain, including every release image and worker replica."""
    images = candidate.get("images")
    if (
        not isinstance(images, Mapping) or set(images) != IMAGE_KEYS
        or any(not SHA256.fullmatch(str(value)) for value in images.values())
    ):
        raise DeploymentBindingError("candidate must identify all exact release image digests")
    if (
        snapshot.get("schema_version") != SNAPSHOT_SCHEMA
        or snapshot.get("verification") != "docker_inspect"
        or snapshot.get("source_revision") != candidate.get("candidate_sha")
        or not SOURCE_SHA.fullmatch(str(snapshot.get("source_revision")))
        or snapshot.get("image_built") is not True
        or snapshot.get("version") != candidate.get("version")
        or snapshot.get("images") != dict(images)
    ):
        raise DeploymentBindingError("running deployment lacks the candidate's image-built identity")
    inspections = snapshot.get("image_inspections")
    if not isinstance(inspections, Mapping) or set(inspections) != IMAGE_KEYS:
        raise DeploymentBindingError("running deployment lacks every digest-addressed image inspection")
    for image in RELEASE_IMAGES:
        key = image["key"]
        observed = inspections[key]
        reference = f"{image['repository']}@{images[key]}"
        if (
            not isinstance(observed, Mapping)
            or not SHA256.fullmatch(str(observed.get("image_id")))
            or not isinstance(observed.get("repo_digests"), list)
            or reference not in [_repository_ref(str(item)) for item in observed["repo_digests"]]
        ):
            raise DeploymentBindingError(f"{key} image inspection does not bind its candidate digest")
    containers = snapshot.get("containers")
    if not isinstance(containers, list) or not containers:
        raise DeploymentBindingError("running deployment has no inspected containers")
    seen_ids: set[str] = set()
    seen_keys: set[str] = set()
    for container in containers:
        if not isinstance(container, Mapping):
            raise DeploymentBindingError("invalid running container identity")
        key = SERVICE_KEYS.get(container.get("service"))
        container_id = str(container.get("container_id") or "")
        if (
            key is None or container.get("running") is not True
            or not re.fullmatch(r"[0-9a-f]{64}", container_id)
            or container_id in seen_ids
            or container.get("image_id") != inspections[key]["image_id"]
        ):
            raise DeploymentBindingError("running container does not use its candidate digest image")
        seen_ids.add(container_id)
        seen_keys.add(key)
    if seen_keys != IMAGE_KEYS:
        raise DeploymentBindingError("running deployment does not cover every release image")


def validate_binding(binding: Any, candidate: Mapping[str, Any]) -> None:
    if not isinstance(binding, Mapping) or binding.get("schema_version") != BINDING_SCHEMA:
        raise DeploymentBindingError("receipt lacks verified running-container image bindings")
    for boundary in ("before", "after"):
        snapshot = binding.get(boundary)
        if not isinstance(snapshot, Mapping):
            raise DeploymentBindingError(f"receipt lacks {boundary} running-container image bindings")
        validate_snapshot(snapshot, candidate)
    # Containers may be recreated by lifecycle tests, but their digest-bound platform images
    # must remain identical throughout this acceptance run.
    if any(
        binding["before"]["image_inspections"][key]["image_id"]
        != binding["after"]["image_inspections"][key]["image_id"] for key in IMAGE_KEYS
    ):
        raise DeploymentBindingError("release image identities changed during acceptance")


def _docker_json(args: list[str]) -> Any:
    output = subprocess.run(["docker", *args], check=True, capture_output=True, text=True).stdout
    return json.loads(output)


def capture_snapshot(candidate: Mapping[str, Any], compose: list[str]) -> dict[str, Any]:
    ids = subprocess.run(
        ["docker", *compose, "ps", "--quiet"],
        check=True, capture_output=True, text=True,
    ).stdout.split()
    if not ids:
        raise DeploymentBindingError("release stack has no containers")
    records = _docker_json(["inspect", *ids])
    containers = []
    for record in records:
        service = (record.get("Config", {}).get("Labels") or {}).get("com.docker.compose.service")
        if service in SERVICE_KEYS:
            containers.append({
                "service": service, "container_id": record.get("Id"),
                "image_id": record.get("Image"),
                "running": record.get("State", {}).get("Running") is True,
            })
    api_ids = [item["container_id"] for item in containers if item["service"] == "api"]
    if len(api_ids) != 1:
        raise DeploymentBindingError("release stack must have one running API identity")
    identity = _docker_json(["exec", api_ids[0], "python3", "/app/release_identity.py"])
    inspections = {}
    for image in RELEASE_IMAGES:
        reference = f"{image['repository']}@{candidate['images'][image['key']]}"
        observed = _docker_json(["image", "inspect", reference])
        if not isinstance(observed, list) or len(observed) != 1:
            raise DeploymentBindingError(f"cannot inspect candidate image {reference}")
        inspections[image["key"]] = {
            "image_id": observed[0].get("Id"), "repo_digests": observed[0].get("RepoDigests"),
        }
    snapshot = {
        "schema_version": SNAPSHOT_SCHEMA, "verification": "docker_inspect",
        "source_revision": identity.get("source_revision"), "version": identity.get("version"),
        "image_built": identity.get("image_built"), "images": candidate["images"],
        "image_inspections": inspections, "containers": containers,
    }
    validate_snapshot(snapshot, candidate)
    return snapshot


def bind_receipt(receipt: dict[str, Any], before: dict[str, Any], after: dict[str, Any],
                 candidate: Mapping[str, Any]) -> dict[str, Any]:
    binding = {"schema_version": BINDING_SCHEMA, "before": before, "after": after}
    validate_binding(binding, candidate)
    subject = receipt.get("subject")
    if not isinstance(subject, dict) or subject.get("source_revision") != before["source_revision"]:
        raise DeploymentBindingError("receipt did not test the inspected deployment revision")
    if subject.get("image_built") is False or subject.get("identity_stable") is False:
        raise DeploymentBindingError("receipt did not run on a stable image-built deployment")
    if subject.get("images") is not None and subject["images"] != before["images"]:
        raise DeploymentBindingError("receipt image claims contradict the inspected deployment")
    return {**receipt, "subject": {
        **subject, "image_built": True, "images": before["images"], "deployment_binding": binding,
    }}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--bind-receipt", type=Path)
    args = parser.parse_args()
    candidate = json.loads(args.candidate.read_text())
    compose = [
        "compose", "--project-name", args.project, "--project-directory", str(args.runtime),
        "--env-file", str(args.runtime / ".env"), "-f", str(args.runtime / "docker-compose.release.yml"),
    ]
    observed = capture_snapshot(candidate, compose)
    if args.bind_receipt is None:
        args.snapshot.write_text(json.dumps(observed, sort_keys=True) + "\n")
    else:
        before = json.loads(args.snapshot.read_text())
        receipt = json.loads(args.bind_receipt.read_text())
        bound = bind_receipt(receipt, before, observed, candidate)
        args.bind_receipt.write_text(json.dumps(bound, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
