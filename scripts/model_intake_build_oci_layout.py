#!/usr/bin/env python3
"""Build a content-addressed OCI layout for an admitted exact model bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any


OCI_LAYOUT_VERSION = {"imageLayoutVersion": "1.0.0"}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _blob(root: Path, content: bytes, media_type: str) -> dict[str, Any]:
    digest = hashlib.sha256(content).hexdigest()
    destination = root / "blobs" / "sha256" / digest
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(content)
    return {"mediaType": media_type, "digest": f"sha256:{digest}", "size": len(content)}


def build_layout(
    output: Path,
    *,
    deployment_bundle: dict[str, Any],
    admission_package: dict[str, Any],
    artifact: Path | None = None,
    repository_snapshot: Path | None = None,
) -> dict[str, Any]:
    if output.exists() and any(output.iterdir()):
        raise ValueError("output OCI layout directory must be empty")
    output.mkdir(parents=True, exist_ok=True)
    if len(str(deployment_bundle.get("bundle_sha256") or "")) != 64:
        raise ValueError("deployment bundle digest is missing")
    if admission_package.get("schema_version") != "model-intake-admission/v2":
        raise ValueError("active admission v2 package is required")
    layers = [
        _blob(output, _canonical(deployment_bundle), "application/vnd.shakerscan.model.bundle.v1+json"),
        _blob(output, _canonical(admission_package), "application/vnd.shakerscan.model.admission.v2+json"),
    ]
    for path, media_type, expected in (
        (artifact, "application/vnd.shakerscan.model.artifact.v1", deployment_bundle.get("model_artifact_sha256")),
        (repository_snapshot, "application/vnd.shakerscan.model.repository-snapshot.v1", deployment_bundle.get("repository_snapshot_sha256")),
    ):
        if path:
            content = path.read_bytes()
            if hashlib.sha256(content).hexdigest() != expected:
                raise ValueError(f"{path.name} does not match deployment bundle")
            layers.append(_blob(output, content, media_type))
    config = _blob(output, _canonical({
        "createdBy": "shakerscan-model-intake",
        "deployment_bundle_sha256": deployment_bundle["bundle_sha256"],
        "target_environment": deployment_bundle["target_environment"],
    }), "application/vnd.shakerscan.model.config.v1+json")
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": config,
        "layers": layers,
        "annotations": {
            "org.opencontainers.image.title": "ShakerScan admitted model bundle",
            "dev.shakerscan.deployment-bundle.sha256": deployment_bundle["bundle_sha256"],
            "dev.shakerscan.admission.statement.sha256": str(admission_package.get("statement_sha256") or ""),
        },
    }
    manifest_descriptor = _blob(output, _canonical(manifest), "application/vnd.oci.image.manifest.v1+json")
    index = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{**manifest_descriptor, "annotations": {"org.opencontainers.image.ref.name": "admitted"}}],
    }
    (output / "oci-layout").write_bytes(_canonical(OCI_LAYOUT_VERSION))
    (output / "index.json").write_bytes(_canonical(index))
    return {"layout": str(output), "manifest_digest": manifest_descriptor["digest"], "layers": len(layers)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--deployment-bundle", type=Path, required=True)
    parser.add_argument("--admission-package", type=Path, required=True)
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--repository-snapshot", type=Path)
    args = parser.parse_args()
    try:
        result = build_layout(
            args.output,
            deployment_bundle=json.loads(args.deployment_bundle.read_text()),
            admission_package=json.loads(args.admission_package.read_text()),
            artifact=args.artifact,
            repository_snapshot=args.repository_snapshot,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"OCI PROMOTION LAYOUT FAILED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
