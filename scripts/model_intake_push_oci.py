#!/usr/bin/env python3
"""Push one admitted OCI layout and verify the exact remote manifest digest."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Any


DESTINATION_RE = re.compile(r"^[a-zA-Z0-9.-]+(?::[0-9]{1,5})?/[a-z0-9]+(?:[._/-][a-z0-9]+)*$")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def layout_manifest(layout: Path) -> tuple[str, str]:
    index_path = layout.resolve(strict=True) / "index.json"
    index = json.loads(index_path.read_text())
    descriptors = index.get("manifests") if isinstance(index.get("manifests"), list) else []
    descriptor = next(
        (
            item for item in descriptors
            if isinstance(item, dict)
            and item.get("annotations", {}).get("org.opencontainers.image.ref.name") == "admitted"
        ),
        None,
    )
    digest = str((descriptor or {}).get("digest") or "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("OCI layout has no exact admitted manifest descriptor")
    blob = layout / "blobs" / "sha256" / digest.removeprefix("sha256:")
    if not blob.is_file() or f"sha256:{hashlib.sha256(blob.read_bytes()).hexdigest()}" != digest:
        raise ValueError("OCI layout manifest blob does not match its descriptor")
    manifest = json.loads(blob.read_text())
    bundle_sha = str(manifest.get("annotations", {}).get("dev.shakerscan.deployment-bundle.sha256") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", bundle_sha):
        raise ValueError("OCI layout lacks a deployment bundle binding")
    return digest, bundle_sha


def push_and_verify(layout: Path, destination: str, *, oras_binary: str = "oras") -> dict[str, Any]:
    registry, _, repository = destination.partition("/")
    if (
        not DESTINATION_RE.fullmatch(destination)
        or "localhost" in registry.lower()
        or registry in {".", ".."}
        or registry.startswith((".", "-"))
        or registry.endswith((".", "-"))
        or any(part in {"", ".", ".."} for part in repository.split("/"))
    ):
        raise ValueError("configured OCI destination must be one non-local registry repository without tag or scheme")
    if shutil.which(oras_binary) is None:
        raise RuntimeError("oras is required for configured OCI promotion")
    digest, bundle_sha = layout_manifest(layout)
    tag = f"admitted-{bundle_sha[:24]}"
    target = f"{destination}:{tag}"
    copied = subprocess.run(
        [oras_binary, "cp", "--from-oci-layout", f"{layout.resolve()}:admitted", target],
        capture_output=True,
        text=True,
        timeout=1800,
        check=False,
    )
    if copied.returncode:
        raise RuntimeError(f"OCI copy failed: {(copied.stderr or copied.stdout)[-2000:]}")
    fetched = subprocess.run(
        [oras_binary, "manifest", "fetch", "--descriptor", target],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if fetched.returncode:
        raise RuntimeError(f"remote OCI descriptor fetch failed: {(fetched.stderr or fetched.stdout)[-2000:]}")
    descriptor = json.loads(fetched.stdout)
    remote_digest = str(descriptor.get("digest") or "")
    if remote_digest != digest:
        raise RuntimeError(f"remote OCI digest mismatch: expected {digest}, observed {remote_digest}")
    receipt = {
        "schema_version": "model-intake-oci-promotion-receipt/v1",
        "remote_reference": f"{destination}@{digest}",
        "tag_reference": target,
        "manifest_digest": digest,
        "deployment_bundle_sha256": bundle_sha,
        "transport": "oci-distribution-https",
        "post_push_verified": True,
        "verified_at": datetime.now(timezone.utc).isoformat(),
    }
    receipt["receipt_sha256"] = hashlib.sha256(_canonical(receipt)).hexdigest()
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--layout", type=Path, required=True)
    parser.add_argument("--destination", default=os.getenv("MODEL_INTAKE_OCI_REGISTRY_REPOSITORY", ""))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        receipt = push_and_verify(args.layout, args.destination)
        encoded = _canonical(receipt)
        if args.output:
            temporary = args.output.with_name(f".{args.output.name}.tmp")
            temporary.write_bytes(encoded)
            temporary.chmod(0o600)
            os.replace(temporary, args.output)
        print(encoded.decode())
        return 0
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        print(f"OCI PROMOTION FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
