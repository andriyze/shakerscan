#!/usr/bin/env python3
"""Immutable image release identity shared by API, workers, and scan reports."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_MANIFEST_PATH = Path("/opt/shakerscan/release-manifest.json")


@dataclass(frozen=True)
class ReleaseIdentity:
    version: str
    source_revision: str
    image_built: bool

    @property
    def is_release(self) -> bool:
        return bool(
            self.image_built
            and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z.-]+)?", self.version)
        )


def _manifest_path() -> Path:
    configured = str(os.environ.get("SHAKERSCAN_RELEASE_MANIFEST") or "").strip()
    return Path(configured) if configured else DEFAULT_MANIFEST_PATH


def load_release_identity(path: Path | None = None) -> ReleaseIdentity:
    manifest_path = path or _manifest_path()
    if manifest_path.is_file():
        try:
            payload: Any = json.loads(manifest_path.read_text(encoding="utf-8"))
            version = str(payload.get("version") or "").strip()
            revision = str(payload.get("source_revision") or "").strip()
            if not version or not revision:
                raise ValueError("version and source_revision are required")
            return ReleaseIdentity(version, revision, True)
        except (OSError, ValueError, json.JSONDecodeError, AttributeError) as exc:
            raise RuntimeError(f"invalid ShakerScan release manifest {manifest_path}: {exc}") from exc
    return ReleaseIdentity(
        str(os.environ.get("SCANNER_VERSION") or os.environ.get("GIT_COMMIT") or "dev").strip(),
        str(os.environ.get("GIT_COMMIT") or "unknown").strip(),
        False,
    )


def published_scanner_version(fallback: str | None = None) -> str:
    identity = load_release_identity()
    if identity.is_release:
        return identity.version
    return str(fallback or identity.version or "dev")


def build_fingerprint(source_fingerprint: str | None) -> str | None:
    """Bind release fingerprints to both source content and baked provenance."""
    if not source_fingerprint:
        return None
    identity = load_release_identity()
    if not identity.is_release:
        return source_fingerprint
    material = f"{source_fingerprint}\0{identity.version}\0{identity.source_revision}".encode()
    return hashlib.sha256(material).hexdigest()


def verify_runtime_identity(
    expected_version: str | None = None,
    expected_revision: str | None = None,
) -> ReleaseIdentity:
    identity = load_release_identity()
    version = str(expected_version or os.environ.get("SCANNER_EXPECTED_VERSION") or "").strip()
    revision = str(expected_revision or os.environ.get("SCANNER_EXPECTED_REVISION") or "").strip()
    if version and identity.version != version:
        raise RuntimeError(
            f"release identity mismatch: image={identity.version}, deployment={version}"
        )
    if revision and identity.source_revision != revision:
        raise RuntimeError(
            "release revision mismatch: "
            f"image={identity.source_revision}, deployment={revision}"
        )
    return identity


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect or verify baked ShakerScan identity")
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    identity = verify_runtime_identity() if args.verify else load_release_identity()
    print(json.dumps({
        "version": identity.version,
        "source_revision": identity.source_revision,
        "image_built": identity.image_built,
        "release": identity.is_release,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
