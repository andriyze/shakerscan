#!/usr/bin/env python3
"""Classify changed paths for the required pull-request smoke check."""

from __future__ import annotations

import argparse
import subprocess
from collections.abc import Iterable


BACKEND_ROOTS = ("api/", "scanner/", "db/", "tests/e2e/")
BACKEND_FILES = frozenset({
    "docker-compose.yml",
    "Makefile",
    "scanner.sh",
    "scripts/generate_public_api_contract.py",
    "scripts/ci_smoke_scope.py",
    "docs/generated/public-openapi-manifest.json",
    "ui/src/lib/publicApi.generated.ts",
    "ui/src/lib/scanContract.generated.ts",
    "ui/src/lib/huntContract.generated.ts",
    "tests/test_public_api_contract_generation.py",
    ".github/workflows/e2e-pr.yml",
    ".github/workflows/e2e.yml",
})
UI_CONTRACT_FILES = frozenset({
    "api/api.py",
    "api/scan/contracts.py",
    "api/public_api_contract.py",
    "scripts/generate_scan_contract.py",
    "scripts/generate_hunt_contract.py",
    "scripts/generate_public_api_contract.py",
    "docs/generated/public-openapi-manifest.json",
    ".github/workflows/e2e-pr.yml",
    ".github/workflows/v2-contracts.yml",
})
# These change the production UI image or its dependencies, so keep the image gate.
UI_IMAGE_FILES = frozenset({
    "ui/Dockerfile",
    "ui/package.json",
    "ui/package-lock.json",
    "ui/next.config.js",
})
UI_SOURCE_ROOTS = ("ui/src/", "ui/public/", "ui/tests/browser/", "ui/test-manifests/")
PYTHON_SKIP_FILES = frozenset({"LICENSE", ".gitignore"})
PYTHON_FULL_METADATA = frozenset({"RELEASES.md", "install/STABLE_VERSION"})


def python_mode(paths: Iterable[str]) -> str:
    changed = set(paths)
    relevant = {
        path for path in changed
        if path in PYTHON_FULL_METADATA or path.startswith("docs/releases/")
        or not (
            path.startswith("docs/") or path.endswith(".md")
            or path.startswith(".github/rulesets/") or path in PYTHON_SKIP_FILES
        )
    }
    if not relevant:
        return "skip"
    if all(path.startswith(UI_SOURCE_ROOTS) and path not in BACKEND_FILES for path in relevant):
        return "ui"
    return "full"


def classify_paths(paths: Iterable[str]) -> dict[str, bool]:
    changed = set(paths)
    backend = any(
        path in BACKEND_FILES or path.startswith(BACKEND_ROOTS)
        for path in changed
    )
    ui = backend or any(
        path.startswith("ui/") or path in UI_CONTRACT_FILES
        for path in changed
    )
    stack = backend or bool(changed & (UI_IMAGE_FILES | UI_CONTRACT_FILES))
    return {"backend": backend, "ui": ui, "stack": stack}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    args = parser.parse_args()
    result = subprocess.run(
        ["git", "diff", "--name-only", "--no-renames", "-z", args.base, args.head],
        check=True,
        capture_output=True,
    )
    paths = [path.decode() for path in result.stdout.split(b"\0") if path]
    for key, enabled in classify_paths(paths).items():
        print(f"{key}={str(enabled).lower()}")
    print(f"python_mode={python_mode(paths)}")


if __name__ == "__main__":
    main()
