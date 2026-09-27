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
    "scripts/wait_for_running_prebuild.py",
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


def isolated_e2e_area(path: str) -> str | None:
    """Return one area only for paths with an unambiguous product owner."""
    if (
        path.startswith(("api/model_intake/", "api/model_intake_"))
        or path.startswith("scanner/scanner_tools/model_intake")
        or path in {
            "api/worker_handlers/model_intake.py",
            "scanner/Dockerfile.model-intake",
            "tests/e2e/run_model_intake_physical_acceptance.py",
        }
    ):
        return "model_intake"
    if (
        path.startswith(("api/ai_gate/", "api/ai_gate_"))
        or path == "api/worker_handlers/ai_gate.py"
    ):
        return "ai_gate"
    if path.startswith("api/hunt/") or path == "tests/e2e/hunt_authz_proof.py":
        return "hunt"
    return None


def e2e_area(paths: Iterable[str]) -> str:
    changed = set(paths)
    runtime = {
        path for path in changed
        if not (
            (path.startswith("docs/") or path.startswith("ui/"))
            and path not in BACKEND_FILES
        )
        and not (path.startswith("tests/") and not path.startswith("tests/e2e/"))
    }
    areas = {isolated_e2e_area(path) for path in runtime}
    return next(iter(areas)) if len(areas) == 1 and None not in areas else "all"


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
    print(f"e2e_area={e2e_area(paths)}")


if __name__ == "__main__":
    main()
