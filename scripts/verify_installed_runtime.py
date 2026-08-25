#!/usr/bin/env python3
"""Verify the baked scanner/API runtime without importing a mounted checkout."""

from __future__ import annotations

import argparse
import compileall
import importlib
import json
from pathlib import Path
import sys


REQUIRED_MODULES = (
    "capabilities.inline",
    "hunt.action_dispatcher",
    "hunt.capability_executor",
    "runtime.capability_registry",
    "scan.authorization",
    "scan.execution",
    "scanner_tools.request_replay",
)
REQUIRED_FILES = ("api.py", "worker.py", "scanner.py", "release_identity.py")


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", type=Path, default=Path("/app"))
    args = parser.parse_args()
    root = args.runtime_root.resolve()
    if not root.is_dir():
        raise SystemExit(f"installed runtime root is absent: {root}")
    missing = [name for name in REQUIRED_FILES if not (root / name).is_file()]
    if missing:
        raise SystemExit(f"installed runtime files are absent: {', '.join(missing)}")

    # Keep the interpreter's standard-library and site-package paths, but put the
    # installed tree first and drop common checkout mount locations.  Imported
    # ShakerScan modules are checked below, so dependencies may still resolve
    # normally without allowing a mounted source tree to shadow /app.
    checkout_roots = (Path("/src"), Path("/workspace"))
    retained = []
    for item in sys.path:
        if not item:
            continue
        path = Path(item).resolve()
        if any(_within(path, checkout_root) for checkout_root in checkout_roots):
            continue
        if path != root:
            retained.append(item)
    sys.path[:] = [str(root), *retained]
    loaded: dict[str, str] = {}
    for name in REQUIRED_MODULES:
        module = importlib.import_module(name)
        source = Path(str(module.__file__ or "")).resolve()
        if not _within(source, root):
            raise SystemExit(f"{name} loaded outside installed runtime: {source}")
        loaded[name] = str(source)

    registry = importlib.import_module("runtime.capability_registry").CAPABILITY_REGISTRY
    candidate_verify = registry.require("candidate.verify")
    if candidate_verify.executor != "inline" or not candidate_verify.requires_active_approval:
        raise SystemExit("candidate.verify is not an approval-bound installed capability")
    if not compileall.compile_dir(root, quiet=1, force=False):
        raise SystemExit("installed runtime byte-compilation failed")
    print(json.dumps({
        "schema_version": "shakerscan-installed-runtime-check/v1",
        "status": "pass",
        "runtime_root": str(root),
        "loaded_modules": loaded,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
