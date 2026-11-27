"""Include activated V2 security packages in API/worker build freshness checks."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import build_fingerprint as _fingerprint


_MARKER = "_shakerscan_v2_package_fingerprint"
_V2_PACKAGES = ("capabilities", "hunt", "runtime", "scan")


def apply_v2_fingerprint_hardening() -> None:
    if getattr(_fingerprint.source_file_map, _MARKER, False):
        return

    original_source_file_map = _fingerprint.source_file_map
    original_runtime_file_map = _fingerprint.runtime_file_map

    def source_file_map(workspace_root: str = "/workspace") -> dict[str, str]:
        files = dict(original_source_file_map(workspace_root))
        api_root = Path(workspace_root) / "api"
        for package in _V2_PACKAGES:
            _fingerprint._add_tree(files, api_root / package, package)
        return files

    def runtime_file_map(
        runtime_root: str = "/app",
        model_intake_lock_root: str = "/opt/model-intake-locks",
        build_input_root: str = "/opt/build-inputs",
    ) -> dict[str, str]:
        files = dict(original_runtime_file_map(
            runtime_root,
            model_intake_lock_root,
            build_input_root,
        ))
        root = Path(runtime_root)
        for package in _V2_PACKAGES:
            _fingerprint._add_tree(files, root / package, package)
        return files

    setattr(source_file_map, _MARKER, True)
    setattr(runtime_file_map, _MARKER, True)
    _fingerprint.source_file_map = source_file_map
    _fingerprint.runtime_file_map = runtime_file_map


apply_v2_fingerprint_hardening()
