from __future__ import annotations

from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.xfail(
    strict=True,
    reason="V2-P1-01: observation bodies still cross the scanner boundary in an environment variable",
)
def test_scan_placements_use_only_digest_checked_private_references():
    worker_source = (ROOT / "api" / "worker.py").read_text(encoding="utf-8")
    scanner_source = (ROOT / "scanner" / "scanner.py").read_text(encoding="utf-8")
    assert "SHAKERSCAN_CANONICAL_SCAN_PLACEMENTS" not in worker_source
    assert "SHAKERSCAN_CANONICAL_SCAN_PLACEMENTS" not in scanner_source
    assert (ROOT / "api" / "runtime" / "observation_manifests.py").is_file()
