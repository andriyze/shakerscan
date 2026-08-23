from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from api.scan.migration import (
    LEGACY_SCAN_EXECUTION_CUTOFF,
    LegacyScanExecutionExpired,
    require_legacy_scan_execution_window,
)


ROOT = Path(__file__).resolve().parents[1]


def test_digestless_scan_jobs_may_drain_only_before_fixed_cutoff(monkeypatch):
    monkeypatch.delenv("SHAKERSCAN_DISABLE_LEGACY_SCAN_EXECUTION", raising=False)
    require_legacy_scan_execution_window(
        now=LEGACY_SCAN_EXECUTION_CUTOFF - timedelta(microseconds=1),
    )

    with pytest.raises(LegacyScanExecutionExpired, match="canonical V2 Scan job"):
        require_legacy_scan_execution_window(now=LEGACY_SCAN_EXECUTION_CUTOFF)


def test_operator_can_close_legacy_window_early_but_cannot_extend_it(monkeypatch):
    monkeypatch.setenv("SHAKERSCAN_DISABLE_LEGACY_SCAN_EXECUTION", "true")
    with pytest.raises(LegacyScanExecutionExpired, match="expired"):
        require_legacy_scan_execution_window(
            now=datetime(2026, 8, 1, tzinfo=timezone.utc),
        )

    monkeypatch.delenv("SHAKERSCAN_DISABLE_LEGACY_SCAN_EXECUTION", raising=False)
    monkeypatch.setenv("SHAKERSCAN_LEGACY_SCAN_EXECUTION_DEADLINE", "2099-01-01")
    with pytest.raises(LegacyScanExecutionExpired, match="expired"):
        require_legacy_scan_execution_window(
            now=LEGACY_SCAN_EXECUTION_CUTOFF + timedelta(days=1),
        )


def test_every_worker_fallback_checks_the_same_code_owned_cutoff():
    worker = (ROOT / "api" / "worker.py").read_text(encoding="utf-8")
    broker = (ROOT / "api" / "broker_worker.py").read_text(encoding="utf-8")

    assert worker.count("require_legacy_scan_execution_window()") >= 2
    assert "require_legacy_scan_execution_window()\n                result = await run_scan(" in broker
