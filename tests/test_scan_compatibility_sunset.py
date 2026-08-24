from __future__ import annotations

from datetime import datetime, timezone
import sys
from pathlib import Path

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from scan.compatibility import (  # noqa: E402
    COMPATIBILITY_METRIC_KEY,
    CompatibilitySunsetError,
    compatibility_snapshot,
    record_compatibility_call,
    require_raw_secret_compatibility,
)


class _Redis:
    def __init__(self):
        self.values: dict[bytes, bytes] = {}

    def hincrby(self, key, field, amount):
        assert key == COMPATIBILITY_METRIC_KEY
        name = str(field).encode()
        self.values[name] = str(int(self.values.get(name, b"0")) + amount).encode()

    def hgetall(self, key):
        assert key == COMPATIBILITY_METRIC_KEY
        return dict(self.values)


def test_raw_secret_bridge_fails_closed_at_the_documented_sunset():
    require_raw_secret_compatibility(
        now=datetime(2026, 12, 31, 23, 59, 58, tzinfo=timezone.utc),
    )
    with pytest.raises(CompatibilitySunsetError):
        require_raw_secret_compatibility(
            now=datetime(2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
        )


def test_compatibility_telemetry_is_allowlisted_and_content_free():
    redis_client = _Redis()
    assert record_compatibility_call(redis_client, "raw_secret_scan") is True
    assert record_compatibility_call(redis_client, "raw_secret_scan") is True
    assert record_compatibility_call(redis_client, "cli_alias") is True
    with pytest.raises(ValueError):
        record_compatibility_call(redis_client, "https://secret.example/path?token=x")

    snapshot = compatibility_snapshot(
        redis_client,
        now=datetime(2026, 8, 24, tzinfo=timezone.utc),
    )
    assert snapshot["available"] is True
    assert snapshot["sunset_reached"] is False
    assert snapshot["total_calls"] == 3
    assert snapshot["calls"]["raw_secret_scan"] == 2
    assert snapshot["calls"]["cli_alias"] == 1
    assert snapshot["content_free"] is True


def test_compatibility_telemetry_failure_never_changes_admission():
    class BrokenRedis:
        def hincrby(self, *_args):
            raise RuntimeError("offline")

        def hgetall(self, *_args):
            raise RuntimeError("offline")

    assert record_compatibility_call(BrokenRedis(), "raw_secret_batch") is False
    assert compatibility_snapshot(BrokenRedis())["available"] is False


def test_raw_secret_routes_are_deadline_gated_and_canonical_clients_do_not_use_them():
    root = Path(__file__).resolve().parents[1]
    api_source = (root / "api" / "api.py").read_text()
    scan_route = api_source[
        api_source.index("async def submit_scan_compat"):
        api_source.index("def _scan_requires_durable_approval")
    ]
    batch_route = api_source[
        api_source.index("async def submit_batch_compat"):
        api_source.index("async def _submit_batch")
    ]
    assert "require_raw_secret_compatibility()" in scan_route
    assert "require_raw_secret_compatibility()" in batch_route
    assert "status_code=410" in scan_route
    assert "status_code=410" in batch_route

    cli_source = (root / "scripts" / "scan_cli.py").read_text()
    ui_source = "\n".join(
        path.read_text(errors="replace")
        for path in (root / "ui").rglob("*")
        if path.is_file() and path.suffix in {".ts", ".tsx", ".js", ".jsx"}
    )
    assert "/scans/compat" not in cli_source
    assert "/scans/compat" not in ui_source
