from __future__ import annotations

import sys
from pathlib import Path

import pytest

from tests.api_sources import declared_routes, route_is_declared


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from scan.compatibility import (  # noqa: E402
    COMPATIBILITY_METRIC_KEY,
    compatibility_snapshot,
    record_compatibility_call,
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


def test_compatibility_telemetry_is_allowlisted_and_content_free():
    redis_client = _Redis()
    assert record_compatibility_call(redis_client, "raw_secret_scan") is True
    assert record_compatibility_call(redis_client, "raw_secret_scan") is True
    assert record_compatibility_call(redis_client, "cli_alias") is True
    with pytest.raises(ValueError):
        record_compatibility_call(redis_client, "https://secret.example/path?token=x")

    snapshot = compatibility_snapshot(redis_client)
    assert snapshot["available"] is True
    assert snapshot["write_surface"] == "removed"
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


def test_legacy_scan_writes_are_removed_and_canonical_clients_do_not_use_them():
    root = Path(__file__).resolve().parents[1]
    assert not (root / "api" / "scan" / "legacy.py").exists()
    assert not (root / ".claude" / "commands" / "scan-full.md").exists()
    assert not (root / ".claude" / "commands" / "scan-smart.md").exists()

    # Disposition contract for the deprecated surfaces: no writes anywhere under
    # api/, and exactly the bounded V1 reads that installed clients still need.
    assert not route_is_declared("POST", "/scans/compat")
    assert not route_is_declared("POST", "/scans/compat/batch")
    assert not route_is_declared("POST", "/api/v1/scan")
    assert route_is_declared("GET", "/api/v1/scan")
    surviving_v1 = sorted(
        (method, path)
        for method, path in declared_routes("/api/v1")
    )
    assert all(method == "GET" for method, _ in surviving_v1), (
        f"a non-read V1 route survives: {surviving_v1}"
    )

    cli_source = (root / "scripts" / "scan_cli.py").read_text()
    ui_source = "\n".join(
        path.read_text(errors="replace")
        for path in (root / "ui").rglob("*")
        if path.is_file() and path.suffix in {".ts", ".tsx", ".js", ".jsx"}
    )
    assert "/scans/compat" not in cli_source
    assert "/scans/compat" not in ui_source

    scanner_source = (root / "scanner.sh").read_text()
    assert "scan-full)" not in scanner_source
    assert "scan-smart)" not in scanner_source

    worker_contract = (root / "api" / "scan" / "worker_contract.py").read_text()
    assert "digest-less deterministic Scan execution has been removed" in worker_contract
    assert "translate_legacy" not in worker_contract
    assert "canonical=False" not in worker_contract
