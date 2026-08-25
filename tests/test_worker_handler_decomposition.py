from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

from worker_handlers.non_dast import (  # noqa: E402
    NonDastWorkerHandler,
    NonDastWorkerServices,
)


def _handler(**overrides):
    events = []

    async def progress(*args, **kwargs):
        events.append((args, kwargs))

    @asynccontextmanager
    async def hydrate(options, _scan_id):
        yield dict(options)

    services = {
        "update_scan_progress": progress,
        "scan_cancel_requested": lambda _scan_id: False,
        "append_device_activity": lambda *args, **kwargs: None,
        "strip_null_bytes": lambda value: value,
        "get_redis": lambda: None,
        "hydrate_ai_gate_options": hydrate,
        "results_dir": ROOT / "tmp",
        "scan_log_tail": 200,
        "scan_log_ttl_seconds": 60,
    }
    services.update(overrides)
    return NonDastWorkerHandler(NonDastWorkerServices(**services)), events


def test_extracted_handler_rejects_deterministic_scan_and_unknown_run_kind():
    handler, _events = _handler()

    with pytest.raises(ValueError, match="monolithic deterministic Scan"):
        asyncio.run(handler.run("https://example.test", {}))
    with pytest.raises(ValueError, match="unsupported non-DAST"):
        asyncio.run(handler.run(
            "https://example.test", {"run_kind": "device_web_dast"},
        ))


def test_worker_handlers_are_not_monolith_wrappers():
    handlers = ROOT / "api" / "worker_handlers"
    sources = {
        path.name: path.read_text(encoding="utf-8")
        for path in handlers.glob("*.py")
    }
    non_dast = sources["non_dast.py"]

    assert "class NonDastWorkerHandler" in non_dast
    assert "run_device_service_probe" in non_dast
    assert "run_device_posture_scan" in non_dast
    assert "run_model_intake_scan" in non_dast
    assert "run_ai_target_scan" in non_dast
    for source in sources.values():
        assert "from worker import" not in source
        assert "import worker" not in source
        assert "from api import" not in source
        assert "import api" not in source
