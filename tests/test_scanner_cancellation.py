import asyncio
import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools import cancellation  # noqa: E402


def test_scanner_cancel_requested_uses_worker_signal_file(monkeypatch, tmp_path):
    cancel_file = tmp_path / "scan.cancel"
    monkeypatch.setenv("SHAKERSCAN_CANCEL_FILE", str(cancel_file))

    assert cancellation.scanner_cancel_requested() is False
    cancel_file.write_text("1", encoding="utf-8")
    assert cancellation.scanner_cancel_requested() is True


def test_wait_for_scanner_cancel_observes_signal(monkeypatch, tmp_path):
    cancel_file = tmp_path / "scan.cancel"
    monkeypatch.setenv("SHAKERSCAN_CANCEL_FILE", str(cancel_file))

    async def exercise():
        waiter = asyncio.create_task(cancellation.wait_for_scanner_cancel(poll_seconds=0.01))
        await asyncio.sleep(0.02)
        cancel_file.write_text("1", encoding="utf-8")
        return await asyncio.wait_for(waiter, timeout=0.2)

    assert asyncio.run(exercise()) is True
