import asyncio
import os
import sys
import time


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools import cancellation  # noqa: E402
from scanner_tools.common import run  # noqa: E402


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


def test_shared_runner_cancellation_reaps_child_process_group(monkeypatch, tmp_path):
    cancel_file = tmp_path / "scan.cancel"
    child_pid_file = tmp_path / "child.pid"
    monkeypatch.setenv("SHAKERSCAN_CANCEL_FILE", str(cancel_file))
    program = (
        "import pathlib,subprocess,time; "
        "p=subprocess.Popen(['sleep','60']); "
        f"pathlib.Path({str(child_pid_file)!r}).write_text(str(p.pid)); "
        "time.sleep(60)"
    )

    async def exercise():
        task = asyncio.create_task(run([sys.executable, "-c", program], timeout=30))
        for _ in range(100):
            if child_pid_file.exists():
                break
            await asyncio.sleep(0.01)
        assert child_pid_file.exists()
        cancel_file.write_text("1", encoding="utf-8")
        return await asyncio.wait_for(task, timeout=2)

    _out, error, returncode = asyncio.run(exercise())
    assert returncode == 130
    assert "cancellation" in error
    child_pid = int(child_pid_file.read_text())
    for _ in range(50):
        proc_stat = f"/proc/{child_pid}/stat"
        if os.path.exists(proc_stat):
            # A killed grandchild may remain as a short-lived zombie until the
            # container init reaps it; it is no longer executing probes.
            if open(proc_stat, encoding="utf-8").read().split()[2] == "Z":
                break
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.01)
    else:
        raise AssertionError(f"orphan child process remained alive: {child_pid}")


def test_shared_runner_callback_cancellation_stops_process_without_signal_file(monkeypatch):
    monkeypatch.delenv("SHAKERSCAN_CANCEL_FILE", raising=False)
    checks = 0

    async def cancelled():
        nonlocal checks
        checks += 1
        return checks >= 2

    _out, error, returncode = asyncio.run(
        run([sys.executable, "-c", "import time; time.sleep(60)"], timeout=30, cancel_check=cancelled)
    )
    assert returncode == 130
    assert "cancellation" in error
