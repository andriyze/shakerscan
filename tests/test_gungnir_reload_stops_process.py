"""The CT monitor's periodic domain reload stops the gungnir process it started, and an address
root is never monitored (unit tests with a stand-in gungnir executable; no DB or Redis)."""

from __future__ import annotations

import asyncio
import importlib.util
import os
from pathlib import Path
import sys
import time
import types

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def gungnir(monkeypatch):
    monkeypatch.setitem(sys.modules, "redis", types.SimpleNamespace(Redis=object, from_url=lambda *_a, **_k: None))
    monkeypatch.setitem(sys.modules, "asyncpg", types.SimpleNamespace(create_pool=None))
    monkeypatch.syspath_prepend(str(ROOT / "api"))
    spec = importlib.util.spec_from_file_location("gungnir_reload_under_test", ROOT / "api" / "gungnir_worker.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # A zombie still answers kill(0); on Linux its state is Z.
    stat = Path(f"/proc/{pid}/stat")
    return not (stat.exists() and stat.read_text().split(")")[-1].split()[0] == "Z")


def test_reload_timeout_stops_the_running_gungnir(gungnir, tmp_path, monkeypatch):
    pidfile = tmp_path / "pid"
    fake = tmp_path / "gungnir"
    fake.write_text(f"#!/bin/sh\necho $$ > {pidfile}\nexec sleep 60\n")
    fake.chmod(0o755)
    monkeypatch.setattr(gungnir, "GUNGNIR_BIN", str(fake))

    async def reload_once():
        with pytest.raises(asyncio.TimeoutError):
            # monitor_loop's reload: wait_for cancels run_gungnir after the interval
            await asyncio.wait_for(gungnir.run_gungnir(["example.com"]), timeout=1.5)

    asyncio.run(reload_once())
    pid = int(pidfile.read_text())
    deadline = time.time() + 2
    while alive(pid) and time.time() < deadline:
        time.sleep(0.05)
    assert not alive(pid), "the reload left the previous gungnir running"


def test_an_address_root_is_not_monitored(gungnir):
    assert gungnir.monitored_roots(["172.17.0.1", "example.com", "2001:db8::1", "[::1]", "10.0.0.5"]) == ["example.com"]


def test_reload_also_stops_a_process_gungnir_started(gungnir, tmp_path, monkeypatch):
    pidfile, childfile = tmp_path / "pid", tmp_path / "child"
    fake = tmp_path / "gungnir"
    fake.write_text(f"#!/bin/sh\nsleep 60 &\necho $! > {childfile}\necho $$ > {pidfile}\nwait\n")
    fake.chmod(0o755)
    monkeypatch.setattr(gungnir, "GUNGNIR_BIN", str(fake))

    async def reload_once():
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(gungnir.run_gungnir(["example.com"]), timeout=1.5)

    asyncio.run(reload_once())
    pids = [int(pidfile.read_text()), int(childfile.read_text())]
    deadline = time.time() + 2
    while any(alive(pid) for pid in pids) and time.time() < deadline:
        time.sleep(0.05)
    assert not any(alive(pid) for pid in pids), "the reload left gungnir or a process it started running"


def test_shutdown_stops_gungnir(gungnir, tmp_path, monkeypatch):
    # The worker's SIGTERM handler sets shutdown_event; run_gungnir returns and stops the process.
    pidfile = tmp_path / "pid"
    fake = tmp_path / "gungnir"
    fake.write_text(f"#!/bin/sh\necho $$ > {pidfile}\nexec sleep 60\n")
    fake.chmod(0o755)
    monkeypatch.setattr(gungnir, "GUNGNIR_BIN", str(fake))

    async def run_then_shut_down():
        gungnir.shutdown_event.clear()
        task = asyncio.ensure_future(gungnir.run_gungnir(["example.com"]))
        while not pidfile.exists():
            await asyncio.sleep(0.05)
        gungnir.shutdown_event.set()
        await asyncio.wait_for(task, timeout=10)

    asyncio.run(run_then_shut_down())
    pid = int(pidfile.read_text())
    assert not alive(pid), "worker shutdown left gungnir running"


def test_a_stop_ends_an_idle_monitor_at_once(gungnir, monkeypatch):
    """With no domain to watch the monitor waits a minute between looks; a stop signal must not
    wait for that minute to pass (Docker kills the container ten seconds after the signal)."""

    async def no_domains():
        return []

    monkeypatch.setattr(gungnir, "get_monitored_domains", no_domains)

    async def stop_while_idle() -> float:
        loop = asyncio.create_task(gungnir.monitor_loop())
        await asyncio.sleep(0.2)
        assert gungnir.stats["running"] is True
        asked = time.monotonic()
        gungnir.handle_shutdown(15, None)
        await asyncio.wait_for(loop, timeout=3)
        return time.monotonic() - asked

    assert asyncio.run(stop_while_idle()) < 1
    assert gungnir.stats["running"] is False
