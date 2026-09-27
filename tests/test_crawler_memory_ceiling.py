"""A runaway crawl is stopped by its own memory ceiling and reported partial.

Observed on EKS (2026-09-13): katana with JavaScript crawling grew from 100 MiB to more than
7.5 GiB in about 20 s on a JavaScript-heavy site, and the kernel OOM-killed the whole scan
worker at 4 GiB and again at 8 GiB. The 2.3.2 bound (``prlimit --data``) covered only the
static crawler: the headless crawler was exempt, and a per-process ``RLIMIT_DATA`` cannot
bound a browser tree anyway -- Chromium runs a zygote, GPU, network and one renderer per
tab, in process groups of their own. The supervisor now measures the whole tree and kills
it at ``SHAKERSCAN_CRAWLER_MEMORY_LIMIT_MB``; what the crawler wrote before that is kept
and labelled partial with ``crawler_memory_bound_exceeded``, never complete.
"""
from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
import time
from types import SimpleNamespace

import pytest

import agent_tools as at
import deployment_policy as policy
import worker
from scan.capability_result import CapabilityResultReason
from scan.coverage_rollup import action_coverage_reasons
from scan.execution_backend import PostgresScanExecutionBackend
from scanner.scanner_tools import discovery
from scanner.scanner_tools.common import run_streaming
from scanner_tools import process_memory

MiB = 1024 * 1024
LINUX_PROC = sys.platform.startswith("linux") and os.path.exists("/proc/self/smaps_rollup")
needs_linux_proc = pytest.mark.skipif(not LINUX_PROC, reason="the ceiling reads Linux /proc")


def _value(argv, flag):
    assert flag in argv, f"{flag} missing from crawler argv"
    return argv[argv.index(flag) + 1]


# --- the crawler's own limits -------------------------------------------------------------


@pytest.mark.parametrize("tool", ["katana", "katana_headless"])
def test_both_crawl_paths_state_their_own_bounds(tool):
    plan = at.build_enforced_scanner_plan(
        tool, "http://app.test/", {},
        reserved_budget={"http_requests": 600, "tool_wall_seconds": 150},
    )
    argv = plan.argv
    assert int(_value(argv, "-depth")) == 2
    assert int(_value(argv, "-concurrency")) <= 5
    assert _value(argv, "-parallelism") == "1"
    assert _value(argv, "-crawl-duration").endswith("s")
    assert int(_value(argv, "-max-response-size")) == 4 * MiB
    # A page cap that never cuts a crawl the reservation funds: katana ends a capped
    # crawl with exit 0, which would read as complete.
    pages = int(_value(argv, "-max-domain-pages"))
    duration = int(_value(argv, "-crawl-duration").removesuffix("s"))
    assert pages >= dict(plan.hard_budget)["http_requests"] >= duration


def test_the_browser_bounds_each_tab_heap_and_its_renderer_count():
    argv = at.build_enforced_scanner_plan(
        "katana_headless", "http://app.test/", {},
        reserved_budget={"http_requests": 600, "tool_wall_seconds": 150},
    ).argv
    options = _value(argv, "-headless-options").split(",")
    assert "--js-flags=--max-old-space-size=512" in options
    assert "--renderer-process-limit=4" in options


def test_legacy_discovery_crawl_is_bounded_by_the_same_ceiling(monkeypatch):
    captured = {}

    async def fake_stream(cmd, **kwargs):
        captured["cmd"], captured["kwargs"] = cmd, kwargs
        return SimpleNamespace(timed_out=False, partial=False, cancelled=False, returncode=0)

    monkeypatch.setattr(discovery, "run_streaming", fake_stream)
    monkeypatch.setattr(policy, "container_memory_limit_bytes", lambda: None)
    monkeypatch.setenv(policy.CRAWLER_MEMORY_LIMIT_MB_ENV, "1536")
    asyncio.run(discovery.run_katana_stream("katana", "https://example.test", 3, lambda _l: None))

    assert captured["kwargs"]["memory_limit_bytes"] == 1536 * MiB
    assert _value(captured["cmd"], "-parallelism") == "1"
    assert int(_value(captured["cmd"], "-max-response-size")) == 4 * MiB


# --- the ceiling policy ---------------------------------------------------------------------


def test_every_crawler_including_the_headless_one_gets_a_ceiling():
    unlimited = lambda: None  # noqa: E731
    assert policy.crawler_memory_ceiling("katana", environ={}, container_limit=unlimited) == (
        2048 * MiB, "configured",
    )
    assert policy.crawler_memory_ceiling(
        "katana_headless", environ={policy.CRAWLER_MEMORY_LIMIT_MB_ENV: "3072"},
        container_limit=unlimited,
    ) == (3072 * MiB, "configured")
    assert policy.crawler_memory_ceiling("nuclei", environ={}, container_limit=unlimited)[0] == 0
    assert policy.crawler_memory_ceiling(
        "katana_headless", environ={policy.CRAWLER_MEMORY_LIMIT_MB_ENV: "0"},
        container_limit=unlimited,
    ) == (0, "disabled")


def test_the_ceiling_stays_below_the_worker_containers_own_limit():
    """A ceiling above the container's limit is no ceiling: the kernel kills the worker."""
    two_gib_container = lambda: 2048 * MiB  # noqa: E731
    limit, source = policy.crawler_memory_ceiling(
        "katana_headless", environ={}, container_limit=two_gib_container,
    )
    assert source == "container_limit_share"
    assert limit == int(2048 * MiB * policy.CRAWLER_CONTAINER_MEMORY_SHARE) < 2048 * MiB
    # A roomy container keeps the configured value.
    assert policy.crawler_memory_ceiling(
        "katana", environ={}, container_limit=lambda: 8192 * MiB,
    ) == (2048 * MiB, "configured")


def test_cgroup_limits_are_read_for_v2_and_v1_and_unlimited_is_none():
    def reader(files):
        def read(path):
            if path not in files:
                raise FileNotFoundError(path)
            return files[path]
        return read

    assert policy.container_memory_limit_bytes(reader({"/sys/fs/cgroup/memory.max": "4294967296\n"})) == 4 * 1024 * MiB
    assert policy.container_memory_limit_bytes(reader({"/sys/fs/cgroup/memory.max": "max\n"})) is None
    assert policy.container_memory_limit_bytes(
        reader({"/sys/fs/cgroup/memory/memory.limit_in_bytes": "9223372036854771712"})
    ) is None
    assert policy.container_memory_limit_bytes(
        reader({"/sys/fs/cgroup/memory/memory.limit_in_bytes": "2147483648"})
    ) == 2048 * MiB
    assert policy.container_memory_limit_bytes(reader({})) is None


def test_go_collects_harder_well_before_the_ceiling():
    assert policy.crawler_memory_environment("katana", 2048 * MiB) == {"GOMEMLIMIT": "1536MiB"}
    assert policy.crawler_memory_environment("katana_headless", 2048 * MiB) == {"GOMEMLIMIT": "512MiB"}
    assert policy.crawler_memory_environment("katana", 0) == {}
    assert policy.crawler_memory_environment("httpx", 2048 * MiB) == {}


# --- measuring the tree ---------------------------------------------------------------------


def _fake_proc(root, pid, *, ppid, session, pss_kib=None, rss_pages=None, comm="tool"):
    base = root / str(pid)
    base.mkdir()
    # pid (comm) state ppid pgrp session ...
    (base / "stat").write_text(f"{pid} ({comm}) S {ppid} {pid} {session} 0 0 0\n")
    if pss_kib is not None:
        (base / "smaps_rollup").write_text(f"Rss: {pss_kib * 2} kB\nPss: {pss_kib} kB\n")
    if rss_pages is not None:
        (base / "statm").write_text(f"100000 {rss_pages} 0 0 0 0 0\n")


def test_the_tree_is_the_tools_session_plus_anything_that_left_it(tmp_path):
    _fake_proc(tmp_path, 100, ppid=1, session=100, pss_kib=1000)             # katana
    _fake_proc(tmp_path, 101, ppid=100, session=100, pss_kib=2000)           # leakless
    _fake_proc(tmp_path, 102, ppid=101, session=100, pss_kib=3000,
               comm="chrome (browser) x")                                     # browser, own pgid
    _fake_proc(tmp_path, 103, ppid=102, session=103, pss_kib=4000)           # setsid'd child
    _fake_proc(tmp_path, 104, ppid=103, session=103, rss_pages=10)           # its child, no smaps
    _fake_proc(tmp_path, 200, ppid=1, session=200, pss_kib=999_999)          # the worker itself
    (tmp_path / "self").mkdir()

    assert process_memory.process_tree(100, proc_root=tmp_path) == [100, 101, 102, 103, 104]
    expected = (1000 + 2000 + 3000 + 4000) * 1024 + 10 * process_memory._PAGE_SIZE
    assert process_memory.process_tree_memory_bytes(100, proc_root=tmp_path) == expected


def test_kill_snapshots_descendants_before_root_group_can_reparent_them(monkeypatch, tmp_path):
    _fake_proc(tmp_path, 100, ppid=1, session=100)
    _fake_proc(tmp_path, 101, ppid=100, session=101)  # browser left the tool's group
    killed = []

    def kill_group(_pid, _signal):
        # Linux reparents the browser as soon as its parent dies.
        (tmp_path / "101" / "stat").write_text("101 (browser) S 1 101 101 0 0 0\n")

    monkeypatch.setattr(process_memory.os, "killpg", kill_group)
    monkeypatch.setattr(process_memory.os, "kill", lambda pid, _signal: killed.append(pid))

    process_memory.kill_process_tree(100, proc_root=tmp_path)
    assert 101 in killed


def test_the_ceiling_samples_at_its_interval_and_stays_crossed():
    samples = iter([10 * MiB, 50 * MiB, 200 * MiB, 1])
    now = [0.0]
    ceiling = process_memory.ProcessTreeMemoryCeiling(
        1, 100 * MiB, sample=lambda: next(samples), clock=lambda: now[0], interval=0.25,
    )
    assert ceiling.over_ceiling() is False          # 10 MiB
    assert ceiling.over_ceiling() is False          # inside the interval: no sample
    now[0] = 0.3
    assert ceiling.over_ceiling() is False          # 50 MiB
    now[0] = 0.6
    assert ceiling.over_ceiling() is True           # 200 MiB
    now[0] = 0.9
    assert ceiling.over_ceiling() is True           # sticky; not resampled
    receipt = ceiling.receipt()
    assert receipt["exceeded"] is True and receipt["peak_bytes"] == 200 * MiB
    assert receipt["limit_bytes"] == 100 * MiB and receipt["enforced"] is True


def test_a_disabled_ceiling_never_fires():
    ceiling = process_memory.ProcessTreeMemoryCeiling(1, 0, sample=lambda: 1 << 40)
    assert ceiling.enforced is False
    assert ceiling.over_ceiling() is False


# --- the worker records the stop truthfully --------------------------------------------------


class _PinnedProxy:
    def __init__(self, **_kwargs):
        self.limit_exceeded = asyncio.Event()

    proxy_url = "socks5://127.0.0.1:41000"

    async def start(self):
        return self

    async def close(self):
        return None


class _Redis:
    def exists(self, _key):
        return False


_CRAWL_LINE = json.dumps({
    "timestamp": "2026-09-13T04:00:00Z",
    "request": {"method": "GET", "endpoint": "https://example.test/api/items?id=1",
                "tag": "a", "source": "https://example.test/"},
    "response": {"status_code": 200},
})


def _run_crawl(monkeypatch, *, tool="katana", launch=None, ceiling_factory=None):
    monkeypatch.setattr(worker, "PinnedSocksProxy", _PinnedProxy)
    monkeypatch.setattr(worker, "get_redis", lambda: _Redis())
    if ceiling_factory is not None:
        monkeypatch.setattr(worker, "ProcessTreeMemoryCeiling", ceiling_factory)
    if launch is not None:
        monkeypatch.setattr(worker.asyncio, "create_subprocess_exec", launch)
    return asyncio.run(worker._execute_agent_scanner_process({
        "job_id": "crawl-job-mem",
        "tool_name": tool,
        "registered_target": "https://example.test",
        "execution_target": "https://example.test/",
        "scanner_options": {},
        "timeout_ms": 60_000,
        "pinned_address": "203.0.113.7",
        "authorized_addresses": ["203.0.113.7"],
        "_reserved_budget": {"http_requests": 600, "tool_wall_seconds": 60},
    }))


class _RunningCrawler:
    """A crawler that has written one record and keeps running until killed."""

    pid = 4242

    def __init__(self):
        self.returncode = None
        self.stdout = asyncio.StreamReader()
        self.stderr = asyncio.StreamReader()
        self.stdout.feed_data(_CRAWL_LINE.encode() + b"\n")
        self._done = asyncio.Event()

    async def wait(self):
        await self._done.wait()
        return self.returncode

    def kill(self):
        self.returncode = -9
        self.stdout.feed_eof()
        self.stderr.feed_eof()
        self._done.set()


class _CrossedCeiling:
    instances: list = []

    def __init__(self, pid, limit_bytes, *, source="configured"):
        self.limit_bytes, self.source, self.exceeded = limit_bytes, source, False
        self.killed = False
        _CrossedCeiling.instances.append(self)

    def over_ceiling(self):
        self.exceeded = True
        return True

    def receipt(self):
        return {"exceeded": self.exceeded, "limit_bytes": self.limit_bytes,
                "limit_source": self.source}


@pytest.mark.parametrize("tool", ["katana", "katana_headless"])
def test_a_crawl_stopped_at_its_ceiling_is_partial_and_names_the_reason(monkeypatch, tool):
    running: list[_RunningCrawler] = []

    async def launch(*_cmd, **_kwargs):
        running.append(_RunningCrawler())
        return running[-1]

    monkeypatch.setattr(worker, "_terminate_agent_tool_process_group", lambda proc: proc.kill())
    monkeypatch.setattr(worker.deployment_policy, "container_memory_limit_bytes", lambda: None)
    monkeypatch.setenv(policy.CRAWLER_MEMORY_LIMIT_MB_ENV, "2048")
    _CrossedCeiling.instances.clear()
    result = _run_crawl(monkeypatch, tool=tool, launch=launch, ceiling_factory=_CrossedCeiling)

    assert _CrossedCeiling.instances[0].limit_bytes == 2048 * MiB
    assert running[0].returncode == -9, "the supervisor must stop the tool, not wait for the kernel"
    assert result["status"] == "success"
    assert result["partial"] is True
    assert result["timed_out"] is False
    assert result["error"] == "crawler_memory_bound_exceeded"
    assert result["line_count"] == 1
    assert result["memory_ceiling"]["exceeded"] is True


def test_the_crawler_runs_with_a_go_soft_limit(monkeypatch):
    seen = {}

    class _Done:
        pid = 4242
        returncode = 0

        def __init__(self):
            self.stdout = asyncio.StreamReader()
            self.stderr = asyncio.StreamReader()
            self.stdout.feed_data(_CRAWL_LINE.encode() + b"\n")
            self.stdout.feed_eof()
            self.stderr.feed_eof()

        async def wait(self):
            return 0

    async def launch(*_cmd, env=None, **_kwargs):
        seen["env"] = env
        return _Done()

    monkeypatch.setattr(worker.deployment_policy, "container_memory_limit_bytes", lambda: None)
    monkeypatch.setenv(policy.CRAWLER_MEMORY_LIMIT_MB_ENV, "2048")
    result = _run_crawl(monkeypatch, launch=launch)
    assert result["status"] == "success" and result["partial"] is False
    assert result["error"] is None
    assert result["memory_ceiling"]["exceeded"] is False
    assert seen["env"]["GOMEMLIMIT"] == "1536MiB"


def test_the_stop_reaches_coverage_as_the_memory_reason_not_truncation():
    receipt = SimpleNamespace(errors=("crawler_memory_bound_exceeded",))
    reason = PostgresScanExecutionBackend._receipt_reason(
        receipt, CapabilityResultReason.OUTPUT_TRUNCATED,
    )
    assert reason is CapabilityResultReason.CRAWLER_MEMORY_BOUND_EXCEEDED
    assert action_coverage_reasons([{
        "capability_name": "web.browser_crawl", "status": "partial",
        "reason_code": reason.value, "required": True,
    }]) == ["web_browser_crawl_partial:crawler_memory_bound_exceeded"]


# --- real process trees (Linux) -------------------------------------------------------------

# A parent that writes one record, then starts a grandchild in a process group of its own
# (as katana starts Chromium) which allocates until something stops it.
_HOG_TREE = r"""
import os, subprocess, sys, time
print('{"request":{"method":"GET","endpoint":"https://example.test/a"}}', flush=True)
child = subprocess.Popen([sys.executable, "-c",
    "import time\nblocks = []\nwhile True:\n    blocks.append(bytearray(8 << 20))\n    time.sleep(0.02)\n"],
    process_group=0)
print(child.pid, file=sys.stderr, flush=True)
time.sleep(60)
"""


def _alive(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/stat") as handle:
            return handle.read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


@needs_linux_proc
def test_run_streaming_kills_a_tree_that_crosses_the_ceiling():
    started = time.monotonic()
    result = asyncio.run(run_streaming(
        [sys.executable, "-c", _HOG_TREE], soft_timeout=30, flush_grace=1, hard_timeout=40,
        memory_limit_bytes=96 * MiB,
    ))
    assert time.monotonic() - started < 20
    assert result.memory_limit_exceeded is True
    assert result.status == "partial" and result.partial is True
    assert result.timed_out is False
    assert result.stdout.strip().endswith('"https://example.test/a"}}')
    grandchild = int(result.stderr.split()[0])
    deadline = time.monotonic() + 5
    while _alive(grandchild) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not _alive(grandchild), "the grandchild in its own process group must be killed"


@needs_linux_proc
def test_run_streaming_cancellation_kills_a_browser_in_its_own_group():
    started = time.monotonic()
    result = asyncio.run(run_streaming(
        [sys.executable, "-c", _HOG_TREE], soft_timeout=5, flush_grace=1, hard_timeout=8,
        cancel_check=lambda: time.monotonic() - started > 0.2,
    ))
    grandchild = int(result.stderr.split()[0])
    try:
        assert result.cancelled is True and result.status == "cancelled"
        deadline = time.monotonic() + 5
        while _alive(grandchild) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not _alive(grandchild)
    finally:
        if _alive(grandchild):
            os.kill(grandchild, signal.SIGKILL)


@needs_linux_proc
def test_run_streaming_is_unaffected_below_the_ceiling():
    result = asyncio.run(run_streaming(
        [sys.executable, "-c", "print('ok')"], soft_timeout=10, flush_grace=1, hard_timeout=12,
        memory_limit_bytes=512 * MiB,
    ))
    assert result.status == "succeeded" and result.memory_limit_exceeded is False
    assert result.partial is False and result.stdout.strip() == "ok"


@needs_linux_proc
def test_worker_stops_a_real_runaway_crawler_tree_and_records_it_partial(monkeypatch):
    real_exec = asyncio.create_subprocess_exec

    async def launch(*_cmd, **kwargs):
        # The crawler's argv is replaced by the memory hog; the supervision is the real one.
        return await real_exec(sys.executable, "-c", _HOG_TREE, **kwargs)

    monkeypatch.setattr(worker.deployment_policy, "container_memory_limit_bytes", lambda: None)
    monkeypatch.setattr(worker.deployment_policy, "crawler_memory_bound_argv", lambda *_a, **_k: [])
    monkeypatch.setenv(policy.CRAWLER_MEMORY_LIMIT_MB_ENV, "96")
    started = time.monotonic()
    result = _run_crawl(monkeypatch, tool="katana_headless", launch=launch)

    assert time.monotonic() - started < 30
    assert result["status"] == "success" and result["partial"] is True
    assert result["error"] == "crawler_memory_bound_exceeded"
    assert result["returncode"] == -signal.SIGKILL
    ceiling = result["memory_ceiling"]
    assert ceiling["exceeded"] is True and ceiling["enforced"] is True
    assert ceiling["limit_bytes"] == 96 * MiB <= ceiling["peak_bytes"]
