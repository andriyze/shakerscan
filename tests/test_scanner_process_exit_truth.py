"""A scanner that dies after emitting output yields a partial receipt, not a complete one.

Observed live with katana 1.7.0: its JavaScript parser exceeded the worker's memory limit
while crawling a Next.js site, the kernel killed the crawler after one output line, and the
scan reported its crawl as complete. Output written before the kill is trustworthy partial
coverage and must be labelled that way (AGENTS.md invariant 9).
"""
import asyncio
import json

import pytest

import worker


class _PinnedProxy:
    def __init__(self, **_kwargs):
        self.limit_exceeded = asyncio.Event()
        self.connection_attempts = 0
        self.connections_opened = 0
        self.connections_rejected = 0
        self.upstream_connection_attempts = 0
        self.address_attempts = {}
        self.address_connections = {}
        self.bytes_to_target = 0
        self.bytes_from_target = 0

    @property
    def proxy_url(self):
        return "socks5://127.0.0.1:41000"

    async def start(self):
        return self

    async def close(self):
        return None


class _Redis:
    def exists(self, _key):
        return False


class _Process:
    pid = 4242

    def __init__(self, returncode: int, stdout: bytes, stderr: bytes = b""):
        self.returncode = returncode
        self.stdout = asyncio.StreamReader()
        self.stderr = asyncio.StreamReader()
        self.stdout.feed_data(stdout)
        self.stdout.feed_eof()
        self.stderr.feed_data(stderr)
        self.stderr.feed_eof()

    async def wait(self):
        return self.returncode

    def kill(self):
        self.returncode = -9


_CRAWL_LINE = json.dumps({
    "timestamp": "2026-09-13T04:00:00Z",
    "request": {
        "method": "GET",
        "endpoint": "https://example.test/api/items?id=1",
        "tag": "a",
        "source": "https://example.test/",
    },
    "response": {"status_code": 200},
}).encode() + b"\n"


def _run_katana(
    monkeypatch, returncode: int, stdout: bytes, stderr: bytes = b"", launched: dict | None = None
) -> dict:
    monkeypatch.setattr(worker, "PinnedSocksProxy", _PinnedProxy)
    monkeypatch.setattr(worker, "get_redis", lambda: _Redis())

    async def _exec(*cmd, **_kwargs):
        if launched is not None:
            launched["cmd"] = list(cmd)
        # Stream readers bind to the running loop, so the fake is built here.
        return _Process(returncode, stdout, stderr)

    monkeypatch.setattr(worker.asyncio, "create_subprocess_exec", _exec)
    return asyncio.run(worker._execute_agent_scanner_process({
        "job_id": "crawl-job-1",
        "tool_name": "katana",
        "registered_target": "https://example.test",
        "execution_target": "https://example.test/",
        "scanner_options": {},
        "timeout_ms": 30_000,
        "pinned_address": "203.0.113.7",
        "authorized_addresses": ["203.0.113.7"],
        "_reserved_budget": {"http_requests": 20, "tool_wall_seconds": 30},
    }))


@pytest.mark.parametrize("returncode", [-9, 137, 1])
def test_crawler_killed_after_output_is_partial_with_its_exit_code(monkeypatch, returncode):
    result = _run_katana(monkeypatch, returncode, _CRAWL_LINE)

    assert result["status"] == "success"
    assert result["partial"] is True
    assert result["timed_out"] is False
    assert result["error"] == f"exit_{returncode}"
    assert result["returncode"] == returncode
    assert result["line_count"] == 1


def test_crawler_that_exits_cleanly_is_complete(monkeypatch):
    result = _run_katana(monkeypatch, 0, _CRAWL_LINE)

    assert result["status"] == "success"
    assert result["partial"] is False
    assert result["error"] is None
    assert result["line_count"] == 1


def test_crawler_killed_before_any_output_still_fails(monkeypatch):
    result = _run_katana(monkeypatch, -9, b"", b"fatal: out of memory\n")

    assert result["status"] == "failed"
    assert result["partial"] is False
    assert "out of memory" in result["error"]


def test_scanner_image_lifts_katana_javascript_parser_dependency():
    """katana 1.7.0 pins a tree-sitter snapshot whose string lexing is super-linear.

    Measured on the reference host: the release build was killed at 6 GiB while parsing
    one inline script of a Next.js page; the same source built with gotreesitter v0.52.0
    peaked at 599 MiB and found 427 endpoints on the same site.
    """
    from pathlib import Path

    dockerfile = (Path(__file__).resolve().parents[1] / "scanner" / "Dockerfile").read_text()
    builder = dockerfile.split("# --- Stage 2", 1)[0]
    # Extra module pins after the tool version are forwarded to `go get` per tool...
    assert 'shift 3; \\' in builder
    assert 'if [ "$#" -gt 0 ]; then go get "$@" || return 1; fi; \\' in builder
    # ...and katana carries the parser lift.
    katana_call = builder[builder.index("build_tool katana "):]
    katana_call = katana_call[:katana_call.index("build_tool subfinder")]
    assert "github.com/odvcencio/gotreesitter@v0.52.0" in katana_call


def test_crawler_runs_under_the_memory_bound_when_the_platform_provides_it(monkeypatch):
    monkeypatch.setattr(
        worker.deployment_policy,
        "crawler_memory_bound_argv",
        lambda name: ["/usr/bin/prlimit", "--data=2147483648", "--"] if name == "katana" else [],
    )
    launched: dict = {}
    result = _run_katana(monkeypatch, 0, _CRAWL_LINE, launched=launched)
    assert result["status"] == "success"
    assert launched["cmd"][:3] == ["/usr/bin/prlimit", "--data=2147483648", "--"]
    assert launched["cmd"][3].endswith("katana")


def test_crawler_stopped_by_its_memory_bound_is_named_as_such(monkeypatch):
    """Go reports a refused allocation as exit 2 with a fatal runtime error on stderr."""
    result = _run_katana(monkeypatch, 2, _CRAWL_LINE, b"fatal error: runtime: out of memory\n")
    assert result["status"] == "success" and result["partial"] is True
    assert result["error"] == "crawler_memory_bound_exceeded"
    silent = _run_katana(monkeypatch, 2, b"", b"fatal error: runtime: out of memory\n")
    assert silent["status"] == "failed"
    assert silent["error"] == "crawler_memory_bound_exceeded"


def test_proxy_connection_ceiling_keeps_its_failure_reason_after_killing_tool(monkeypatch):
    class LimitedProxy(_PinnedProxy):
        async def start(self):
            self.connection_attempts = 401
            self.connections_rejected = 1
            asyncio.get_running_loop().call_soon(self.limit_exceeded.set)
            return self

    class RunningProcess(_Process):
        def __init__(self):
            super().__init__(0, b"")
            self._done = asyncio.Event()

        async def wait(self):
            await self._done.wait()
            return self.returncode

        def kill(self):
            self.returncode = -9
            self._done.set()

    monkeypatch.setattr(worker, "PinnedSocksProxy", LimitedProxy)
    monkeypatch.setattr(worker, "get_redis", lambda: _Redis())
    monkeypatch.setattr(worker, "_terminate_agent_tool_process_group", lambda proc: proc.kill())

    async def _exec(*_cmd, **_kwargs):
        return RunningProcess()

    monkeypatch.setattr(worker.asyncio, "create_subprocess_exec", _exec)
    result = asyncio.run(worker._execute_agent_scanner_process({
        "job_id": "bounded-xss-job",
        "tool_name": "dalfox",
        "registered_target": "https://example.test",
        "execution_target": "https://example.test/search?q=test",
        "scanner_options": {"deep_domxss": True},
        "pinned_address": "203.0.113.7",
        "authorized_addresses": ["203.0.113.7"],
        "_reserved_budget": {"http_requests": 400, "tool_wall_seconds": 120},
    }))

    assert result["status"] == "failed"
    assert result["error"] == "connection_limit_exceeded"
    assert result["returncode"] == -9
    assert result["network_telemetry"]["connections_attempted"] == 401
    assert result["network_telemetry"]["connections_rejected"] == 1
