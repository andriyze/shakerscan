"""A memory ceiling for a tool's whole process tree, enforced from outside it.

A headless crawl is not one process. katana launches a ``leakless`` guardian in its own
process group, which launches Chromium in another, which forks a zygote, a GPU process, a
network service and one renderer per tab. ``RLIMIT_DATA`` (``prlimit --data``) is per
process and inherited, so N browser processes may each use the whole limit, and a
``killpg`` of katana's group leaves the browser groups running. Inside a container there is
no per-process cgroup to delegate to either. So the supervisor measures the tree itself:
every process in the tool's session (the tool is started with ``start_new_session``) plus
anything descended from it, summed by proportional set size (PSS, so pages the browser
processes share are not counted once per process), and SIGKILLs all of it at the ceiling.
The caller then reports the run as stopped by its memory ceiling, never as complete.

Linux only (it reads ``/proc``). Elsewhere the ceiling reports itself as not enforced.
"""
from __future__ import annotations

import os
import signal
import time
from pathlib import Path
from typing import Callable, Iterable

MEMORY_CEILING_SCHEMA = "process-tree-memory-ceiling/v1"
_PAGE_SIZE = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096


def _stat_fields(proc_root: Path, pid: int) -> tuple[int, int] | None:
    """``(ppid, session)`` of a process, or None when it is gone or unreadable."""
    try:
        raw = (proc_root / str(pid) / "stat").read_text()
    except OSError:
        return None
    # The command name is parenthesised and may itself contain spaces or parentheses.
    fields = raw[raw.rfind(")") + 2:].split()
    try:
        return int(fields[1]), int(fields[3])
    except (IndexError, ValueError):
        return None


def process_tree(root_pid: int, *, proc_root: str | Path = "/proc") -> list[int]:
    """Every live process in ``root_pid``'s session or descended from it, root first."""
    root = Path(proc_root)
    parents: dict[int, int] = {}
    members: set[int] = set()
    try:
        entries = [int(name) for name in os.listdir(root) if name.isdigit()]
    except OSError:
        return []
    for pid in entries:
        fields = _stat_fields(root, pid)
        if fields is None:
            continue
        ppid, session = fields
        parents[pid] = ppid
        if pid == root_pid or session == root_pid:
            members.add(pid)
    # Descendants that left the session (setsid) are still the tool's processes.
    changed = True
    while changed:
        changed = False
        for pid, ppid in parents.items():
            if pid not in members and ppid in members:
                members.add(pid)
                changed = True
    return sorted(members, key=lambda pid: (pid != root_pid, pid))


def process_memory_bytes(pid: int, *, proc_root: str | Path = "/proc") -> int:
    """Proportional set size of one process, falling back to its resident set size."""
    base = Path(proc_root) / str(pid)
    try:
        for line in (base / "smaps_rollup").read_text().splitlines():
            if line.startswith("Pss:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    try:
        return int((base / "statm").read_text().split()[1]) * _PAGE_SIZE
    except (OSError, ValueError, IndexError):
        return 0


def process_tree_memory_bytes(root_pid: int, *, proc_root: str | Path = "/proc") -> int:
    return sum(
        process_memory_bytes(pid, proc_root=proc_root)
        for pid in process_tree(root_pid, proc_root=proc_root)
    )


def kill_process_tree(
    root_pid: int,
    *,
    proc_root: str | Path = "/proc",
    members: Iterable[int] | None = None,
) -> int:
    """SIGKILL the tool's process group and every process in its tree; returns the count."""
    # Killing the root group can immediately reparent a Chromium child that left
    # that group. Snapshot descendants first so the later PID walk still finds it.
    targets = tuple(members) if members is not None else tuple(process_tree(root_pid, proc_root=proc_root))
    killed = 0
    try:
        os.killpg(root_pid, signal.SIGKILL)
        killed += 1
    except (AttributeError, ProcessLookupError, PermissionError, OSError):
        pass
    for pid in targets:
        try:
            os.kill(pid, signal.SIGKILL)
            killed += 1
        except (ProcessLookupError, PermissionError, OSError):
            continue
    return killed


class ProcessTreeMemoryCeiling:
    """Sample a tool's process tree and report when it crosses ``limit_bytes``.

    ``over_ceiling()`` is cheap to call from a supervisor's poll loop: it samples at most
    once per ``interval`` seconds. Once the ceiling is crossed it stays crossed.
    """

    def __init__(
        self,
        root_pid: int,
        limit_bytes: int,
        *,
        source: str = "configured",
        interval: float = 0.25,
        proc_root: str | Path = "/proc",
        sample: Callable[[], int] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.root_pid = int(root_pid)
        self.limit_bytes = max(0, int(limit_bytes or 0))
        self.source = source
        self.interval = float(interval)
        self.proc_root = Path(proc_root)
        self._sample = sample or (
            lambda: process_tree_memory_bytes(self.root_pid, proc_root=self.proc_root)
        )
        self._clock = clock
        self._next_sample = 0.0
        self.enforced = self.limit_bytes > 0 and (
            sample is not None or (self.proc_root / "self" / "stat").exists()
        )
        self.peak_bytes = 0
        self.exceeded = False

    def over_ceiling(self) -> bool:
        if self.exceeded or not self.enforced:
            return self.exceeded
        now = self._clock()
        if now < self._next_sample:
            return False
        self._next_sample = now + self.interval
        used = int(self._sample() or 0)
        self.peak_bytes = max(self.peak_bytes, used)
        self.exceeded = used >= self.limit_bytes
        return self.exceeded

    def kill(self) -> int:
        return kill_process_tree(self.root_pid, proc_root=self.proc_root)

    def receipt(self) -> dict[str, object]:
        return {
            "schema": MEMORY_CEILING_SCHEMA,
            "enforced": self.enforced,
            "limit_bytes": self.limit_bytes,
            "limit_source": self.source,
            "peak_bytes": self.peak_bytes,
            "exceeded": self.exceeded,
        }
