"""bounded_exec must resolve libseccomp before it lowers RLIMIT_NPROC.

RLIMIT_NPROC counts every task of the real uid, not just this launcher's children. Resolving
libseccomp with ctypes.util.find_library forks (ldconfig -p, then gcc/ld fallbacks); after the
limit is lowered that fork fails as soon as the uid already runs about 128 tasks, find_library
returns None and the launcher refused every scanner with "requires libseccomp". These tests run
the launcher's main() in-process with every side effect stubbed, so they hold on any platform.
"""

from __future__ import annotations

import importlib.util
import resource
from pathlib import Path
from typing import ClassVar

import pytest

LAUNCHER = Path(__file__).resolve().parents[1] / "scanner/scanner_tools/bounded_exec.py"


class _Exec(Exception):
    pass


class _FakeFunction:
    def __init__(self, result):
        self.result = result
        self.argtypes = None
        self.restype = None

    def __call__(self, *_args):
        return self.result


class _FakeLibrary:
    """libseccomp and libc as far as bounded_exec calls them, every call succeeding."""

    _results: ClassVar[dict[str, int]] = {"seccomp_init": 1, "seccomp_syscall_resolve_name": 41}

    def __getattr__(self, name):
        function = _FakeFunction(self._results.get(name, 0))
        setattr(self, name, function)
        return function


def _load(monkeypatch, *, library_name="libseccomp.so.2"):
    spec = importlib.util.spec_from_file_location("bounded_exec_under_test", LAUNCHER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    events: list[tuple[str, object]] = []

    def find_library(name):
        events.append(("find_library", name))
        return library_name

    def load_library(name, **_kwargs):
        events.append(("dlopen", name))
        return _FakeLibrary()

    def execve(path, _argv, _env):
        events.append(("execve", path))
        raise _Exec

    monkeypatch.setattr(module, "_limit", lambda kind, value: events.append(("limit", kind)))
    monkeypatch.setattr(module.ctypes.util, "find_library", find_library)
    monkeypatch.setattr(module.ctypes, "CDLL", load_library)
    monkeypatch.setattr(module.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(module.os, "execve", execve)
    return module, events


@pytest.mark.skipif(not hasattr(resource, "RLIMIT_NPROC"), reason="platform has no RLIMIT_NPROC")
def test_libseccomp_is_resolved_and_loaded_before_the_process_limit_is_lowered(monkeypatch):
    module, events = _load(monkeypatch)
    with pytest.raises(_Exec):
        module.main(["--", "/usr/bin/true"])
    names = [name for name, _ in events]
    nproc = events.index(("limit", resource.RLIMIT_NPROC))
    assert names.index("find_library") < nproc
    assert max(i for i, name in enumerate(names) if name == "dlopen") < nproc
    # The limits still apply, and before the scanner runs.
    assert ("limit", resource.RLIMIT_CPU) in events
    assert names[-1] == "execve"


def test_nothing_after_the_limits_forks_or_resolves_a_library(monkeypatch):
    module, events = _load(monkeypatch)
    with pytest.raises(_Exec):
        module.main(["--", "/usr/bin/true"])
    first_limit = next(i for i, (name, _) in enumerate(events) if name == "limit")
    assert not [name for name, _ in events[first_limit:] if name in {"find_library", "dlopen"}]


def test_a_missing_libseccomp_still_refuses_to_run_the_scanner(monkeypatch):
    module, events = _load(monkeypatch, library_name=None)
    with pytest.raises(SystemExit, match="requires libseccomp"):
        module.main(["--", "/usr/bin/true"])
    assert "execve" not in [name for name, _ in events]
