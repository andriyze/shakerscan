"""Suite-wide fixtures."""

from __future__ import annotations

import contextlib
import os
import re
import socket
import sys
from pathlib import Path

import pytest


async def _resolver_unavailable(_hostname):
    raise socket.gaierror(socket.EAI_AGAIN, "name resolution is not available to unit tests")


@pytest.fixture(autouse=True)
def _hermetic_target_resolution(monkeypatch):
    """Keep target-name DNS lookups off the network.

    Scan submission and target creation ask DNS whether the target name has an address record
    (``api/target_resolution.py``), so the www/apex twin can be used when it does not. Unit tests
    must not depend on the machine's resolver, so here the resolver reports a fault -- the
    outcome that, by contract, changes nothing. Tests of that behaviour install their own
    fixture resolver over this one.
    """
    for name, module in list(sys.modules.items()):
        if name.rsplit(".", 1)[-1] == "target_resolution" and hasattr(module, "system_lookup"):
            monkeypatch.setattr(module, "system_lookup", _resolver_unavailable)
            if hasattr(module, "system_answer"):
                monkeypatch.setattr(module, "system_answer", _resolver_unavailable)


# --- the client's files stay out of the real home ------------------------------------------------

# Read once, before any test can move HOME: the home the guard below protects.
REAL_HOME = Path(os.path.expanduser("~"))
_CLIENT_TEST_FILES = re.compile(
    r"^test_(client_|shakerscan_client|agent_|hunt_approve|hunt_terminal_approval|mcp_|read_only_mcp)"
)
_CLIENT_HOME_DIRECTORIES = (".config/shakerscan", ".local/state/shakerscan", ".local/share/shakerscan")


def client_home_snapshot(home: Path | None = None) -> dict[str, tuple[int, int]]:
    """Every entry under the (real) home's ShakerScan client directories, with mtime and size."""
    seen: dict[str, tuple[int, int]] = {}
    for relative in _CLIENT_HOME_DIRECTORIES:
        root = (home or REAL_HOME) / relative
        if root.is_symlink() or not root.is_dir():
            continue
        for directory, folders, files in os.walk(root):
            for name in [*folders, *files]:
                with contextlib.suppress(OSError):
                    info = (Path(directory) / name).lstat()
                    seen[str(Path(directory) / name)] = (info.st_mtime_ns, info.st_size)
    return seen


@pytest.fixture(autouse=True)
def _hermetic_client_home(request, monkeypatch, tmp_path_factory):
    """Client and agent tests get their own configuration, state and data directories, and fail
    if they write under the real home's ShakerScan directories anyway. A test once wrote five
    workspace records into a developer's ~/.local/state/shakerscan."""
    if not _CLIENT_TEST_FILES.match(Path(str(request.node.fspath)).name):
        yield
        return
    base = tmp_path_factory.mktemp("client-home")
    monkeypatch.setenv("SHAKERSCAN_CONFIG_DIR", str(base / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(base / "state"))
    monkeypatch.setenv("XDG_DATA_HOME", str(base / "data"))
    before = client_home_snapshot()
    yield
    after = client_home_snapshot()
    changed = sorted(path for path in set(before) | set(after) if before.get(path) != after.get(path))
    assert not changed, f"this test wrote under the real home: {changed[:10]}"
