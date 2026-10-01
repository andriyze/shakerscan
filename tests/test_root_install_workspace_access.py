"""A root install keeps a healthy API.

The installer builds the install directory in a 0700 staging directory. A root install runs the
API as the unprivileged uid/gid 10002, which then could not enter its read-only /workspace mount:
every /health call raised PermissionError (HTTP 500) and the installer gave up waiting for the API.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess

from scanner.scanner_tools import build_fingerprint

ROOT = Path(__file__).resolve().parents[1]


def _fake_bin(tmp_path: Path, uid: str) -> Path:
    """Commands that report `uid` from `id -u`/`id -g` and record chgrp/chmod/chown calls."""
    fake = tmp_path / "bin"
    fake.mkdir()
    calls = tmp_path / "calls"
    for command in ("chgrp", "chown"):
        (fake / command).write_text(f'#!/bin/sh\necho "{command} $*" >> "{calls}"\n', encoding="utf-8")
    (fake / "chmod").write_text(f'#!/bin/sh\necho "chmod $*" >> "{calls}"\nexec /bin/chmod "$@"\n', encoding="utf-8")
    (fake / "id").write_text(
        f'#!/bin/sh\ncase "$1" in -u|-g) echo {uid};; *) exec /usr/bin/id "$@";; esac\n', encoding="utf-8",
    )
    for path in fake.iterdir():
        path.chmod(0o755)
    return calls


def _prepare_runtime_files(tmp_path: Path, uid: str) -> list[str]:
    calls = _fake_bin(tmp_path, uid)
    install = tmp_path / "install"
    install.mkdir(mode=0o700)
    functions = (ROOT / "scanner.sh").read_text(encoding="utf-8").rsplit("# Parse arguments", 1)[0]
    script = functions + f'\nSCRIPT_DIR="{install}"; cd "$SCRIPT_DIR" || exit 9; prepare_runtime_files\n'
    # The function goes on to require release files this bare directory does not have; only the
    # permission calls made before that matter here.
    subprocess.run(
        ["bash", "-s"], input=script, cwd=ROOT, capture_output=True, text=True, timeout=60,
        env={**os.environ, "PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}", "HOME": str(tmp_path)},
    )
    return calls.read_text(encoding="utf-8").splitlines() if calls.exists() else []


def test_a_root_install_lets_the_api_group_read_the_install_directory(tmp_path):
    calls = _prepare_runtime_files(tmp_path, "0")
    install = str(tmp_path / "install")
    assert f"chgrp 10002 {install}" in calls
    assert f"chmod g+rx {install}" in calls
    # Only the group: the directory is not opened to other host accounts.
    assert not any(call.startswith("chmod") and install in call and "o+" in call for call in calls)


def test_a_non_root_install_is_left_as_it_is(tmp_path):
    # Non-root installs run the API as the operator, who already owns the directory.
    calls = _prepare_runtime_files(tmp_path, "1000")
    assert not any(call.startswith("chgrp") for call in calls)


def test_an_unreadable_workspace_falls_back_instead_of_raising(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    (workspace / "scanner").mkdir(parents=True)
    (workspace / "api").mkdir()
    real_is_file = Path.is_file

    def denied(self, *args, **kwargs):
        if str(self).startswith(str(workspace)):
            raise PermissionError(13, "Permission denied", str(self))
        return real_is_file(self, *args, **kwargs)

    monkeypatch.setattr(Path, "is_file", denied)
    files = build_fingerprint.source_file_map(str(workspace))
    # Treated as no checkout: the complete manifest, which require_all cannot satisfy, so the
    # caller falls back to the API's own /app runtime instead of failing /health.
    assert files
    assert build_fingerprint.hash_source_files(files, require_all=True) is None
