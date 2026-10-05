"""A root install keeps a healthy API.

The installer builds the install directory in a 0700 staging directory. A root install runs the
API as the unprivileged uid/gid 10002, which then could not enter its read-only /workspace mount:
every /health call raised PermissionError (HTTP 500) and the installer gave up waiting for the API.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest

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


def _prepare_with_host_accounts(tmp_path: Path, taken: dict[str, str], **env: str):
    calls = _fake_bin(tmp_path, "0")
    entries = "\n".join(f'  {uid}) echo "{name}:x:{uid}:{uid}::/home/{name}:/bin/sh"; exit 0;;' for uid, name in taken.items())
    (tmp_path / "bin" / "getent").write_text(f'#!/bin/sh\ncase "$2" in\n{entries}\nesac\nexit 2\n', encoding="utf-8")
    (tmp_path / "bin" / "getent").chmod(0o755)
    install = tmp_path / "install"
    install.mkdir(mode=0o700)
    functions = (ROOT / "scanner.sh").read_text(encoding="utf-8").rsplit("# Parse arguments", 1)[0]
    script = functions + f'\nSCRIPT_DIR="{install}"; cd "$SCRIPT_DIR" || exit 9; prepare_runtime_files\n'
    result = subprocess.run(
        ["bash", "-s"], input=script, cwd=ROOT, capture_output=True, text=True, timeout=60,
        env={**os.environ, "PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}", "HOME": str(tmp_path), **env},
    )
    recorded = calls.read_text(encoding="utf-8").splitlines() if calls.exists() else []
    return result, recorded, str(install)


def test_a_root_install_refuses_an_api_id_a_host_account_already_owns(tmp_path):
    """The API owns results/ and the encryption key; a host account with the same id could read them."""
    result, calls, install = _prepare_with_host_accounts(tmp_path, {"10002": "alice"})
    assert result.returncode != 0
    assert "10002 already belongs" in result.stderr and "alice" in result.stderr
    assert not any(call.startswith("chgrp") for call in calls)


def test_a_root_install_can_choose_a_free_api_id(tmp_path):
    result, calls, install = _prepare_with_host_accounts(
        tmp_path, {"10002": "alice"}, SHAKERSCAN_ROOT_API_UID="10050",
    )
    assert "already belongs" not in result.stderr
    assert f"chgrp 10050 {install}" in calls
    assert "SHAKERSCAN_API_UID=10050" in (Path(install) / ".env").read_text()


def _prepare_existing_install(tmp_path: Path, install: str, **overrides: str):
    functions = (ROOT / "scanner.sh").read_text(encoding="utf-8").rsplit("# Parse arguments", 1)[0]
    script = functions + f'\nSCRIPT_DIR="{install}"; cd "$SCRIPT_DIR" || exit 9; prepare_runtime_files\n'
    result = subprocess.run(
        ["bash", "-s"], input=script, cwd=ROOT, capture_output=True, text=True, timeout=60,
        env={**os.environ, "PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}",
             "HOME": str(tmp_path), "SHAKERSCAN_ROOT_API_UID": "", **overrides},
    )
    calls = (tmp_path / "calls").read_text(encoding="utf-8").splitlines()
    return result, calls


@pytest.mark.parametrize("identity", ["0", "00", "10001", "010001", "4294967295", "9" * 30])
def test_a_root_install_rejects_reserved_or_out_of_range_numeric_spellings(tmp_path, identity):
    result, calls, _install = _prepare_with_host_accounts(
        tmp_path, {}, SHAKERSCAN_ROOT_API_UID=identity,
    )
    assert result.returncode != 0 and "SHAKERSCAN_ROOT_API_UID must be" in result.stderr
    assert not any(call.startswith("chgrp") for call in calls)


def test_a_root_install_canonicalizes_and_reuses_its_saved_free_identity(tmp_path):
    result, calls, install = _prepare_with_host_accounts(
        tmp_path, {"10002": "alice"}, SHAKERSCAN_ROOT_API_UID="010050",
    )
    assert "already belongs" not in result.stderr
    assert f"chgrp 10050 {install}" in calls
    assert "SHAKERSCAN_ROOT_API_UID=10050" in (Path(install) / ".env").read_text()
    restarted, calls = _prepare_existing_install(tmp_path, install)
    assert "already belongs" not in restarted.stderr
    assert f"chgrp 10050 {install}" in calls
    assert f"chgrp 10002 {install}" not in calls
    assert "SHAKERSCAN_API_UID=10050" in (Path(install) / ".env").read_text()


def test_a_root_install_reuses_an_older_saved_api_identity_without_root_setting(tmp_path):
    _result, _calls, install = _prepare_with_host_accounts(
        tmp_path, {"10002": "alice"}, SHAKERSCAN_ROOT_API_UID="10050",
    )
    dotenv = Path(install) / ".env"
    dotenv.write_text("\n".join(
        line for line in dotenv.read_text().splitlines()
        if not line.startswith("SHAKERSCAN_ROOT_API_UID=")
    ) + "\n")
    restarted, calls = _prepare_existing_install(tmp_path, install)
    assert "already belongs" not in restarted.stderr
    assert f"chgrp 10050 {install}" in calls
    assert "SHAKERSCAN_ROOT_API_UID=10050" in dotenv.read_text()


def test_a_root_install_preserves_explicit_override_and_rechecks_collisions(tmp_path):
    _result, _calls, install = _prepare_with_host_accounts(
        tmp_path, {"10002": "alice"}, SHAKERSCAN_ROOT_API_UID="10050",
    )
    overridden, calls = _prepare_existing_install(tmp_path, install, SHAKERSCAN_ROOT_API_UID="10051")
    assert "already belongs" not in overridden.stderr
    assert f"chgrp 10051 {install}" in calls
    assert "SHAKERSCAN_ROOT_API_UID=10051" in (Path(install) / ".env").read_text()
    refused, calls = _prepare_existing_install(tmp_path, install, SHAKERSCAN_ROOT_API_UID="010002")
    assert "id 10002 already belongs" in refused.stderr
    assert f"chgrp 10002 {install}" not in calls
    assert "SHAKERSCAN_ROOT_API_UID=10051" in (Path(install) / ".env").read_text()
