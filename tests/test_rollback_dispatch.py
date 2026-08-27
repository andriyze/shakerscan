"""A rollback must restore the version it names, not the current stable one.

`install/bootstrap.sh` resolved the stable channel and then overwrote the caller's
`SHAKERSCAN_RAW_BASE` with it. The documented rollback pipes the dispatcher with that variable set
to a previous tag, so the one command whose entire purpose is "not the current version" silently
reinstalled the current version. An explicit base now suppresses channel resolution.

The documented command had a second problem: `curl ... | VAR=x sh` sets the variable for the shell
but `VAR=x curl ... | sh` sets it for curl. The doc now reads the script into `sh -c` instead.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "install" / "bootstrap.sh"
DOC = ROOT / "docs" / "upgrade-and-rollback.md"


def _runnable(tmp_path: Path) -> Path:
    channel = tmp_path / "STABLE_VERSION"
    channel.write_text("0.8.18\n", encoding="utf-8")
    probe = tmp_path / "probe.sh"
    probe.write_text(
        "#!/bin/sh\n"
        'echo "base=${SHAKERSCAN_RAW_BASE:-unset}"\n'
        'echo "version=${SHAKERSCAN_INSTALL_VERSION:-unset}"\n',
        encoding="utf-8",
    )
    source = BOOTSTRAP.read_text(encoding="utf-8")
    source = source.replace(
        'curl -fsSL "$CHANNEL_RAW_BASE/install/STABLE_VERSION"', f"cat {channel}", 1)
    source = source.replace(
        'curl -fsSL "$release_base/install/index.sh" -o "$tmp"', f'cp {probe} "$tmp"', 1)
    script = tmp_path / "bootstrap_under_test.sh"
    script.write_text(source, encoding="utf-8")
    return script


def _run(script: Path, **env):
    base = {"PATH": "/usr/bin:/bin", "HOME": str(script.parent), "TMPDIR": str(script.parent)}
    base.update(env)
    return subprocess.run(["sh", str(script)], capture_output=True, text=True, env=base)


def test_a_pinned_version_is_restored_not_current_stable(tmp_path):
    run = _run(_runnable(tmp_path), SHAKERSCAN_INSTALL_VERSION="0.7.4")
    assert "version=0.7.4" in run.stdout, run.stdout + run.stderr
    assert "base=https://raw.githubusercontent.com/andriyze/shakerscan/v0.7.4" in run.stdout
    assert "0.8.18" not in run.stdout, "the channel version must not override the pinned one"


def test_an_explicit_raw_base_is_not_replaced_by_the_channel(tmp_path):
    # The exact defect: the documented rollback set this and got current stable anyway.
    run = _run(
        _runnable(tmp_path),
        SHAKERSCAN_RAW_BASE="https://raw.githubusercontent.com/andriyze/shakerscan/v0.7.4",
    )
    assert "base=https://raw.githubusercontent.com/andriyze/shakerscan/v0.7.4" in run.stdout
    assert "0.8.18" not in run.stdout


def test_no_pin_still_follows_the_stable_channel(tmp_path):
    run = _run(_runnable(tmp_path))
    assert "version=0.8.18" in run.stdout
    assert "base=https://raw.githubusercontent.com/andriyze/shakerscan/v0.8.18" in run.stdout


def test_an_unsafe_channel_version_still_fails_closed(tmp_path):
    script = _runnable(tmp_path)
    (tmp_path / "STABLE_VERSION").write_text("../../evil\n", encoding="utf-8")
    run = _run(script)
    assert run.returncode != 0
    assert "unsafe version" in run.stderr


def test_the_documented_rollback_sets_the_variable_for_the_installer(tmp_path):
    doc = DOC.read_text(encoding="utf-8")
    assert 'SHAKERSCAN_INSTALL_VERSION=PREVIOUS_VERSION' in doc
    # `VAR=x curl ... | sh` sets VAR for curl, not for the installer.
    assert 'sh -c "$(curl -fsSL https://install.shakerscan.com)"' in doc
    assert "| \\\n  SHAKERSCAN_RAW_BASE=" not in doc
