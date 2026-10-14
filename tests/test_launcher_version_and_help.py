"""The launcher answers `version` like the client does, and its help starts with the banner."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def install(tmp_path):
    """A minimal release tree: the launcher, the helper it sources, and a VERSION file."""
    (tmp_path / "scripts").mkdir()
    shutil.copy(ROOT / "scanner.sh", tmp_path / "scanner.sh")
    shutil.copy(ROOT / "scripts" / "postgres_upgrade.sh", tmp_path / "scripts" / "postgres_upgrade.sh")
    shutil.copy(ROOT / "scripts" / "upgrade_safety.sh", tmp_path / "scripts" / "upgrade_safety.sh")
    (tmp_path / "VERSION").write_text("9.8.7\n", encoding="utf-8")
    return tmp_path


def _run(install, *args):
    return subprocess.run(
        ["bash", str(install / "scanner.sh"), *args],
        cwd=install, env={"PATH": "/usr/bin:/bin", "HOME": str(install)},
        capture_output=True, text=True, timeout=60,
    )


@pytest.mark.parametrize("command", ["version", "--version", "-V"])
def test_version_prints_the_installed_release(install, command):
    result = _run(install, command)
    assert result.returncode == 0, result.stdout + result.stderr
    # An installed release is not a git checkout, so there is no source revision to print.
    assert "shakerscan engine 9.8.7\n" in result.stdout
    assert "Unknown command" not in result.stdout


def test_help_starts_with_the_banner_and_lists_lan_with_the_options(install):
    result = _run(install, "help")
    assert result.returncode == 0
    output = result.stdout
    assert output.index("ShakerScan - Open Source Edition") < output.index("Usage:")
    assert "Trusted LAN:" not in output.split("Usage:")[0]
    options = output.split("Options:", 1)[1]
    assert "--lan" in options and "--bind-host" in options
    assert "  version  " in output.split("Options:", 1)[0]


def test_secrets_reaches_the_product_cli_and_is_in_the_help(install):
    """2.10 acceptance (D2): `shakerscan secrets` printed "Unknown command" on an installed engine
    although the release notes promise it."""
    (install / "scripts" / "v2_cli.py").write_text("", encoding="utf-8")
    bin_dir = install / "bin"
    bin_dir.mkdir()
    (bin_dir / "python3").write_text('#!/bin/sh\necho "python3 $*"\n', encoding="utf-8")
    (bin_dir / "python3").chmod(0o755)
    result = subprocess.run(
        ["bash", str(install / "scanner.sh"), "secrets", "list", "t-1"],
        cwd=install, env={"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(install)},
        capture_output=True, text=True, timeout=60,
    )
    assert "Unknown command" not in result.stdout + result.stderr
    assert "scripts/v2_cli.py --api-url" in result.stdout and result.stdout.rstrip().endswith("secrets list t-1")
    assert "  secrets <cmd>  " in _run(install, "help").stdout


def test_secrets_help_is_the_commands_own(install):
    """Review F7: `shakerscan secrets --help` printed the launcher's global help."""
    (install / "scripts" / "v2_cli.py").write_text("", encoding="utf-8")
    bin_dir = install / "bin"
    bin_dir.mkdir()
    (bin_dir / "python3").write_text('#!/bin/sh\necho "python3 $*"\n', encoding="utf-8")
    (bin_dir / "python3").chmod(0o755)
    result = subprocess.run(
        ["bash", str(install / "scanner.sh"), "secrets", "--help"],
        cwd=install, env={"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(install)},
        capture_output=True, text=True, timeout=60,
    )
    assert result.stdout.rstrip().endswith("secrets --help"), result.stdout[-300:]
