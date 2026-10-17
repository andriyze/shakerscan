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


def _record(install, python_stub, *args):
    bin_dir = install / "bin"
    bin_dir.mkdir(exist_ok=True)
    (bin_dir / "python3").write_text(python_stub, encoding="utf-8")
    (bin_dir / "python3").chmod(0o755)
    return subprocess.run(
        ["bash", str(install / "scanner.sh"), "record", *args],
        cwd=install, env={"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(install)},
        capture_output=True, text=True, timeout=60,
    )


def test_record_hands_off_to_an_installed_client_pointed_at_this_instance(install):
    """`record` runs in the client (a browser on this machine); the launcher has none of its own."""
    # The import probe (`-c 'import shakerscan.record, playwright'`) succeeds; `-m` echoes.
    stub = '#!/bin/sh\nif [ "$1" = "-c" ]; then exit 0; fi\necho "python3 $*"\n'
    result = _record(install, stub, "https://app.example.test", "--name", "Walk")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Unknown command" not in result.stdout + result.stderr
    line = result.stdout.strip().splitlines()[-1]
    assert line.startswith("python3 -m shakerscan record --url http")
    assert line.endswith("https://app.example.test --name Walk")
    assert "  record <target>  " in _run(install, "help").stdout


def test_record_without_the_client_names_the_install_commands(install):
    stub = '#!/bin/sh\nif [ "$1" = "-c" ]; then exit 1; fi\necho "python3 $*"\n'
    result = _record(install, stub, "https://app.example.test")
    assert result.returncode == 2
    assert "pipx install --force 'shakerscan[record]'" in result.stderr
    assert "python -m playwright install chromium" in result.stderr
    assert "python3 -m shakerscan" not in result.stdout
    assert "Unknown command" not in result.stdout + result.stderr
