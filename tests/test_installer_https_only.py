"""The installer refuses plain-HTTP sources before it downloads anything."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _run(script: str, env: dict[str, str], tmp_path: Path) -> subprocess.CompletedProcess:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(exist_ok=True)
    marker = tmp_path / "curl-called"
    (fake_bin / "curl").write_text(f"#!/bin/sh\ntouch {marker}\nexit 1\n")
    (fake_bin / "curl").chmod(0o755)
    return subprocess.run(
        ["sh", str(ROOT / "install" / script)],
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "PATH": f"{fake_bin}:{os.environ['PATH']}",
            "HOME": str(tmp_path),
            "SHAKERSCAN_HOME": str(tmp_path / "home"),
            "SHAKERSCAN_START": "0",
            **env,
        },
    )


@pytest.mark.parametrize(
    "variable",
    ["SHAKERSCAN_RAW_BASE", "SHAKERSCAN_CHANNEL_RAW_BASE", "SHAKERSCAN_RELEASE_RAW_ROOT"],
)
def test_bootstrap_refuses_http_sources(tmp_path, variable):
    result = _run("bootstrap.sh", {variable: "http://mirror.example.test/shakerscan"}, tmp_path)

    assert result.returncode != 0
    assert "https:// or file://" in result.stderr
    assert not (tmp_path / "curl-called").exists()


@pytest.mark.parametrize("variable", ["SHAKERSCAN_RAW_BASE", "SHAKERSCAN_RELEASE_ASSET_ROOT"])
def test_installer_refuses_http_sources(tmp_path, variable):
    result = _run("index.sh", {variable: "http://mirror.example.test/shakerscan"}, tmp_path)

    assert result.returncode != 0
    assert "https:// or file://" in result.stderr
    assert not (tmp_path / "curl-called").exists()


def test_installer_downloads_pin_https_including_redirects():
    source = (ROOT / "install" / "index.sh").read_text()
    assert "--proto '=https,file' --proto-redir '=https'" in source
