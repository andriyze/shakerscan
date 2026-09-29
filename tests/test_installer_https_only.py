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


@pytest.mark.parametrize("script", ["bootstrap.sh", "index.sh"])
def test_installer_dispatch_downloads_restrict_redirect_protocols(tmp_path, script):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    trace = tmp_path / "curl-calls"
    fake_curl = fake_bin / "curl"
    fake_curl.write_text(
        "#!/usr/bin/env python3\n"
        "import os, pathlib, sys\n"
        "args = sys.argv[1:]\n"
        "if not {'--proto', '=https,file', '--proto-redir', '=https', '--tlsv1.2'} <= set(args):\n"
        "    sys.exit(82)\n"
        "url = next((arg for arg in args if arg.startswith(('https://', 'file://'))), '')\n"
        "with open(os.environ['SHAKERSCAN_CURL_TRACE'], 'a') as stream:\n"
        "    stream.write(url + '\\n')\n"
        "if url.endswith('/STABLE_VERSION'):\n"
        "    print('2.5.4')\n"
        "elif url.endswith('/install/index.sh') and '-o' in args:\n"
        "    pathlib.Path(args[args.index('-o') + 1]).write_text('#!/bin/sh\\nexit 0\\n')\n"
        "else:\n"
        "    sys.exit(83)\n"
    )
    fake_curl.chmod(0o755)
    result = subprocess.run(
        ["sh", str(ROOT / "install" / script)],
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "PATH": f"{fake_bin}:{os.environ['PATH']}",
            "HOME": str(tmp_path),
            "SHAKERSCAN_HOME": str(tmp_path / "home"),
            "SHAKERSCAN_START": "0",
            "SHAKERSCAN_RAW_BASE": "",
            "SHAKERSCAN_INSTALL_VERSION": "",
            "SHAKERSCAN_CURL_TRACE": str(trace),
        },
    )

    assert result.returncode == 0, result.stderr
    assert trace.read_text().splitlines() == [
        "https://raw.githubusercontent.com/andriyze/shakerscan/main/install/STABLE_VERSION",
        "https://raw.githubusercontent.com/andriyze/shakerscan/v2.5.4/install/index.sh",
    ]
