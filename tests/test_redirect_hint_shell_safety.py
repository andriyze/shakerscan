"""A refused-redirect hint names an origin only when it is a plain, rebuildable origin.

The instance (or anything in front of it) chooses the ``Location`` header. The hint turns it
into a command the person is told to run (``shakerscan connect <origin>``), so a hostile
``Location`` must never become shell syntax in that command. Each suggested command is run
through ``/bin/sh`` with a stand-in ``shakerscan`` on ``PATH``; no marker file may appear.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "scanner"))

import redirect_hint  # noqa: E402
from scanner_tools.shell_words import shell_word  # noqa: E402

REQUEST = "http://shakerscan.example/api/v1/health"
HOSTILE = [
    "https://shakerscan.example$(touch${IFS}.shell-ran)/",
    "https://shakerscan.example;touch${IFS}.shell-ran;/",
    "https://shakerscan.example`touch${IFS}.shell-ran`/",
    "https://shakerscan.example|touch${IFS}.shell-ran|/",
    "https://shakerscan.example&&touch${IFS}.shell-ran&&/",
    "https://shakerscan.example\ntouch .shell-ran\n/",
    "https://shakerscan.example:443$(touch${IFS}.shell-ran)/",
    "https://[::1$(touch${IFS}.shell-ran)]/",
    "https://shakerscan.example%3Btouch${IFS}.shell-ran/",
]


def _suggested_commands(text: str) -> list[str]:
    match = re.search(r"\((shakerscan connect .*?), or (--url .*?)\)\.?$", text, re.S)
    if not match:
        return []
    return [match.group(1), "shakerscan " + match.group(2)]


def _run_through_sh(command: str, workdir: Path) -> str:
    bindir = workdir / "bin"
    bindir.mkdir(exist_ok=True)
    stand_in = bindir / "shakerscan"
    stand_in.write_text('#!/bin/sh\nfor a in "$@"; do printf "%s\\n" "$a"; done\n')
    stand_in.chmod(0o755)
    env = {"PATH": f"{bindir}:/usr/bin:/bin", "HOME": str(workdir)}
    result = subprocess.run(["/bin/sh", "-c", command], cwd=workdir, env=env, capture_output=True, text=True, timeout=10)
    return result.stdout


@pytest.mark.parametrize("location", HOSTILE)
def test_hostile_location_never_becomes_shell_syntax(location, tmp_path):
    text = redirect_hint.redirect_explanation(308, location, REQUEST)
    for command in _suggested_commands(text):
        if "<origin>" in command:
            continue
        _run_through_sh(command, tmp_path)
    assert not (tmp_path / ".shell-ran").exists()
    assert redirect_hint.redirect_origin(location, REQUEST) is None
    assert "touch" not in text


@pytest.mark.parametrize("location,origin", [
    ("https://shakerscan.example/api/v1/health", "https://shakerscan.example"),
    ("https://Shakerscan.Example:8443/x", "https://shakerscan.example:8443"),
    ("https://user:pw@shakerscan.example/", "https://shakerscan.example"),
    ("https://10.0.0.5:9443/", "https://10.0.0.5:9443"),
    ("https://[2001:db8::1]:8443/", "https://[2001:db8::1]:8443"),
    ("//other.example/", "http://other.example"),
])
def test_normal_origins_are_still_named_and_survive_the_shell(location, origin, tmp_path):
    assert redirect_hint.redirect_origin(location, REQUEST) == origin
    text = redirect_hint.redirect_explanation(308, location, REQUEST)
    commands = _suggested_commands(text)
    assert commands, text
    for command in commands:
        assert _run_through_sh(command, tmp_path).splitlines()[-1] == origin


def test_vendored_shell_word_matches_the_shared_one():
    samples = ["https://a.example", "https://[::1]:8443", "it's", "a\\b", "$(x)", "", "=cmd", "\x1b[2J"]
    for sample in samples:
        assert redirect_hint.shell_word(sample) == shell_word(sample)
