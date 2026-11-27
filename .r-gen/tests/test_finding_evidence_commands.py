"""A finding read never offers a stored command from an earlier release for copying as stored.

Findings written before every target-chosen value went through ``shell_word`` keep their
evidence text: ``verify_commands`` (the finding page's "Copy verification command") and the
``reproduction`` line of configuration findings hold the URL or host as typed. GET
/findings/{id} rebuilds verify commands from the evidence's URL and path, and moves commands it
cannot rebuild or check to ``*_as_recorded`` (shown as text, not offered for copying).

The rows here are 2.11.0-shaped unit fixtures with control characters and command substitution
in the URL; each served command is pasted into every shell on the host (tests/shell_paste.py).
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import json
from pathlib import Path
import sys
import urllib.parse
import uuid

import pytest

from tests.shell_paste import paste

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "api", ROOT / "scanner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import finding_routes.router as findings_router  # noqa: E402
from scanner_tools.shell_words import shell_word  # noqa: E402

FINDING = uuid.UUID("55555555-5555-4555-8555-555555555555")
HOSTILE_URL = "https://app.fixture.invalid/'$(pwn)'\x15`pwn`\x1b[2J/.git/config"


def _old_verify_commands(url: str) -> list[str]:
    # What the scanner stored before shell_word: the URL typed into the command.
    return [f"curl -sI {url}", f"curl -sL {url} | sed -n '1,40p'",
            "curl -sL https://app.fixture.invalid/.git/HEAD", "curl -sL https://app.fixture.invalid/.git/config"]


def _serve(monkeypatch, row: dict) -> dict:
    @asynccontextmanager
    async def acquire():
        yield object()

    class _Pool:
        def acquire(self):
            return acquire()

    async def record(_conn, _finding_id):
        return dict(row)

    async def no_exposures(_conn, _finding):
        return []

    monkeypatch.setattr(findings_router, "_pool_provider", lambda: _Pool())
    monkeypatch.setattr(findings_router, "get_finding_record", record)
    monkeypatch.setattr(findings_router, "related_exposures", no_exposures)
    monkeypatch.setattr(findings_router, "_load_effective_ai_settings", lambda: {})
    result = asyncio.run(findings_router.get_finding(str(FINDING)))
    evidence = result["evidence"]
    return json.loads(evidence) if isinstance(evidence, str) else evidence


def _row(tool: str, evidence: dict, *, as_text: bool = False) -> dict:
    return {
        "id": FINDING, "title": "Exposed file: /.git/config", "severity": "high", "tool": tool,
        "status": "active", "target_id": None, "target_url": "https://app.fixture.invalid",
        "url": evidence.get("url") or "https://app.fixture.invalid/", "source": "dast",
        "evidence": json.dumps(evidence) if as_text else evidence,
    }


@pytest.mark.parametrize("as_text", [False, True])
def test_stored_exposed_file_commands_are_rebuilt_and_run_nothing(monkeypatch, tmp_path, as_text):
    evidence = {"path": "/.git/config", "url": HOSTILE_URL, "verify_commands": _old_verify_commands(HOSTILE_URL)}
    served = _serve(monkeypatch, _row("exposed_files", evidence, as_text=as_text))
    commands = served["verify_commands"]
    assert commands and commands != evidence["verify_commands"]
    assert commands[0] == f"curl -sI {shell_word(HOSTILE_URL)}"
    for command in commands:
        assert not any(ch < " " or "\x7f" <= ch <= "\x9f" for ch in command), repr(command)
        for run in paste(command, tmp_path):
            curl_args = [args for tool, args in run.calls if tool == "curl"]
            assert curl_args, run
            sent = curl_args[0][-1]
            assert sent.startswith("https://app.fixture.invalid/"), run
            if "'$(pwn)'" in urllib.parse.unquote(sent):
                assert urllib.parse.unquote(sent) == HOSTILE_URL, run


def test_verify_commands_without_inputs_are_shown_as_recorded_only(monkeypatch):
    evidence = {"verify_commands": [f"curl -sI {HOSTILE_URL}"]}
    served = _serve(monkeypatch, _row("custom_probe", evidence))
    assert "verify_commands" not in served
    assert served["verify_commands_as_recorded"] == evidence["verify_commands"]


@pytest.mark.parametrize("reproduction", [
    "dig +short app$(pwn)\x03.fixture.example TXT",
    "curl -sIL https://app.fixture.example/$(pwn)",
    "curl -sIL https://app.fixture.example/'$(pwn)",
    "curl -sI http://app.fixture.example;pwn",
    "openssl s_client -connect app.fixture.example:443 -servername app`pwn` -status | sed -n '1,120p'",
])
def test_an_unchecked_reproduction_is_shown_as_recorded_only(monkeypatch, reproduction):
    served = _serve(monkeypatch, _row("http_headers", {"header": "x-frame-options", "reproduction": reproduction}))
    assert "reproduction" not in served and served["reproduction_as_recorded"] == reproduction


@pytest.mark.parametrize("reproduction", [
    "curl -sIL https://app.fixture.example/",
    f"curl -sIL {shell_word(HOSTILE_URL)}",
    f"dig +short {shell_word('_dmarc.app.fixture.example')} TXT",
    f"echo | openssl s_client -connect {shell_word('app.fixture.example:443')} -servername "
    f"{shell_word(chr(39) + '$(pwn)')} 2>/dev/null | openssl x509 -noout -enddate",
])
def test_a_reproduction_in_the_current_shape_is_kept_and_runs_nothing(monkeypatch, tmp_path, reproduction):
    served = _serve(monkeypatch, _row("http_headers", {"header": "x-frame-options", "reproduction": reproduction}))
    assert served["reproduction"] == reproduction
    for _run in paste(reproduction, tmp_path):
        pass
