"""The `shakerscan` client never lets server-supplied text drive the terminal.

The public check service, an instance's health answer and its error messages are written to
the terminal by the client. A value carrying an escape sequence (``\\x1b]0;...\\x07`` retitles
the window, ``\\x1b[2J`` clears it) or a carriage return (``\\r`` overwrites the line just
printed) is shown as visible text instead, the way ``shakerscan`` review screens show Hunt text.

Unit fixtures: the response payloads are built here; nothing reaches the network.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "client" / "src"))
sys.path.insert(0, str(ROOT / "client"))

from shakerscan import cli  # noqa: E402

HOSTILE = [
    "\x1b]0;owned\x07", "\x1b[2J\x1b[H", "ok\rFAKE: all clear", "\x9b31m", "a\x08\x08b",
    "‮evil", "zero​width", "\x1bP+q\x1b\\",
]


def _terminal_safe(text: str) -> bool:
    return not any(ch in text for ch in "\x1b\r\x07\x08\x9b‮​") and not any(
        (ord(ch) < 0x20 and ch not in "\n\t") or 0x7f <= ord(ch) < 0xa0 for ch in text
    )


def _facts(value: str) -> dict:
    return {
        "schema_version": "2", "target": f"example.com{value}", "checked_at": f"2026-10-20T00:00:00Z{value}",
        "observations": [
            {"id": "dns.records", "group": "dns", "name": f"DNS{value}",
             "result": {f"txt{value}": [f"v=spf1{value}", {"k": value}], "note": value}},
            {"id": "ip.network", "group": "ip", "name": "IP",
             "result": {"addresses": [{"ip": "192.0.2.1", "as_name": f"AS{value}"}], "reverse_dns": [value]}},
            {"id": "http.connections", "group": "http", "name": "HTTP",
             "result": {"connections": [{"ip": "192.0.2.1", "status_code": 200, "cipher": value,
                                         "certificate": {"subject": f"CN={value}"}}]}},
            {"id": "mail.dmarc", "group": "mail", "name": f"DMARC{value}", "result": {"applied_policy": "none"}},
            {"id": "tls.none", "group": "tls", "name": f"missing{value}", "result": {}},
        ],
        "limitations": [f"limited{value}"],
    }


@pytest.mark.parametrize("value", HOSTILE)
def test_public_check_rendering_is_terminal_safe(value):
    text = cli.render_public_check(_facts(value), "example.com")
    assert _terminal_safe(text), repr(text)


@pytest.mark.parametrize("value", HOSTILE)
def test_brief_is_terminal_safe(value):
    assert _terminal_safe(cli._brief(value))
    assert _terminal_safe(cli._brief([value, {"k": value}]))
    assert _terminal_safe(cli._brief({value: value}))


def test_ordinary_text_is_unchanged():
    facts = _facts("")
    text = cli.render_public_check(facts, "example.com")
    assert "Target: example.com" in text and "AS" in text and "CN=" in text and "v=spf1" in text
    assert cli._brief(["café", "日本", "a\tb"]) == "café, 日本, a\tb"
    assert cli._brief({"key": "value", "n": 3}) == "key=value n=3"


@pytest.mark.parametrize("value", HOSTILE)
def test_error_messages_from_the_server_are_terminal_safe(monkeypatch, value):
    def failing(_args):
        raise cli.ClientError(f"the instance said: {value}")

    monkeypatch.setitem(cli.COMMANDS, "version", failing)
    stderr = io.StringIO()
    monkeypatch.setattr(sys, "stderr", stderr)
    assert cli.main(["version"]) == 2
    assert _terminal_safe(stderr.getvalue()), repr(stderr.getvalue())
    assert stderr.getvalue().startswith("shakerscan: the instance said: ")
