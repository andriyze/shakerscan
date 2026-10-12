"""``shakerscan knowledge show|dismiss|reopen``: reading interpretations, and a person's dismissal.

Unit fixtures: a scripted terminal double and a loopback stub of the interpretation and finding
routes (it is not an engine). The pseudo-terminal test runs the installed client and sends real key
bytes, so an arrow key or a paste never dismisses a finding.
"""
from __future__ import annotations

import io
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import hunt_approve as approval  # noqa: E402
import v2_cli  # noqa: E402

from tests.test_hunt_terminal_approval import Session  # noqa: E402
from tests.test_knowledge_review_cli import Terminal, _environment  # noqa: E402

TARGET = "11111111-1111-4111-8111-111111111111"
FINDING = "44444444-4444-4444-8444-444444444444"
REAL_TERMINAL = approval.Terminal


class Stub:
    """Loopback stub of the interpretation, negative-result and finding routes (unit fixture)."""

    def __init__(self) -> None:
        self.seen: list[tuple[str, str, Any]] = []
        self.status = "active"
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                return

            def _reply(self, status: int, body: Any) -> None:
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:  # noqa: N802
                stub.seen.append(("GET", self.path, None))
                if self.path.startswith(f"/findings/{FINDING}"):
                    return self._reply(200, {"id": FINDING, "title": "XSS in \x1b[2Jsearch‮", "severity": "medium",
                                             "status": stub.status, "tool": "nuclei", "url": "https://app/s"})
                if "/negative-results" in self.path:
                    return self._reply(200, {"rows": [{"source": "authorization_workflow",
                                                       "negative_state": "experiment_completed_negative",
                                                       "record_ref": {"id": "p-1"}, "created_at": "2026-10-10"}]})
                return self._reply(200, {"interpretations": [
                    {"id": "e-1", "kind": "next_step", "title": "Compare roles\x1b]0;x\x07", "written_by": "hunt:a",
                     "created_at": "2026-10-10"},
                    {"id": "e-2", "kind": "note", "title": None, "written_by": "hunt:a",
                     "untrusted_data": {"title": "Banner", "body": "rm -rf"}}], "has_more": False})

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length)) if length else None
                stub.seen.append(("POST", self.path, body))
                stub.status = "false_positive" if self.path.endswith("/dismiss") else "active"
                return self._reply(200, {"finding": {"id": FINDING, "status": stub.status}, "dismissal": {}})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def posts(self) -> list[tuple[str, Any]]:
        return [(path, body) for method, path, body in self.seen if method == "POST"]

    def __enter__(self) -> "Stub":
        self.thread.start()
        return self

    def __exit__(self, *args: Any) -> None:
        self.server.shutdown()
        self.server.server_close()


def _run(stub: Stub, terminal: Terminal | None, *argv: str, monkeypatch: pytest.MonkeyPatch) -> int:
    if terminal is not None:
        monkeypatch.setattr(approval, "Terminal", lambda: terminal)
    return v2_cli.main(["--api-url", stub.url, "knowledge", *argv])


def test_show_lists_entries_and_negative_results_with_hostile_text_inert(monkeypatch, capsys):
    with Stub() as stub:
        assert _run(stub, None, "show", TARGET, "--kind", "next_step", monkeypatch=monkeypatch) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out
    assert "Compare roles" in out and "[quoted from the target] Banner" in out and "rm -rf" not in out
    assert "experiment_completed_negative" in out and "not proof" in out
    assert any("kind=next_step" in path and "status=active" in path for method, path, _ in stub.seen)
    assert stub.posts() == []


def test_dismiss_happens_only_on_the_keypress_and_sends_the_reason(monkeypatch):
    with Stub() as stub:
        terminal = Terminal("n")
        assert _run(stub, terminal, "dismiss", TARGET, FINDING, "--reason", "duplicate", "--note", "Same as #12",
                    monkeypatch=monkeypatch) == 0
        assert stub.posts() == [] and "nothing changed" in terminal.stdout.getvalue()
        terminal = Terminal("d")
        assert _run(stub, terminal, "dismiss", TARGET, FINDING, "--reason", "duplicate", "--note", "Same as #12",
                    monkeypatch=monkeypatch) == 0
    assert stub.posts() == [(f"/targets/{TARGET}/findings/{FINDING}/dismiss",
                             {"reason": "duplicate", "note": "Same as #12"})]
    text = terminal.stdout.getvalue()
    assert "\x1b" not in text and "‮" not in text
    assert text.index("XSS in") < text.index("[d] dismiss") and "dismissed: the finding is now false_positive" in text


def test_reopen_needs_its_own_key(monkeypatch):
    with Stub() as stub:
        terminal = Terminal("o")
        assert _run(stub, terminal, "reopen", TARGET, FINDING, "--note", "Changed after the release",
                    monkeypatch=monkeypatch) == 0
    assert stub.posts() == [(f"/targets/{TARGET}/findings/{FINDING}/reopen", {"note": "Changed after the release"})]
    assert "reopened: the finding is now active" in terminal.stdout.getvalue()


def test_a_pipe_never_dismisses(monkeypatch, capsys):
    with Stub() as stub:
        monkeypatch.setattr(approval, "Terminal", REAL_TERMINAL)
        monkeypatch.setattr(sys, "stdin", io.StringIO("d\n"))
        assert v2_cli.main(["--api-url", stub.url, "knowledge", "dismiss", TARGET, FINDING,
                            "--reason", "false_positive", "--note", "agent says"]) == 2
        assert "interactive terminal" in capsys.readouterr().err
    assert stub.seen == []


@pytest.mark.parametrize("burst", ["\x1b[A", "d\n", "dd", "\x1b[200~d\x1b[201~"],
                         ids=["up-arrow", "paste-line", "two-keys", "bracketed-paste"])
def test_arrow_keys_and_pastes_never_dismiss_in_a_real_terminal(tmp_path, burst):
    with Stub() as stub:
        session = Session(["knowledge", "--url", stub.url, "dismiss", TARGET, FINDING, "--reason",
                           "false_positive", "--note", "Checked by hand"], _environment(tmp_path))
        session.expect("[d] dismiss  [n] cancel: ")
        session.type(burst)
        time.sleep(1.0)
        assert stub.posts() == [], f"{burst!r} dismissed the finding"
        session.type("d")
        session.expect("dismissed", timeout=10)
        code, out, err = session.finish()
    assert code == 0, (out, err)
    assert [path for path, _ in stub.posts()] == [f"/targets/{TARGET}/findings/{FINDING}/dismiss"]


def test_an_entry_no_longer_in_force_says_so():
    # A reopened dismissal stays in the negative results as history; it must not read as in force.
    reopened = {"id": "ac3e7ca6", "negative_state": "finding_dismissed", "status": "reopened",
                "title": "Dismissed (accepted_risk): Missing header", "written_by": "operator:interpretations-api"}
    assert "finding_dismissed (reopened)" in v2_cli._entry_line(reopened)
    assert "(active)" not in v2_cli._entry_line({**reopened, "status": "active"})
    assert "finding_dismissed " in v2_cli._entry_line({**reopened, "status": "active"})
