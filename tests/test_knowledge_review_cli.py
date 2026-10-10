"""``shakerscan knowledge review``: deciding instruction proposals at the person's own terminal.

Unit fixtures: a scripted terminal double and a stub instance serving the proposal routes over
real loopback HTTP (it is not an engine). The pseudo-terminal tests run the installed client
(``python -m shakerscan``) and send real key bytes, so an arrow key, an escape sequence or a paste is
checked to decide nothing, as for ``approve``.
"""
from __future__ import annotations

import io
import json
import os
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

TARGET = "11111111-1111-4111-8111-111111111111"
PROPOSAL = "22222222-2222-4222-8222-222222222222"
REBASED = "33333333-3333-4333-8333-333333333333"
REAL_TERMINAL = approval.Terminal


def _proposal(**extra: Any) -> dict[str, Any]:
    return {"id": PROPOSAL, "target_id": TARGET, "target_name": "Admin portal", "status": "pending",
            "title": "Cover the admin API", "reason": "8443 is reachable", "evidence_refs": [],
            "proposed_by": "hunt:abc", "created_at": "2026-10-10T00:00:00Z", "base_revision": 2,
            "current_revision": 2, "stale": False,
            "diff": {"format": "unified", "text": "--- current instructions\n+++ proposed instructions\n"
                     "@@ -1 +1 @@\n-Inspect 443.\n+Inspect 443 and 8443.", "added_lines": 1,
                     "removed_lines": 1, "truncated": False}, **extra}


class Stub:
    """A loopback stub of the proposal routes (unit fixture); records every request."""

    def __init__(self, *proposals: dict[str, Any]) -> None:
        self.proposals = {item["id"]: dict(item) for item in proposals}
        self.seen: list[tuple[str, str, Any]] = []
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
                pending = [item for item in stub.proposals.values() if item["status"] == "pending"]
                self._reply(200, {"proposals": pending, "count": len(pending), "has_more": False})

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length)) if length else None
                stub.seen.append(("POST", self.path, body))
                identifier, action = self.path.rstrip("/").split("/")[-2:]
                item = stub.proposals[identifier]
                if action == "accept":
                    if item.get("stale"):
                        return self._reply(409, {"detail": {"error": "proposal_stale", "message": "stale"}})
                    item["status"] = "accepted"
                    return self._reply(200, {"proposal": item, "instructions": {"revision": 3}})
                if action == "reject":
                    item["status"] = "rejected"
                    return self._reply(200, {"proposal": item})
                item["status"] = "superseded"
                fresh = {**item, "id": REBASED, "status": "pending", "stale": False, "base_revision": 5,
                         "current_revision": 5}
                stub.proposals[REBASED] = fresh
                return self._reply(200, {"proposal": fresh, "superseded": identifier})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def decisions(self) -> list[str]:
        return [path.rsplit("/", 1)[-1] for method, path, _ in self.seen if method == "POST"]

    def __enter__(self) -> "Stub":
        self.thread.start()
        return self

    def __exit__(self, *args: Any) -> None:
        self.server.shutdown()
        self.server.server_close()


class Terminal(approval.Terminal):
    """A labelled double for the person's terminal: scripted keys."""

    def __init__(self, *keys: str) -> None:
        super().__init__(io.StringIO(), io.StringIO())
        self.keys = list(keys)

    def require(self, what: str) -> None:
        return None

    def key(self, prompt: str, choices: str, **_waiting: Any) -> str:
        self.stdout.write(prompt)
        key = self.keys.pop(0)
        assert key in choices, (key, choices)
        return key


def _review(stub: Stub, terminal: Terminal, *argv: str, monkeypatch: pytest.MonkeyPatch) -> int:
    monkeypatch.setattr(approval, "Terminal", lambda: terminal)
    return v2_cli.main(["--api-url", stub.url, "knowledge", "review", *argv])


@pytest.mark.parametrize(("key", "decision", "status"), [("y", "accept", "accepted"), ("r", "reject", "rejected")])
def test_a_keypress_accepts_or_rejects_and_shows_the_diff_first(monkeypatch, key, decision, status):
    with Stub(_proposal()) as stub:
        terminal = Terminal(key)
        assert _review(stub, terminal, monkeypatch=monkeypatch) == 0
    assert stub.decisions() == [decision] and stub.proposals[PROPOSAL]["status"] == status
    text = terminal.stdout.getvalue()
    assert text.index("+Inspect 443 and 8443.") < text.index("[y] accept")
    assert "Cover the admin API" in text and "hunt:abc" in text


def test_not_now_and_quit_decide_nothing(monkeypatch):
    second = _proposal(id=REBASED, title="Second")
    with Stub(_proposal(), second) as stub:
        assert _review(stub, Terminal("n", "q"), monkeypatch=monkeypatch) == 0
    assert stub.decisions() == []
    assert {item["status"] for item in stub.proposals.values()} == {"pending"}


def test_a_stale_proposal_cannot_be_accepted_until_rebased_and_reviewed_again(monkeypatch):
    with Stub(_proposal(stale=True, current_revision=5)) as stub:
        terminal = Terminal("b", "y")
        assert _review(stub, terminal, TARGET, monkeypatch=monkeypatch) == 0
    assert stub.decisions() == ["rebase", "accept"]
    assert stub.proposals[PROPOSAL]["status"] == "superseded" and stub.proposals[REBASED]["status"] == "accepted"
    text = terminal.stdout.getvalue()
    assert "STALE" in text and "[b] rebase" in text and text.count("+Inspect 443 and 8443.") == 2
    assert any(path.startswith(f"/targets/{TARGET}/instruction-proposals") for method, path, _ in stub.seen if method == "GET")


def test_accept_and_reject_options_name_one_proposal_and_still_ask(monkeypatch):
    other = _proposal(id=REBASED, title="Other")
    with Stub(_proposal(), other) as stub:
        assert _review(stub, Terminal("n"), "--accept", PROPOSAL, monkeypatch=monkeypatch) == 0
        assert stub.decisions() == []
        assert _review(stub, Terminal("y"), "--accept", PROPOSAL, "--note", "ok", monkeypatch=monkeypatch) == 0
        assert _review(stub, Terminal("r"), "--reject", REBASED, monkeypatch=monkeypatch) == 0
    assert stub.decisions() == ["accept", "reject"]
    assert [body for method, path, body in stub.seen if method == "POST"][0]["note"] == "ok"
    assert stub.proposals[PROPOSAL]["status"] == "accepted" and stub.proposals[REBASED]["status"] == "rejected"


def test_accept_sends_the_digest_of_the_text_that_was_shown(monkeypatch):
    with Stub(_proposal(methodology_sha256="f" * 64)) as stub:
        assert _review(stub, Terminal("y"), monkeypatch=monkeypatch) == 0
    (body,) = [body for method, path, body in stub.seen if method == "POST"]
    assert body == {"note": None, "methodology_sha256": "f" * 64}


def test_a_diff_that_was_not_shown_in_full_cannot_be_accepted(monkeypatch):
    long_diff = {"format": "unified", "text": "\n".join(f"+line {index}" for index in range(500)),
                 "added_lines": 500, "removed_lines": 0, "truncated": False}
    for diff in (long_diff, {**_proposal()["diff"], "truncated": True}):
        with Stub(_proposal(diff=diff)) as stub:
            terminal = Terminal("r")
            assert _review(stub, terminal, monkeypatch=monkeypatch) == 0
        assert stub.decisions() == ["reject"]
        text = terminal.stdout.getvalue()
        assert "[y] accept" not in text and "cannot be accepted here" in text


def test_control_sequences_in_proposal_text_are_shown_inert(monkeypatch):
    hostile = _proposal(title="Fix\x1b[2K\x1b[1Ascope", reason="ok\x07\x9b31m",
                        diff={**_proposal()["diff"], "text": "+safe\n\x1b]0;title\x07+hidden"})
    with Stub(hostile) as stub:
        terminal = Terminal("n")
        assert _review(stub, terminal, monkeypatch=monkeypatch) == 0
    text = terminal.stdout.getvalue()
    assert "\x1b" not in text and "\x07" not in text and "\x9b" not in text
    assert "Fix?[2K?[1Ascope" in text


def test_an_unknown_id_or_a_pipe_decides_nothing(monkeypatch, capsys):
    with Stub(_proposal()) as stub:
        assert _review(stub, Terminal(), "--accept", REBASED, monkeypatch=monkeypatch) == 2
        assert "no pending instruction proposal" in capsys.readouterr().err
        # The real terminal check: a pipe (an agent's tool shell) is refused before any request.
        monkeypatch.setattr(approval, "Terminal", REAL_TERMINAL)
        monkeypatch.setattr(sys, "stdin", io.StringIO("y\n"))
        assert v2_cli.main(["--api-url", stub.url, "knowledge", "review"]) == 2
        assert "interactive terminal" in capsys.readouterr().err
    assert stub.decisions() == []


# --- the real CLI in a pseudo-terminal --------------------------------------------------------------

PROMPT = "[y] accept  [n] not now  [r] reject  [q] quit: "


def _environment(tmp_path: Path) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith("SHAKERSCAN_")}
    env.update({"PYTHONPATH": str(ROOT / "client" / "src"), "SHAKERSCAN_CONFIG_DIR": str(tmp_path / "cfg"),
                "SHAKERSCAN_HOME": str(tmp_path / "no-engine")})
    return env


@pytest.mark.parametrize("burst", ["\x1b[A", "\x1b[B", "\x1bOA", "\x1by", "y\n", "yy", "\x1b[200~y\x1b[201~"],
                         ids=["up-arrow", "down-arrow", "up-arrow-ss3", "alt-y", "paste-line", "two-keys",
                              "bracketed-paste"])
def test_arrow_keys_and_pastes_never_decide_in_a_real_terminal(tmp_path, burst):
    with Stub(_proposal()) as stub:
        session = Session(["knowledge", "--url", stub.url, "review"], _environment(tmp_path))
        session.expect(PROMPT)
        session.type(burst)
        time.sleep(1.0)
        assert stub.decisions() == [], f"{burst!r} decided the proposal"
        session.type("r")
        session.expect("rejected", timeout=10)
        code, out, err = session.finish()
    assert code == 0, (out, err)
    assert stub.decisions() == ["reject"]
    assert stub.proposals[PROPOSAL]["status"] == "rejected"


def test_uppercase_y_does_not_accept_and_a_lone_y_does(tmp_path):
    with Stub(_proposal()) as stub:
        session = Session(["knowledge", "--url", stub.url, "review"], _environment(tmp_path))
        session.expect(PROMPT)
        session.type("Y")
        time.sleep(0.8)
        assert stub.decisions() == []
        session.type("y")
        session.expect("accepted: the target instructions are now revision 3", timeout=10)
        code, out, err = session.finish()
    assert code == 0, (out, err)
    assert stub.decisions() == ["accept"]
