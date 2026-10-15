"""``shakerscan secrets``: a target's discovered secrets from the terminal.

Unit fixtures: a scripted terminal double and a loopback stub of the discovered-secrets routes (it is
not an engine). Listing never shows a value; reveal, grant and promote happen only on the person's
keypress (an open-source engine) or through their step-up (Enterprise, the approval protocol).
"""
from __future__ import annotations

import io
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import hunt_approve as approval  # noqa: E402
import v2_cli  # noqa: E402

from tests.test_knowledge_review_cli import Terminal  # noqa: E402

TARGET = "11111111-1111-4111-8111-111111111111"
OTHER = "22222222-2222-4222-8222-222222222222"
SECRET = "33333333-3333-4333-8333-333333333333"
VALUE = "synthetic\x1b[2Jvalue"
REAL_TERMINAL = approval.Terminal


class Stub:
    """Loopback stub of the discovered-secrets routes (unit fixture)."""

    def __init__(self) -> None:
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
                if self.path.startswith("/_enterprise/"):
                    return self._reply(404, {"detail": "Not Found"})
                return self._reply(200, {"secrets": [{
                    "ref": f"secret://{SECRET}", "kind": "password", "label": "DB_\x1b]0;xPASSWORD",
                    "length": 22, "state": "active", "seen_count": 2, "last_seen_at": "2026-10-13",
                    "uses": 1, "found_on": OTHER}], "count": 1, "values_visible": False})

            def _body(self) -> Any:
                length = int(self.headers.get("Content-Length") or 0)
                return json.loads(self.rfile.read(length)) if length else None

            def do_POST(self) -> None:  # noqa: N802
                body = self._body()
                stub.seen.append(("POST", self.path, body))
                if self.path.endswith("/reveal"):
                    return self._reply(200, {"value": VALUE})
                if self.path.endswith("/promote"):
                    return self._reply(201, {"status": "promoted", "profile": {"id": "p-1"}})
                return self._reply(200, {"status": "ok"})

            def do_DELETE(self) -> None:  # noqa: N802
                stub.seen.append(("DELETE", self.path, None))
                return self._reply(200, {"status": "revoked"})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def writes(self) -> list[tuple[str, str, Any]]:
        return [item for item in self.seen if item[0] != "GET"]

    def __enter__(self) -> "Stub":
        self.thread.start()
        return self

    def __exit__(self, *args: Any) -> None:
        self.server.shutdown()
        self.server.server_close()


def _run(stub: Stub, terminal: Terminal | None, *argv: str, monkeypatch: pytest.MonkeyPatch) -> int:
    if terminal is not None:
        monkeypatch.setattr(approval, "Terminal", lambda: terminal)
    return v2_cli.main(["--api-url", stub.url, "secrets", *argv])


def test_list_shows_metadata_with_hostile_text_inert_and_never_a_value(monkeypatch, capsys):
    with Stub() as stub:
        assert _run(stub, None, "list", TARGET, "--usable", monkeypatch=monkeypatch) == 0
    out = capsys.readouterr().out
    assert f"secret://{SECRET}" in out and "granted from " + OTHER in out
    assert "\x1b" not in out and "\x07" not in out
    assert any("usable_only=true" in path for _method, path, _body in stub.seen)
    assert stub.writes() == []


def test_revoke_expiry_and_ungrant_are_plain_operator_writes(monkeypatch):
    with Stub() as stub:
        assert _run(stub, None, "revoke", TARGET, f"secret://{SECRET}", monkeypatch=monkeypatch) == 0
        assert _run(stub, None, "expiry", TARGET, SECRET, "--days", "7", monkeypatch=monkeypatch) == 0
        assert _run(stub, None, "ungrant", TARGET, SECRET, "--to", OTHER, monkeypatch=monkeypatch) == 0
    base = f"/targets/{TARGET}/discovered-secrets/{SECRET}"
    assert stub.writes() == [
        ("POST", base + "/state", {"state": "revoked_by_operator"}),
        ("POST", base + "/expiry", {"days": 7}),
        ("DELETE", base + f"/grants/{OTHER}", None),
    ]


def test_reveal_happens_only_on_the_keypress_and_shows_the_value_inert(monkeypatch):
    with Stub() as stub:
        terminal = Terminal("n")
        assert _run(stub, terminal, "reveal", TARGET, SECRET, monkeypatch=monkeypatch) == 0
        assert stub.writes() == [] and "nothing changed" in terminal.stdout.getvalue()
        terminal = Terminal("y")
        assert _run(stub, terminal, "reveal", TARGET, SECRET, monkeypatch=monkeypatch) == 0
    assert stub.writes() == [("POST", f"/targets/{TARGET}/discovered-secrets/{SECRET}/reveal", {})]
    text = terminal.stdout.getvalue()
    assert "\x1b" not in text and "value: synthetic" in text and "show you the value of" in text


def test_grant_and_promote_send_exactly_their_fields(monkeypatch):
    with Stub() as stub:
        assert _run(stub, Terminal("y"), "grant", TARGET, SECRET, "--to", OTHER, monkeypatch=monkeypatch) == 0
        assert _run(stub, Terminal("y"), "promote", TARGET, SECRET, "--name", "Found", "--auth-kind",
                    "api_key_header", "--header-name", "X-Api-Key", monkeypatch=monkeypatch) == 0
    base = f"/targets/{TARGET}/discovered-secrets/{SECRET}"
    assert stub.writes() == [
        ("POST", base + "/grants", {"target_id": OTHER}),
        ("POST", base + "/promote", {"name": "Found", "auth_kind": "api_key_header", "header_name": "X-Api-Key"}),
    ]


def test_a_pipe_never_reveals(monkeypatch, capsys):
    with Stub() as stub:
        monkeypatch.setattr(approval, "Terminal", REAL_TERMINAL)
        monkeypatch.setattr(sys, "stdin", io.StringIO("y\n"))
        assert v2_cli.main(["--api-url", stub.url, "secrets", "reveal", TARGET, SECRET]) == 2
        assert "interactive terminal" in capsys.readouterr().err
    assert stub.writes() == []


def test_enterprise_decides_through_the_step_up_with_the_exact_decision(monkeypatch):
    decided: list[dict[str, Any]] = []
    monkeypatch.setattr(approval, "instance_kind", lambda send: "enterprise")
    monkeypatch.setattr(approval, "StepUp", lambda *args, **kwargs: object())

    def decide(stepup, entry):
        decided.append(dict(entry))
        return 200, {"value": VALUE}

    monkeypatch.setattr(approval, "decide_knowledge", decide)
    with Stub() as stub:
        terminal = Terminal("")
        assert _run(stub, terminal, "reveal", TARGET, SECRET, monkeypatch=monkeypatch) == 0
        assert stub.writes() == []  # the gateway applies it, never this client
    assert decided == [{"decision": "secret_decision", "method": "POST",
                        "path": f"/targets/{TARGET}/discovered-secrets/{SECRET}/reveal", "payload": {}}]
    assert "value: synthetic" in terminal.stdout.getvalue()


class ManyStub(Stub):
    """The list route answering ``count`` rows whatever limit it is sent (an engine before 2.11
    ignores limit=; unit fixture)."""

    def __init__(self, count: int) -> None:
        super().__init__()
        rows = [{"ref": f"secret://{index:08d}-0000-4000-8000-000000000000", "kind": "token", "label": None,
                 "length": 8, "state": "active", "seen_count": 1, "last_seen_at": "2026-10-13", "uses": 0,
                 "found_on": TARGET} for index in range(count)]
        handler = self.server.RequestHandlerClass
        stub = self

        def do_GET(self) -> None:  # noqa: N802
            stub.seen.append(("GET", self.path, None))
            self._reply(200, {"secrets": rows, "count": len(rows), "values_visible": False})

        handler.do_GET = do_GET


def test_list_sends_a_limit_and_says_when_there_are_more(monkeypatch, capsys):
    """the list had no limit; it asks for one more than it shows, and an engine that
    ignores limit= (before 2.11) is cut to --limit by the client."""
    with ManyStub(30) as stub:
        assert _run(stub, None, "list", TARGET, "--limit", "5", monkeypatch=monkeypatch) == 0
    out = capsys.readouterr().out
    assert any(path.endswith("/discovered-secrets?limit=6") for _m, path, _b in stub.seen), stub.seen
    assert out.count("secret://") == 5 and "there are more" in out and "--limit" in out

    with ManyStub(3) as stub:
        assert _run(stub, None, "list", TARGET, "--usable", monkeypatch=monkeypatch) == 0
    out = capsys.readouterr().out
    assert any("usable_only=true&limit=51" in path for _m, path, _b in stub.seen), stub.seen
    assert out.count("secret://") == 3 and "more" not in out

    with ManyStub(200) as stub:
        assert _run(stub, None, "list", TARGET, "--limit", "200", monkeypatch=monkeypatch) == 0
    out = capsys.readouterr().out
    assert out.count("secret://") == 200 and "there may be more" in out

    for bad in ("0", "201", "x"):
        with pytest.raises(SystemExit):
            v2_cli.main(["--api-url", "http://127.0.0.1:9", "secrets", "list", TARGET, "--limit", bad])
