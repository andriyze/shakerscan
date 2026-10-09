"""E3: approving a Hunt permission request from the person's own terminal, with the real CLI.

Process tests: the installed command (``python -m shakerscan``) runs in a pseudo-terminal against
a stub instance (``tests/hunt_permission_stub.py``, a unit fixture: real HTTP(S), scripted
routes). They cover the three paths the design names:

* Enterprise: the person's TOTP code, typed at the terminal, goes to the gateway's step-up
  routes; the gateway sets ``decided_by`` to the person. The engine's decision route is never
  called from an Enterprise connection.
* An Enterprise gateway without those routes (before G1): an exact error, nothing decided, no
  fallback to the engine.
* A local open-source engine: a y/N confirmation sent to the engine's decision route.

None of these may run from a pipe (an agent's tool shell): the CLI refuses without a terminal.
"""

from __future__ import annotations

import contextlib
import os
import pty
import select
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from tests.hunt_permission_stub import HUNT, REQUEST, TITLE, TOKEN, TOTP, StubInstance, self_signed

ROOT = Path(__file__).resolve().parents[1]
CLIENT_SRC = ROOT / "client" / "src"


@contextlib.contextmanager
def _sigint_as_a_shell_leaves_it():
    """Start the CLI with SIGINT at its default, as a person's interactive shell starts a
    foreground command. A test run launched in the background (``pytest &``) inherits SIGINT
    ignored, a child inherits that, and a Python started that way keeps ignoring it: a Ctrl-C sent
    below would never arrive. A handled signal (unlike an ignored one) is reset by exec."""
    inherited = signal.getsignal(signal.SIGINT)
    if inherited is not signal.SIG_IGN:
        yield
        return
    signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, inherited)


class Session:
    """The CLI in a pseudo-terminal: stdin is the terminal, stdout/stderr are read here."""

    def __init__(self, argv: list[str], env: dict[str, str]) -> None:
        self.master, slave = pty.openpty()
        with _sigint_as_a_shell_leaves_it():
            self.proc = subprocess.Popen(
                [sys.executable, "-m", "shakerscan", *argv], stdin=slave, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=env, cwd=str(ROOT), start_new_session=True,
            )
        os.close(slave)
        self.out = b""

    def expect(self, text: str, timeout: float = 20.0) -> None:
        deadline = time.monotonic() + timeout
        while text.encode() not in self.out:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or self.proc.poll() is not None and not self._ready(0):
                raise AssertionError(f"never saw {text!r}; output so far: {self.out.decode(errors='replace')}")
            if self._ready(min(0.2, remaining)):
                self.out += os.read(self.proc.stdout.fileno(), 65536)

    def _ready(self, timeout: float) -> bool:
        return bool(select.select([self.proc.stdout], [], [], timeout)[0])

    def type(self, text: str) -> None:
        os.write(self.master, text.encode())

    def finish(self, timeout: float = 30.0) -> tuple[int, str, str]:
        out, err = self.proc.communicate(timeout=timeout)
        os.close(self.master)
        return self.proc.returncode, (self.out + out).decode(), err.decode()


def _environment(tmp_path: Path, **extra: str) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith("SHAKERSCAN_")}
    env.update({"PYTHONPATH": str(CLIENT_SRC), "SHAKERSCAN_CONFIG_DIR": str(tmp_path / "cfg"),
                "SHAKERSCAN_HOME": str(tmp_path / "no-engine"), **extra})
    return env


@pytest.fixture
def enterprise(tmp_path):
    cert, key = self_signed(tmp_path)
    token = tmp_path / "token"
    token.write_text(TOKEN + "\n", encoding="utf-8")
    token.chmod(0o600)

    def start(gateway: str, **options):
        stub = StubInstance(tls=(cert, key), gateway=gateway, **options)
        env = _environment(tmp_path, SSL_CERT_FILE=str(cert))
        return stub, ["--url", stub.url, "--token-file", str(token)], env

    return start


def test_enterprise_approval_takes_the_persons_totp_and_the_gateway_names_them(enterprise):
    stub, connection, env = enterprise("g1")
    with stub:
        session = Session(["approve", *connection, REQUEST, "--hunt", HUNT, "--account", "alice"], env)
        session.expect(TITLE)
        session.expect("TOTP code for alice")
        session.type(TOTP + "\n")
        code, out, err = session.finish()
    assert code == 0, (out, err)
    assert f"granted: {TITLE} (by alice, terminal stepup)" in out
    assert TOTP not in out and TOTP not in err, "the code is never echoed"
    finish = next(body for method, path, body in stub.seen if path == "/_enterprise/approvals/finish")
    assert finish["proof"] == {"method": "totp", "code": TOTP}
    begin = next(body for method, path, body in stub.seen if path == "/_enterprise/approvals/begin")
    assert begin["purpose"] == "permission_decision" and begin["account"] == "alice"
    assert begin["decisions"] == [{"hunt_id": HUNT, "request_id": REQUEST, "subject_digest": "d" * 64,
                                   "decision": "allow", "scope": "hunt", "choice": {}}]
    assert stub.request["status"] == "granted" and stub.request["decided_by"] == "alice"
    assert stub.request["decision_via"] == "terminal_stepup"
    assert not [path for path in stub.routes("POST") if path.endswith("/decision")], (
        "an Enterprise connection never calls the engine's decision route itself"
    )


def test_ctrl_c_ends_watch_promptly_when_the_gateway_stalls_the_revoke(enterprise):
    stub, connection, env = enterprise("g1", stall_revoke=True)
    with stub:
        session = Session(["approve", *connection, "--watch", "--hunt", HUNT, "--account", "alice",
                           "--minutes", "1"], env)
        session.expect("TOTP code for alice")
        session.type(TOTP + "\n")
        session.expect("approver session open until")
        session.expect("[a]llow")
        started = time.monotonic()
        session.proc.send_signal(signal.SIGINT)
        code, out, err = session.finish(timeout=30)
        elapsed = time.monotonic() - started
    assert code == 0, (out, err)
    assert elapsed < 10, f"Ctrl-C took {elapsed:.1f}s to end --watch"
    assert "approver session ended\n" in out and "(time limit)" not in out, (out, err)
    assert "could not revoke the approver session at the gateway; it expires on its own" in out
    assert "/_enterprise/approvals/session/revoke" in stub.routes("POST"), "the revoke was attempted"
    assert stub.request["status"] == "pending", "nothing was decided"


def test_a_wrong_totp_code_decides_nothing(enterprise):
    stub, connection, env = enterprise("g1")
    with stub:
        session = Session(["approve", *connection, REQUEST, "--hunt", HUNT, "--account", "alice"], env)
        session.expect("TOTP code for alice")
        session.type("111111\n")
        code, out, err = session.finish()
    assert code == 2 and "stepup_failed" in err, (out, err)
    assert stub.request["status"] == "pending"


def test_a_gateway_without_the_step_up_routes_gets_an_exact_error_and_no_fallback(enterprise):
    stub, connection, env = enterprise("pre-g1")
    with stub:
        session = Session(["approve", *connection, REQUEST, "--hunt", HUNT, "--account", "alice"], env)
        code, out, err = session.finish()
    assert code == 2, (out, err)
    assert ("this ShakerScan Enterprise gateway has no terminal approval yet: POST "
            "/_enterprise/approvals/begin answered HTTP 403") in err
    assert "step-up routes (G1)" in err and "Nothing was approved, denied or pre-authorized" in err
    assert stub.request["status"] == "pending"
    assert not [path for path in stub.routes() if path.endswith("/decision")], "no fallback to the engine"


def test_local_open_source_approval_is_a_y_n_confirmation_through_the_engine(tmp_path):
    with StubInstance() as stub:
        env = _environment(tmp_path)
        session = Session(["approve", "--url", stub.url, REQUEST], env)
        session.expect("anyone who can reach its API could decide")
        session.expect("on this engine? [y/N]")
        session.type("y\n")
        code, out, err = session.finish()
    assert code == 0, (out, err)
    assert f"granted: {TITLE} (by local-operator, local confirmation)" in out
    decision = next(body for method, path, body in stub.seen if path.endswith("/decision"))
    assert decision["decision"] == "allow" and decision["decision_via"] == "local_confirm"
    assert decision["subject_digest"] == "d" * 64 and decision["idempotency_key"].startswith("local-approve-")
    # Without --hunt the request was found among the open Hunts.
    assert any(path.startswith("/hunts?status=active") for path in stub.routes("GET"))


def test_local_deny_and_a_declined_confirmation(tmp_path):
    with StubInstance() as stub:
        env = _environment(tmp_path)
        session = Session(["approve", "--url", stub.url, REQUEST, "--hunt", HUNT], env)
        session.expect("[y/N]")
        session.type("\n")
        code, out, _ = session.finish()
        assert code == 1 and "nothing was decided" in out
        assert stub.request["status"] == "pending"
        session = Session(["deny", "--url", stub.url, REQUEST, "--hunt", HUNT], env)
        session.expect("Deny this request on this engine? [y/N]")
        session.type("yes\n")
        code, out, err = session.finish()
    assert code == 0, (out, err)
    assert stub.request["status"] == "denied"


def test_approve_refuses_without_a_terminal(tmp_path):
    """An agent's tool shell is a pipe: the command must not decide from there."""
    with StubInstance() as stub:
        result = subprocess.run(
            [sys.executable, "-m", "shakerscan", "approve", "--url", stub.url, REQUEST, "--hunt", HUNT],
            input="y\n", capture_output=True, text=True, env=_environment(tmp_path), cwd=str(ROOT), timeout=60,
        )
    assert result.returncode == 2
    assert "interactive terminal" in result.stderr and "never through an agent's shell" in result.stderr
    assert stub.request["status"] == "pending"
    assert not [path for path in stub.routes() if path.endswith("/decision")]
