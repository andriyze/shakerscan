"""The `shakerscan` client: fixes from the live OpenCode Hunt runs, and `agent --allow`.

* D15: a client installed from ``git+…@<commit>`` reported only the last released version; it
  now carries the version bump and names its source commit.
* D16: ``connect`` saved a token the instance refused, and dropped a token given for http://.
* D18: ``agent --no-launch`` named codex as the launch command when no agent was installed.
* ``agent --allow``: one step-up before any agent process exists (Enterprise); the bounds and the
  gateway's pre-authorization id reach the agent's Hunts; without the gateway's routes, an exact
  error and no agent.

Unit fixtures: the instance is a fake ``ArsenalClient`` or the stub instance; no network.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CLIENT = ROOT / "client"
sys.path.insert(0, str(CLIENT / "src"))
sys.path.insert(0, str(CLIENT))

import hatch_build  # noqa: E402
from shakerscan import __version__, cli  # noqa: E402
from shakerscan._vendored import load  # noqa: E402

SECRET = "secret-token-value"


@pytest.fixture
def clean_environ():
    saved = dict(os.environ)
    for key in (cli.ENV_URL, cli.ENV_TOKEN, cli.ENV_TOKEN_FILE, cli.ENV_ALLOW_REMOTE, cli.ENV_TIMEOUT,
                "SHAKERSCAN_HUNT_ALLOW", "SHAKERSCAN_PREAUTHORIZATION_ID"):
        os.environ.pop(key, None)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)


def test_the_client_version_is_bumped_past_the_release_that_lacked_terminal_approval():
    major, minor, _patch = (int(part) for part in __version__.split("."))
    assert (major, minor) >= (0, 8), "0.7.5 had no approve/deny/--allow; D15 asked for a visible bump"


def test_a_built_client_names_the_commit_it_was_built_from(tmp_path, monkeypatch, capsys):
    """D15: `git+…@cec4cadd` and `@732b9c15` both said 0.7.5."""
    plan = hatch_build.plan_build_info("wheel", CLIENT, tmp_path)
    source, target = next(iter(plan.items()))
    assert target == "shakerscan/_build.json"
    commit = json.loads(Path(source).read_text(encoding="utf-8"))["source_commit"]
    head = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    assert commit == head
    assert hatch_build.plan_build_info("sdist", CLIENT, tmp_path)[str(tmp_path / "_build.json")] == "src/shakerscan/_build.json"
    # The packaged client reads it back.
    package = tmp_path / "site" / "shakerscan"
    shutil.copytree(CLIENT / "src" / "shakerscan", package, ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copyfile(source, package / "_build.json")
    result = subprocess.run(
        [sys.executable, "-c", "from shakerscan import cli; print(cli.client_version())"],
        env={**os.environ, "PYTHONPATH": str(tmp_path / "site")}, capture_output=True, text=True, timeout=60,
    )
    assert result.stdout.strip() == f"{__version__} (source {commit[:12]})", result.stderr
    # A checkout (no stamp) keeps the plain version.
    assert cli.client_version() == __version__


def _instance(monkeypatch, tmp_path, *, health):
    monkeypatch.setenv(cli.ENV_CONFIG_DIR, str(tmp_path / "cfg"))
    mcp = load("_mcp")

    class Instance:
        def __init__(self, base_url, *, timeout_seconds, api_token):
            self.api_token = api_token

        def request_json(self, method, path, payload=None):
            return health(self.api_token)

        def list_tools(self):
            return [{"name": "shakerscan_hunt_start"}]

    monkeypatch.setattr(mcp, "ArsenalClient", Instance)
    return mcp


def test_connect_with_a_refused_token_saves_nothing(monkeypatch, tmp_path, capsys, clean_environ):
    """D16: the profile and the 0600 token used to be saved, then every command failed."""
    mcp = load("_mcp")

    def health(token):
        raise mcp.MCPError(-32002, "ShakerScan API returned HTTP 401: sign in", '{"detail":"sign in"}', http_status=401)

    _instance(monkeypatch, tmp_path, health=health)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("wrong-token\n"))
    assert cli.main(["connect", "https://scanner.example.com", "--token-stdin"]) == 2
    err = capsys.readouterr().err
    assert "refused this token (HTTP 401)" in err and "Nothing was saved" in err
    assert not (tmp_path / "cfg" / "config.json").exists() and not (tmp_path / "cfg" / "token").exists()


def test_connect_saves_a_token_the_instance_accepts(monkeypatch, tmp_path, capsys, clean_environ):
    _instance(monkeypatch, tmp_path, health=lambda token: {"status": "ok", "token_seen": token == SECRET})
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO(SECRET + "\n"))
    assert cli.main(["connect", "https://scanner.example.com", "--token-stdin"]) == 0
    assert (tmp_path / "cfg" / "token").read_text(encoding="utf-8").strip() == SECRET


def test_connect_refuses_a_token_for_a_plain_http_address(monkeypatch, tmp_path, capsys, clean_environ):
    """D16: `connect http://… --token-stdin` saved a tokenless profile without a word."""
    monkeypatch.setenv(cli.ENV_CONFIG_DIR, str(tmp_path / "cfg"))
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO(SECRET + "\n"))
    assert cli.main(["connect", "http://scanner.example.com", "--token-stdin"]) == 2
    err = capsys.readouterr().err
    assert "never sent over plain http" in err and "shakerscan connect https://scanner.example.com" in err
    assert not (tmp_path / "cfg" / "config.json").exists()
    assert SECRET not in err


def test_agent_no_launch_does_not_suggest_an_agent_that_is_not_installed(monkeypatch, tmp_path, capsys, clean_environ):
    """D18: with nothing on the PATH it printed `launch: cd … && codex`."""
    monkeypatch.setenv(cli.ENV_CONFIG_DIR, str(tmp_path / "cfg"))
    cli.save_profile("https://scanner.example.com", SECRET)
    monkeypatch.setattr(cli.shutil, "which", lambda name: None)
    assert cli.main(["agent", "--workspace", str(tmp_path / "ws"), "--no-launch"]) == 0
    out = capsys.readouterr().out
    assert "&& codex" not in out
    assert "no supported agent is on this PATH" in out and "Codex, Claude Code, OpenCode or Pi" in out
    # Naming one that is missing still prepares it, with a note.
    assert cli.main(["agent", "opencode", "--workspace", str(tmp_path / "ws"), "--no-launch"]) == 0
    out = capsys.readouterr().out
    assert "&& opencode" in out and "opencode is not on this PATH yet" in out


def test_opencode_workspaces_load_the_hunt_skill(monkeypatch, tmp_path, capsys, clean_environ):
    monkeypatch.setenv(cli.ENV_CONFIG_DIR, str(tmp_path / "cfg"))
    cli.save_profile("https://scanner.example.com", SECRET)
    assert cli.main(["agent", "opencode", "--workspace", str(tmp_path / "ws"), "--no-launch"]) == 0
    config = json.loads((tmp_path / "ws" / "opencode.json").read_text(encoding="utf-8"))
    assert config["instructions"] == ["skills/hunt/SKILL.md"]
    assert (tmp_path / "ws" / "skills" / "hunt" / "SKILL.md").is_file()
    assert "environment" not in config["mcp"]["shakerscan"], "no launch bounds without --allow"


class _Terminal:
    """The person's terminal, answered by the test (a labelled double for the pty)."""

    def __init__(self, *lines):
        self.lines = list(lines)
        self.said = []

    def require(self, what):
        return None

    def say(self, text=""):
        self.said.append(text)

    def line(self, prompt):
        return self.lines.pop(0)

    def secret(self, prompt):
        self.said.append(prompt)
        return self.lines.pop(0)


def _launch(monkeypatch, tmp_path, *, gateway):
    from tests.hunt_permission_stub import TOTP

    monkeypatch.setenv(cli.ENV_CONFIG_DIR, str(tmp_path / "cfg"))
    cli.save_profile("https://scanner.example.com", SECRET)
    v2 = load("_v2_cli")
    approval = v2._approval()
    sent = []

    def send(method, path, payload=None, headers=None):
        sent.append((method, path, payload))
        if gateway == "pre-g1":
            return 403, "operator tokens cannot use POST /_enterprise/approvals/begin"
        if path.endswith("/begin"):
            document = approval.set_document(payload["purpose"], payload["account"], payload["origin"], payload)
            return 200, {"schema_version": "shakerscan-approval-challenge/v1", "approval_id": "apv_1",
                         "set_digest": approval.set_digest(document), "methods": ["totp"]}
        assert payload["proof"] == {"method": "totp", "code": TOTP}
        return 200, {"schema_version": "shakerscan-approval-result/v1", "decided_by": "alice",
                     "preauthorization": {"id": "pre_0042", "allow": ["budget.raise:2x"], "expires_at": "later"}}

    monkeypatch.setattr(v2, "_approval_send", lambda client: send)
    monkeypatch.setattr(approval, "Terminal", lambda *a, **k: _Terminal("alice", TOTP))
    launched = {}
    monkeypatch.setattr(cli.shutil, "which", lambda name: f"/usr/bin/{name}" if name == "opencode" else None)
    monkeypatch.setattr(cli.os, "chdir", lambda path: None)
    monkeypatch.setattr(cli.os, "execvpe", lambda file, argv, env: launched.update(file=file, env=env))
    return sent, launched


def test_agent_allow_steps_up_once_before_the_agent_starts(monkeypatch, tmp_path, capsys, clean_environ):
    sent, launched = _launch(monkeypatch, tmp_path, gateway="g1")
    workspace = tmp_path / "ws"
    assert cli.main(["agent", "opencode", "--workspace", str(workspace), "--allow", "budget.raise:2x"]) == 0
    assert [path for _, path, _ in sent] == ["/_enterprise/approvals/begin", "/_enterprise/approvals/finish"]
    begin = sent[0][2]
    assert begin["purpose"] == "preauthorization"
    assert begin["preauthorization"] == {"allow": ["budget.raise:2x"], "use": "agent_launch"}
    env = launched["env"]
    assert json.loads(env["SHAKERSCAN_HUNT_ALLOW"]) == ["budget.raise:2x"]
    assert env["SHAKERSCAN_PREAUTHORIZATION_ID"] == "pre_0042"
    registration = json.loads((workspace / "opencode.json").read_text(encoding="utf-8"))["mcp"]["shakerscan"]
    assert registration["environment"]["SHAKERSCAN_PREAUTHORIZATION_ID"] == "pre_0042"
    assert "pre-authorization pre_0042" in capsys.readouterr().out


def test_agent_allow_against_a_gateway_without_g1_starts_no_agent(monkeypatch, tmp_path, capsys, clean_environ):
    sent, launched = _launch(monkeypatch, tmp_path, gateway="pre-g1")
    assert cli.main(["agent", "opencode", "--workspace", str(tmp_path / "ws"), "--allow", "budget.raise:2x"]) == 2
    err = capsys.readouterr().err
    assert "has no terminal approval yet" in err and "No agent was started" in err
    assert launched == {}


def test_agent_allow_on_an_open_source_engine_needs_no_step_up(monkeypatch, tmp_path, capsys, clean_environ):
    monkeypatch.setenv(cli.ENV_CONFIG_DIR, str(tmp_path / "cfg"))
    assert cli.main(["agent", "opencode", "--url", "http://192.168.1.50:8080", "--workspace", str(tmp_path / "ws"),
                     "--no-launch", "--allow", "capability:state-changing"]) == 0
    out = capsys.readouterr().out
    assert "SHAKERSCAN_HUNT_ALLOW='[\"capability:state-changing\"]'" in out
    assert cli.main(["agent", "opencode", "--url", "http://192.168.1.50:8080", "--no-launch", "--allow", "nonsense"]) == 2
    assert "--allow takes <kind>:<value>" in capsys.readouterr().err


def test_approve_and_deny_are_client_commands_forwarded_with_the_connection(monkeypatch, tmp_path, clean_environ):
    monkeypatch.setenv(cli.ENV_CONFIG_DIR, str(tmp_path / "cfg"))
    cli.save_profile("https://scanner.example.com", SECRET)
    seen = {}
    v2 = load("_v2_cli")
    monkeypatch.setattr(v2, "main", lambda argv: seen.setdefault("argv", argv) and 0)
    assert "approve" in cli.CLIENT_COMMANDS and "deny" in cli.CLIENT_COMMANDS
    assert cli.main(["approve", "req-1", "--hunt", "h-1", "--timeout", "30"]) == 0
    assert seen["argv"] == ["--api-url", "https://scanner.example.com", "--timeout", "30.0", "approve", "req-1", "--hunt", "h-1"]
