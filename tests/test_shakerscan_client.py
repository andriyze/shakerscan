"""The `shakerscan` client package (client/): one command name, two install channels."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import urllib.error
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CLIENT = ROOT / "client"
SRC = CLIENT / "src"
sys.path.insert(0, str(SRC))
sys.path.insert(0, str(CLIENT))
sys.path.insert(0, str(CLIENT / "homebrew"))

import hatch_build  # noqa: E402
import render_formula  # noqa: E402
from shakerscan import __version__, cli  # noqa: E402
from shakerscan._vendored import kit_sources, load  # noqa: E402

ONE_LINER = "curl -fsSL https://install.shakerscan.com | sh"
SECRET = "secret-token-value"


@pytest.fixture
def clean_environ():
    """`cli.main` writes the connection into os.environ; keep tests independent."""
    saved = dict(os.environ)
    for key in (cli.ENV_URL, cli.ENV_TOKEN, cli.ENV_TOKEN_FILE, cli.ENV_ALLOW_REMOTE, cli.ENV_TIMEOUT):
        os.environ.pop(key, None)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)


def _run(argv: list[str], *, env: dict[str, str], cwd: Path) -> subprocess.CompletedProcess[str]:
    merged = {**os.environ, **env, "PYTHONPATH": str(SRC)}
    return subprocess.run(
        [sys.executable, "-m", "shakerscan", *argv], env=merged, cwd=cwd, capture_output=True, text=True, timeout=60
    )


def test_a_checkout_runs_the_runtime_scripts_themselves():
    mcp = load("_mcp")
    v2 = load("_v2_cli")
    assert Path(mcp.__file__).resolve() == ROOT / "scripts" / "shakerscan_mcp.py"
    assert Path(v2.__file__).resolve() == ROOT / "scripts" / "v2_cli.py"
    assert callable(mcp.main) and callable(v2.main)


def test_the_build_vendors_the_runtime_scripts_and_the_agent_kit(tmp_path):
    scripts = ROOT / "scripts"
    wheel = hatch_build.plan_force_include("wheel", CLIENT)
    assert wheel[str(scripts / "shakerscan_mcp.py")] == "shakerscan/_mcp.py"
    assert wheel[str(scripts / "api_cli.py")] == "shakerscan/_api_cli.py"
    assert wheel[str(scripts / "scan_cli.py")] == "shakerscan/_scan_cli.py"
    assert wheel[str(ROOT / "skills")] == "shakerscan/_kit/skills"
    assert wheel[str(ROOT / ".claude")] == "shakerscan/_kit/claude"
    assert wheel[str(ROOT / "AGENTS.md")] == "shakerscan/_kit/AGENTS.md"
    sdist = hatch_build.plan_force_include("sdist", CLIENT)
    assert sdist[str(scripts / "v2_cli.py")] == "src/shakerscan/_v2_cli.py"
    assert sdist[str(ROOT / "CLAUDE.md")] == "src/shakerscan/_kit/CLAUDE.md"
    # An unpacked sdist has no repository beside it but carries the copies: nothing to map.
    unpacked = tmp_path / "shakerscan-0.0.0" / "src" / "shakerscan"
    unpacked.mkdir(parents=True)
    for module in hatch_build.VENDORED.values():
        (unpacked / module).write_text("# vendored\n", encoding="utf-8")
    for target in hatch_build.KIT.values():
        path = unpacked / target
        if target.endswith(".md"):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# kit\n", encoding="utf-8")
        else:
            path.mkdir(parents=True, exist_ok=True)
    assert hatch_build.plan_force_include("wheel", tmp_path / "shakerscan-0.0.0") == {}
    # Neither source: fail loudly rather than ship a client without its adapter.
    (tmp_path / "bare" / "src" / "shakerscan").mkdir(parents=True)
    with pytest.raises(RuntimeError, match="vendored runtime sources not found"):
        hatch_build.plan_force_include("wheel", tmp_path / "bare")


def _fake_engine(home: Path, version: str = "2.3.4") -> Path:
    home.mkdir(parents=True, exist_ok=True)
    (home / "VERSION").write_text(version + "\n", encoding="utf-8")
    launcher = home / "scanner.sh"
    launcher.write_text(
        '#!/bin/sh\nprintf \'launcher tag=%s args=%s\\n\' "${SCANNER_IMAGE_TAG:-unset}" "$*"\n', encoding="utf-8"
    )
    launcher.chmod(launcher.stat().st_mode | stat.S_IXUSR)
    return launcher


def test_version_reports_the_client_and_a_local_engine(capsys, monkeypatch, tmp_path):
    monkeypatch.setenv(cli.ENV_HOME, str(tmp_path / "missing"))
    assert cli.main(["version"]) == 0
    assert capsys.readouterr().out.strip() == f"shakerscan client {__version__}"
    _fake_engine(tmp_path / "engine")
    monkeypatch.setenv(cli.ENV_HOME, str(tmp_path / "engine"))
    assert cli.main(["version"]) == 0
    assert capsys.readouterr().out.splitlines() == [
        f"shakerscan client {__version__}",
        f"engine 2.3.4 ({tmp_path / 'engine' / 'scanner.sh'})",
    ]


def test_engine_commands_are_handed_to_the_local_install(tmp_path):
    _fake_engine(tmp_path / "engine")
    result = _run(
        ["status", "--json"], env={cli.ENV_HOME: str(tmp_path / "engine"), "SCANNER_IMAGE_TAG": ""}, cwd=tmp_path
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "launcher tag=2.3.4 args=status --json"


def test_an_engine_command_without_an_install_explains_the_one_liner(tmp_path):
    result = _run(["start"], env={cli.ENV_HOME: str(tmp_path / "missing")}, cwd=tmp_path)
    assert result.returncode == 2
    assert ONE_LINER in result.stderr
    assert "client build" in result.stderr
    assert "Traceback" not in result.stderr


def test_an_explicit_url_authorizes_the_origin_and_the_token_stays_out_of_argv(tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text(f"  {SECRET} \n", encoding="utf-8")
    assert cli.connection_environment("https://scanner.example.com", str(token_file), 7.5, environ={}) == {
        cli.ENV_URL: "https://scanner.example.com",
        cli.ENV_ALLOW_REMOTE: "true",
        cli.ENV_TOKEN: SECRET,
        cli.ENV_TIMEOUT: "7.5",
    }
    # A URL taken from the environment keeps the adapter's own remote-origin rule.
    assert (
        cli.connection_environment(
            None, None, None, environ={cli.ENV_URL: "https://scanner.example.com", cli.ENV_CONFIG_DIR: str(tmp_path)}
        )
        == {}
    )
    (tmp_path / "empty").write_text("\n", encoding="utf-8")
    with pytest.raises(cli.ClientError, match="empty"):
        cli.connection_environment(None, str(tmp_path / "empty"), None, environ={})


def test_mcp_refuses_a_token_over_plain_http_without_printing_it(tmp_path, capsys, clean_environ):
    token_file = tmp_path / "token"
    token_file.write_text(SECRET + "\n", encoding="utf-8")
    code = cli.main(["mcp", "--url", "http://scanner.example.com", "--token-file", str(token_file)])
    captured = capsys.readouterr()
    assert code == 2
    assert "https" in captured.err.lower()
    assert SECRET not in captured.err + captured.out


def test_hunt_forwards_to_the_product_cli_with_the_connection_first(monkeypatch, tmp_path, clean_environ):
    token_file = tmp_path / "token"
    token_file.write_text(SECRET + "\n", encoding="utf-8")
    seen: dict[str, object] = {}

    class FakeProductCli:
        @staticmethod
        def main(argv):
            seen["argv"] = list(argv)
            seen["token"] = os.environ.get(cli.ENV_TOKEN)
            return 0

    monkeypatch.setattr(cli, "load", lambda name: FakeProductCli if name == "_v2_cli" else pytest.fail(name))
    code = cli.main(
        ["hunt", "--url", "https://scanner.example.com", "--token-file", str(token_file), "list", "--limit", "5"]
    )
    assert code == 0
    assert seen["argv"] == ["--api-url", "https://scanner.example.com", "hunt", "list", "--limit", "5"]
    assert seen["token"] == SECRET
    assert cli.main(["hunt", "--url", "https://scanner.example.com"]) == 0
    assert seen["argv"] == ["--api-url", "https://scanner.example.com", "hunt", "--help"]


def test_doctor_reports_the_catalogue_the_instance_offers(monkeypatch, capsys, clean_environ):
    mcp = load("_mcp")

    class FakeClient:
        def __init__(self, base_url, *, timeout_seconds, api_token):
            assert base_url == "https://scanner.example.com"
            assert timeout_seconds == 20.0
            assert api_token is None

        def request_json(self, method, path, payload=None):
            assert (method, path, payload) == ("GET", "/health", None)
            return {"status": "ok"}

        def list_tools(self):
            return [{"name": "shakerscan_targets"}, {"name": "shakerscan_hunt_start"}, {"name": "shakerscan_hunt_query"}]

    monkeypatch.setattr(mcp, "ArsenalClient", FakeClient)
    assert cli.main(["doctor", "--url", "https://scanner.example.com"]) == 0
    out = capsys.readouterr().out
    assert "engine:   reachable (ok)" in out
    assert "3 tools (1 read-only Arsenal, 2 Hunt)" in out
    assert "token:    none" in out


def test_the_formula_renders_from_pypi_metadata():
    metadata = {
        "urls": [
            {"packagetype": "bdist_wheel", "url": "https://files.example/shakerscan-0.1.0-py3-none-any.whl", "digests": {"sha256": "a" * 64}},
            {"packagetype": "sdist", "url": "https://files.example/shakerscan-0.1.0.tar.gz", "digests": {"sha256": "b" * 64}},
        ]
    }
    url, sha256 = render_formula.sdist_for("0.1.0", metadata)
    assert (url, sha256) == ("https://files.example/shakerscan-0.1.0.tar.gz", "b" * 64)
    formula = render_formula.render("0.1.0", url, sha256)
    assert f'url "{url}"' in formula and f'sha256 "{sha256}"' in formula
    assert 'assert_match "shakerscan client 0.1.0"' in formula
    assert not any(placeholder in formula for placeholder in render_formula.PLACEHOLDERS)
    with pytest.raises(LookupError):
        render_formula.sdist_for("0.1.0", {"urls": metadata["urls"][:1]})


# --- the installer keeps a client build of the command ---------------------------------------


def _install_command_function() -> str:
    text = (ROOT / "install" / "index.sh").read_text(encoding="utf-8")
    start = text.index("\ninstall_command() {\n") + 1
    end = text.index("\n}\n", start) + 3
    return text[start:end]


def _run_install_command(tmp_path: Path, existing: str | None) -> tuple[str, str]:
    install_dir = tmp_path / "home"
    install_dir.mkdir(parents=True)
    (install_dir / "VERSION").write_text("2.3.4\n", encoding="utf-8")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True)
    if existing is not None:
        (bin_dir / "shakerscan").write_text(existing, encoding="utf-8")
    script = "\n".join(
        [
            "set -eu",
            f'INSTALL_DIR="{install_dir}"',
            f'BIN_DIR="{bin_dir}"',
            f'PATH="{bin_dir}:$PATH"',
            "say() { printf '%s\\n' \"$*\"; }",
            "fail() { printf 'FAIL %s\\n' \"$*\" >&2; exit 1; }",
            "install_path_profiles() { :; }",
            _install_command_function(),
            "install_command",
        ]
    )
    result = subprocess.run(["sh", "-c", script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return result.stdout, (bin_dir / "shakerscan").read_text(encoding="utf-8")


def test_the_installer_writes_the_launcher_shim_and_replaces_an_old_one(tmp_path):
    _, fresh = _run_install_command(tmp_path / "fresh", None)
    assert f'exec "{tmp_path / "fresh" / "home"}/scanner.sh" "$@"' in fresh
    assert 'SCANNER_IMAGE_TAG:=2.3.4' in fresh
    old_shim = '#!/bin/sh\nexec "/old/install/scanner.sh" "$@"\n'
    _, replaced = _run_install_command(tmp_path / "upgrade", old_shim)
    assert "/old/install/" not in replaced
    assert f'exec "{tmp_path / "upgrade" / "home"}/scanner.sh" "$@"' in replaced


def test_the_installer_keeps_a_client_build_on_the_path(tmp_path):
    client = "#!/usr/bin/python3\n# -*- coding: utf-8 -*-\nimport sys\nfrom shakerscan.cli import main\nsys.exit(main())\n"
    stdout, after = _run_install_command(tmp_path, client)
    assert after == client
    assert "Kept the existing shakerscan client" in stdout


def test_doctor_for_a_local_engine_hands_off_to_the_launcher_host_checks(tmp_path):
    _fake_engine(tmp_path / "engine")
    # A closed loopback port: the connection lines report the refusal, then the launcher runs.
    result = _run(
        ["doctor", "--url", "http://127.0.0.1:9"],
        env={cli.ENV_HOME: str(tmp_path / "engine"), "SCANNER_IMAGE_TAG": ""},
        cwd=tmp_path,
    )
    assert result.returncode == 0, result.stderr
    assert f"client:   {__version__}" in result.stdout
    assert result.stdout.rstrip().endswith("launcher tag=2.3.4 args=doctor")
    # A remote instance is a connection check only; no launcher involved.
    remote = _run(
        ["doctor", "--url", "https://127.0.0.2:9", "--timeout", "1"], env={cli.ENV_HOME: str(tmp_path / "engine")}, cwd=tmp_path
    )
    assert "launcher" not in remote.stdout


def test_doctor_names_the_transport_reason(monkeypatch, capsys, clean_environ):
    mcp = load("_mcp")

    class DownClient:
        def __init__(self, base_url, *, timeout_seconds, api_token):
            pass

        def request_json(self, method, path, payload=None):
            raise mcp.MCPError(-32001, "ShakerScan API is unavailable", "<urlopen error timed out>")

        def list_tools(self):
            raise mcp.MCPError(-32001, "ShakerScan API is unavailable", "<urlopen error timed out>")

    monkeypatch.setattr(mcp, "ArsenalClient", DownClient)
    assert cli.main(["doctor", "--url", "https://scanner.example.com"]) == 1
    out = capsys.readouterr().out
    assert "engine:   ShakerScan API is unavailable: <urlopen error timed out>" in out
    assert "mcp:      ShakerScan API is unavailable: <urlopen error timed out>" in out


def _connected(monkeypatch, tmp_path, *, role="operator"):
    """A connect link claim answered without the network, and a fake instance behind doctor."""
    monkeypatch.setenv(cli.ENV_CONFIG_DIR, str(tmp_path / "cfg"))
    monkeypatch.setattr(
        cli,
        "fetch_connect_link",
        lambda link, **kw: {"url": "https://scanner.example.com", "token": SECRET, "role": role, "label": "Laptop"},
    )
    mcp = load("_mcp")

    class FakeClient:
        seen: dict[str, object] = {}

        def __init__(self, base_url, *, timeout_seconds, api_token):
            FakeClient.seen = {"base_url": base_url, "api_token": api_token}

        def request_json(self, method, path, payload=None):
            return {"status": "ok"}

        def list_tools(self):
            return [{"name": "shakerscan_targets"}, {"name": "shakerscan_hunt_start"}]

    monkeypatch.setattr(mcp, "ArsenalClient", FakeClient)
    return FakeClient


def test_connect_with_a_link_saves_the_profile_owner_only_and_checks_it(monkeypatch, tmp_path, capsys, clean_environ):
    fake = _connected(monkeypatch, tmp_path)
    code = cli.main(["connect", "https://scanner.example.com/_enterprise/connect/" + "c" * 43])
    out = capsys.readouterr().out
    assert code == 0, out
    cfg = tmp_path / "cfg"
    assert (cfg / "token").read_text(encoding="utf-8").strip() == SECRET
    assert stat.S_IMODE((cfg / "token").stat().st_mode) == 0o600
    assert stat.S_IMODE(cfg.stat().st_mode) == 0o700
    assert json.loads((cfg / "config.json").read_text(encoding="utf-8")) == {
        "url": "https://scanner.example.com",
        "token_file": str(cfg / "token"),
    }
    assert fake.seen == {"base_url": "https://scanner.example.com", "api_token": SECRET}
    assert "2 tools (1 read-only Arsenal, 1 Hunt)" in out and SECRET not in out
    assert "claude mcp add --scope user shakerscan -- shakerscan mcp" in out
    # From now on every command uses the saved instance and token without options. (connect ran
    # doctor in this process, which exported the connection; a fresh process starts clean.)
    for key in (cli.ENV_URL, cli.ENV_TOKEN, cli.ENV_TOKEN_FILE, cli.ENV_ALLOW_REMOTE):
        os.environ.pop(key, None)
    assert cli.connection_environment(None, None, None) == {
        cli.ENV_URL: "https://scanner.example.com",
        cli.ENV_ALLOW_REMOTE: "true",
        cli.ENV_TOKEN: SECRET,
    }
    assert cli.main(["doctor"]) == 0
    assert "saved profile" in capsys.readouterr().out
    # An explicit --url still wins over the profile.
    assert cli.connection_environment("https://other.example", None, None)[cli.ENV_URL] == "https://other.example"
    assert cli.main(["disconnect"]) == 0
    assert not (cfg / "token").exists() and not (cfg / "config.json").exists()


def test_connect_registers_claude_code_when_asked(monkeypatch, tmp_path, capsys, clean_environ):
    _connected(monkeypatch, tmp_path)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    record = tmp_path / "claude-argv"
    fake_claude = bin_dir / "claude"
    fake_claude.write_text(f'#!/bin/sh\nprintf \'%s\\n\' "$@" > "{record}"\n', encoding="utf-8")
    fake_claude.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ["PATH"])
    assert cli.main(["connect", "https://scanner.example.com/_enterprise/connect/" + "d" * 43, "--claude"]) == 0
    argv = record.read_text(encoding="utf-8").split("\n")
    assert argv[:6] == ["mcp", "add", "--scope", "user", "shakerscan", "--"]
    assert argv[6].endswith("shakerscan") and argv[7] == "mcp"
    assert "registered as MCP server" in capsys.readouterr().out


def test_connect_refuses_plain_http_and_explains_a_used_link(monkeypatch, tmp_path, capsys, clean_environ):
    monkeypatch.setenv(cli.ENV_CONFIG_DIR, str(tmp_path / "cfg"))
    assert cli.main(["connect", "http://scanner.example.com/_enterprise/connect/" + "e" * 43]) == 2
    assert "https only" in capsys.readouterr().err
    assert not (tmp_path / "cfg" / "token").exists()

    class UsedLink:
        def open(self, request, timeout=None):
            raise urllib.error.HTTPError(request.full_url, 404, "gone", {}, None)

    with pytest.raises(cli.ClientError, match="expired or was already used"):
        cli.fetch_connect_link("https://scanner.example.com/_enterprise/connect/" + "f" * 43, opener=UsedLink())



def test_a_checkout_offers_the_kit_and_the_other_runtime_clis():
    sources = kit_sources()
    assert sources["skills"] == ROOT / "skills" and sources[".claude"] == ROOT / ".claude"
    assert callable(load("_api_cli").main) and callable(load("_scan_cli").main)


def test_agent_prepares_the_workspace_against_the_connected_instance(monkeypatch, tmp_path, capsys, clean_environ):
    monkeypatch.setenv(cli.ENV_CONFIG_DIR, str(tmp_path / "cfg"))
    assert cli.main(["agent", "--no-launch"]) == 2, "no connected instance yet"
    assert "shakerscan connect" in capsys.readouterr().err
    cli.save_profile("https://scanner.example.com", SECRET)
    workspace = tmp_path / "ws"
    assert cli.main(["agent", "claude", "--workspace", str(workspace), "--no-launch"]) == 0
    out = capsys.readouterr().out
    assert f"cd {workspace} && claude" in out
    assert (workspace / "skills" / "shakerscan" / "SKILL.md").is_file()
    assert (workspace / ".claude" / "commands" / "scan.md").is_file()
    hook = workspace / ".claude" / "hooks" / "session-start.sh"
    assert hook.is_file() and os.access(hook, os.X_OK)
    for name in ("AGENTS.md", "CLAUDE.md"):
        text = (workspace / name).read_text(encoding="utf-8")
        assert text.startswith("# Connected ShakerScan instance") and "https://scanner.example.com" in text
        assert "shakerscan api METHOD PATH" in text and "@AGENTS.md" in text if name == "CLAUDE.md" else True
    mcp = json.loads((workspace / ".mcp.json").read_text(encoding="utf-8"))
    assert mcp["mcpServers"]["shakerscan"]["args"] == ["mcp"]
    assert mcp["mcpServers"]["shakerscan"]["command"].endswith("shakerscan")
    opencode = json.loads((workspace / "opencode.json").read_text(encoding="utf-8"))
    assert opencode["mcp"]["shakerscan"]["command"][-1] == "mcp"
    # Re-running refreshes the kit and keeps the workspace usable.
    assert cli.main(["agent", "claude", "--workspace", str(workspace), "--no-launch"]) == 0
    env = cli.agent_environment("https://scanner.example.com", str(tmp_path / "cfg" / "token"), "claude", environ={"HOME": "/h", cli.ENV_TOKEN: "leak"})
    assert env["SHAKERSCAN_API_BASE"] == "https://scanner.example.com"
    assert env["SHAKERSCAN_MANAGED_INSTANCE"] == "1" and env[cli.ENV_TOKEN_FILE].endswith("token")
    assert cli.ENV_TOKEN not in env, "the token stays in its file, never in the agent's environment"


def test_api_and_scan_forward_to_the_runtime_clis_with_the_connection(monkeypatch, tmp_path, clean_environ):
    monkeypatch.setenv(cli.ENV_CONFIG_DIR, str(tmp_path / "cfg"))
    cli.save_profile("https://scanner.example.com", SECRET)
    seen: dict[str, list[str]] = {}

    class FakeApi:
        @staticmethod
        def main(argv):
            seen["api"] = list(argv)
            return 0

    class FakeScan:
        @staticmethod
        def main(argv):
            seen["scan"] = list(argv)
            return 0

    monkeypatch.setattr(cli, "load", lambda name: {"_api_cli": FakeApi, "_scan_cli": FakeScan}[name])
    assert cli.main(["api", "GET", "/findings?limit=2"]) == 0
    assert seen["api"] == ["--api-url", "https://scanner.example.com", "GET", "/findings?limit=2"]
    assert cli.main(["scan", "start", "https://t.example"]) == 0
    assert seen["scan"] == ["--api-url", "https://scanner.example.com", "--ui-url", "https://scanner.example.com", "start", "https://t.example"]
    assert os.environ.get(cli.ENV_TOKEN) == SECRET, "the CLIs read the token from the environment the client set"


def test_status_means_the_connected_instance_when_there_is_no_local_engine(monkeypatch, tmp_path, capsys, clean_environ):
    monkeypatch.setenv(cli.ENV_CONFIG_DIR, str(tmp_path / "cfg"))
    monkeypatch.setenv(cli.ENV_HOME, str(tmp_path / "no-engine"))
    cli.save_profile("https://scanner.example.com", SECRET)
    mcp = load("_mcp")

    class Down:
        def __init__(self, base_url, *, timeout_seconds, api_token):
            pass

        def request_json(self, method, path, payload=None):
            raise mcp.MCPError(-32001, "ShakerScan API is unavailable", "refused")

        def list_tools(self):
            raise mcp.MCPError(-32001, "ShakerScan API is unavailable", "refused")

    monkeypatch.setattr(mcp, "ArsenalClient", Down)
    assert cli.main(["status"]) == 1
    assert "saved profile" in capsys.readouterr().out


def test_a_saved_token_is_never_reused_for_a_different_origin(tmp_path):
    """The saved profile is one connection: its token belongs to its URL.

    Resolving the URL and the credential independently meant a `--url` (or an
    environment URL) pointing somewhere else still inherited the saved instance's
    token, so a hostname mistake or an agent-directed URL change sent an existing
    credential to an unintended service.
    """
    environ = {cli.ENV_CONFIG_DIR: str(tmp_path)}
    cli.save_profile("https://saved.example.com", SECRET, environ=environ)

    # Same origin: the operator connected to it deliberately, so it is inherited.
    assert cli.connection_environment(None, None, None, environ=environ)[cli.ENV_TOKEN] == SECRET
    assert cli.connection_environment(
        "https://saved.example.com", None, None, environ=environ,
    )[cli.ENV_TOKEN] == SECRET
    # The same origin spelled with its default port is the same origin.
    assert cli.connection_environment(
        "https://saved.example.com:443", None, None, environ=environ,
    )[cli.ENV_TOKEN] == SECRET

    # Another origin never inherits it -- by argument, or through the environment.
    assert cli.ENV_TOKEN not in cli.connection_environment(
        "https://other.example.com", None, None, environ=environ,
    )
    assert cli.ENV_TOKEN not in cli.connection_environment(
        None, None, None, environ={**environ, cli.ENV_URL: "https://other.example.com"},
    )
    # A different port, and a downgrade to http, are different origins too.
    assert cli.ENV_TOKEN not in cli.connection_environment(
        "https://saved.example.com:8443", None, None, environ=environ,
    )
    assert cli.ENV_TOKEN not in cli.connection_environment(
        "http://saved.example.com", None, None, environ=environ,
    )

    # An explicitly supplied credential is a deliberate override, and still works.
    other = tmp_path / "other-token"
    other.write_text("a-different-token\n", encoding="utf-8")
    assert cli.connection_environment(
        "https://other.example.com", str(other), None, environ=environ,
    )[cli.ENV_TOKEN] == "a-different-token"


def test_doctor_fails_when_the_health_probe_fails_even_if_the_catalogue_answers(
    monkeypatch, capsys, clean_environ,
):
    """A reachable tool catalogue does not establish engine health.

    `ok` was initialised after the health probe's own except block, so a failed
    health check was printed and then thrown away, and onboarding automation relying
    on the exit status accepted a broken connection.
    """
    mcp = load("_mcp")

    class HealthDown:
        def __init__(self, base_url, *, timeout_seconds, api_token):
            pass

        def request_json(self, method, path, payload=None):
            raise mcp.MCPError(-32001, "ShakerScan API is unavailable", "<health probe failed>")

        def list_tools(self):
            return [{"name": "shakerscan_targets"}]

    monkeypatch.setattr(mcp, "ArsenalClient", HealthDown)
    code = cli.main(["doctor", "--url", "https://scanner.example.com"])
    out = capsys.readouterr().out
    assert "engine:   ShakerScan API is unavailable: <health probe failed>" in out
    assert "mcp:      1 tools" in out
    assert code != 0, "a failed health probe must not exit zero"
