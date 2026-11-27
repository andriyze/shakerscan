"""`shakerscan mcp install|uninstall|status`: the shakerscan entry in each agent's own file.

Unit tests with fixture servers: the probes are replaced by fakes (or a fixture stdio server
script), and every agent file lives under the test's own directory.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "client" / "src"))

from shakerscan import _mcp_install as mi  # noqa: E402
from shakerscan import cli  # noqa: E402

TOKEN = "fixture-secret-token-value"


@pytest.fixture
def home(monkeypatch, tmp_path):
    """A private HOME and agent directories; no ShakerScan connection from the real shell."""
    home = tmp_path / "home"
    home.mkdir()
    for key in ("HOME",):
        monkeypatch.setenv(key, str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("CODEX_HOME", str(home / ".codex"))
    monkeypatch.setenv("COPILOT_HOME", str(home / ".copilot"))
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home))
    monkeypatch.setenv(cli.ENV_CONFIG_DIR, str(tmp_path / "shakerscan-config"))
    monkeypatch.setenv(cli.ENV_HOME, str(tmp_path / "no-engine"))
    for key in (cli.ENV_URL, cli.ENV_TOKEN, cli.ENV_TOKEN_FILE, cli.ENV_ALLOW_REMOTE, "SHAKERSCAN_API_TOKEN"):
        monkeypatch.delenv(key, raising=False)
    return home


@pytest.fixture
def client_exe(tmp_path):
    path = tmp_path / "bin" / "shakerscan"
    path.parent.mkdir()
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(0o755)
    return str(path)


@pytest.fixture
def probes(monkeypatch):
    calls = []
    monkeypatch.setattr(mi, "probe_stdio", lambda server, timeout=0: calls.append(server) or 31)
    monkeypatch.setattr(mi, "probe_http", lambda url, token, timeout=0, post=None: calls.append((url, token)) or 12)
    monkeypatch.setattr(mi, "_opencode_major", lambda: 2)
    return calls


def run(*argv: str) -> int:
    return cli.main(["mcp", *argv])


def files(directory: Path) -> dict[str, str]:
    return {str(p.relative_to(directory)): p.read_bytes().decode("utf-8", "replace")
            for p in sorted(directory.rglob("*")) if p.is_file()}


@pytest.fixture
def project(tmp_path):
    path = tmp_path / "project"
    path.mkdir()
    return path


# --- JSONC editing ------------------------------------------------------------------------------

COMMENTED = textwrap.dedent("""\
    {
      // my settings
      "$schema": "https://opencode.ai/config.json",
      "model": "x/y", /* keep */
      "mcp": {
        "servers": {
          "other": { "type": "remote", "url": "https://example.com/mcp" }, // trailing
        },
      },
      "unknown": {"nested": [1, 2, {"deep": true}]},
    }
    """)


def test_jsonc_set_keeps_comments_trailing_commas_and_unknown_keys():
    new = mi.jsonc_set(COMMENTED, ["mcp", "servers", "shakerscan"], {"type": "local", "command": ["/x", "mcp"]})
    assert "// my settings" in new and "/* keep */" in new and "// trailing" in new
    assert '"other": { "type": "remote", "url": "https://example.com/mcp" }, // trailing\n' in new
    assert mi.jsonc_get(new, ["unknown"]) == {"nested": [1, 2, {"deep": True}]}
    assert mi.jsonc_get(new, ["mcp", "servers", "shakerscan"]) == {"type": "local", "command": ["/x", "mcp"]}
    assert mi.jsonc_get(new, ["mcp", "servers", "other", "url"]) == "https://example.com/mcp"
    # the rest of the text is unchanged byte for byte
    assert new.startswith(COMMENTED.split('"other"')[0])
    assert new.endswith('  "unknown": {"nested": [1, 2, {"deep": true}]},\n}\n')
    # replacing the entry again changes only its value
    again = mi.jsonc_set(new, ["mcp", "servers", "shakerscan"], {"type": "local", "command": ["/y", "mcp"]})
    assert again.replace('"/y"', '"/x"') == new


@pytest.mark.parametrize("text, expected_path", [
    ("", ["a", "b"]),
    ("{}", ["a", "b"]),
    ('{\n  "a": {}\n}\n', ["a", "b"]),
    ('{"a": 1}', ["b"]),
    ('{\n\t"a": 1\n}\n', ["c", "d"]),
    ('{\n  "a": 1 // note\n}\n', ["z"]),
])
def test_jsonc_set_creates_what_is_missing(text, expected_path):
    new = mi.jsonc_set(text, expected_path, {"k": [1]})
    assert mi.jsonc_get(new, expected_path) == {"k": [1]}
    json.loads(mi._workspace._strip_jsonc(new))
    if "// note" in text:
        assert '"a": 1, // note\n' in new


@pytest.mark.parametrize("text", [
    '{"mcpServers": {',
    '{"mcpServers": {"a": 1,, }}',
    '[1, 2]',
    '{"a": 1} trailing',
    '{"a": "unterminated}',
    '{"a": 1 /* open',
    '{"mcpServers": {}, "mcpServers": {}}',
    "{'single': 1}",
])
def test_malformed_documents_are_refused(text):
    with pytest.raises(mi.JsoncError):
        mi.jsonc_set(text, ["mcpServers", "shakerscan"], {})


def test_an_entry_path_through_a_non_object_is_refused():
    with pytest.raises(mi.JsoncError):
        mi.jsonc_set('{"mcpServers": []}', ["mcpServers", "shakerscan"], {})


@pytest.mark.parametrize("text, rest", [
    ('{"s": {"shakerscan": {"a": 1}}}', {}),
    ('{"s": {"x": 1, "shakerscan": {"a": 1}}}', {"x": 1}),
    ('{"s": {"shakerscan": {"a": 1}, "x": 1}}', {"x": 1}),
    ('{\n  "s": {\n    "x": 1, // keep\n    "shakerscan": {"a": 1},\n  },\n}\n', {"x": 1}),
])
def test_jsonc_remove_takes_out_only_the_entry(text, rest):
    new = mi.jsonc_remove(text, ["s", "shakerscan"])
    assert mi.jsonc_get(new, ["s"]) == rest
    assert mi.jsonc_remove(new, ["s", "shakerscan"]) == new
    if "// keep" in text:
        assert "// keep" in new


# --- each agent's format ------------------------------------------------------------------------

STDIO = mi.Server(command="/opt/bin/shakerscan", args=("mcp", "--url", "http://127.0.0.1:8080"))
HTTP = mi.Server(url="https://scanner.example.com/mcp", token_env="MY_TOKEN")


@pytest.mark.parametrize("form, server, expected", [
    ("opencode", STDIO, {"type": "local", "command": ["/opt/bin/shakerscan", "mcp", "--url", "http://127.0.0.1:8080"]}),
    ("opencode", HTTP, {"type": "remote", "url": HTTP.url, "oauth": False,
                        "headers": {"Authorization": "Bearer {env:MY_TOKEN}"}}),
    ("claude", STDIO, {"type": "stdio", "command": "/opt/bin/shakerscan", "args": ["mcp", "--url", "http://127.0.0.1:8080"]}),
    ("claude", HTTP, {"type": "http", "url": HTTP.url, "headers": {"Authorization": "Bearer ${MY_TOKEN}"}}),
    ("cursor", HTTP, {"url": HTTP.url, "headers": {"Authorization": "Bearer ${env:MY_TOKEN}"}}),
    ("copilot", STDIO, {"type": "stdio", "command": "/opt/bin/shakerscan", "args": ["mcp", "--url", "http://127.0.0.1:8080"],
                        "tools": ["*"]}),
    ("copilot", HTTP, {"type": "http", "url": HTTP.url, "headers": {"Authorization": "Bearer ${MY_TOKEN}"}, "tools": ["*"]}),
    ("vscode", HTTP, {"type": "http", "url": HTTP.url, "headers": {"Authorization": "Bearer ${env:MY_TOKEN}"}}),
    ("codex", STDIO, {"command": "/opt/bin/shakerscan", "args": ["mcp", "--url", "http://127.0.0.1:8080"],
                      "startup_timeout_sec": 30, "tool_timeout_sec": 180}),
    ("codex", HTTP, {"url": HTTP.url, "bearer_token_env_var": "MY_TOKEN", "startup_timeout_sec": 30,
                     "tool_timeout_sec": 180}),
])
def test_each_agent_gets_its_own_shape(form, server, expected):
    assert mi.entry(form, server) == expected


@pytest.mark.parametrize("client, relative, path", [
    ("opencode", ".config/opencode/opencode.json", ["mcp", "servers", "shakerscan"]),
    ("cursor", ".cursor/mcp.json", ["mcpServers", "shakerscan"]),
    ("vscode", ".copilot/mcp-config.json", ["mcpServers", "shakerscan"]),
])
def test_user_scope_files(home, client, relative, path):
    target = mi.target(client, None, os.environ)
    assert target.path == home / relative
    plan = mi.plan_install(target, STDIO, major=lambda: 2)
    mi.apply(plan)
    assert mi.jsonc_get((home / relative).read_text(), path)["command"] in (STDIO.command, [STDIO.command, *STDIO.args])
    assert oct((home / relative).stat().st_mode & 0o777) == "0o600"


@pytest.mark.parametrize("client, relative", [
    ("opencode", "opencode.json"), ("claude", ".mcp.json"), ("codex", ".codex/config.toml"),
    ("cursor", ".cursor/mcp.json"), ("vscode", ".vscode/mcp.json"),
])
def test_project_scope_files(tmp_path, client, relative):
    target = mi.target(client, tmp_path, {})
    assert target.path == tmp_path / relative and target.scope == "project"


def test_opencode_jsonc_is_preferred_when_it_exists(tmp_path):
    (tmp_path / "opencode.jsonc").write_text("{}")
    assert mi.target("opencode", tmp_path, {}).path == tmp_path / "opencode.jsonc"


def test_opencode_follows_the_files_own_shape(tmp_path):
    legacy = '{"mcp": {"mine": {"type": "local", "command": ["x"], "enabled": true}}}'
    (tmp_path / "opencode.json").write_text(legacy)
    plan = mi.plan_install(mi.target("opencode", tmp_path, {}), STDIO, major=lambda: 2)
    assert mi.jsonc_get(plan.text, ["mcp", "shakerscan"])["enabled"] is True
    assert mi.jsonc_get(plan.text, ["mcp", "mine"]) == {"type": "local", "command": ["x"], "enabled": True}
    # an empty file follows the installed OpenCode: 1.x keeps servers under mcp directly
    (tmp_path / "opencode.json").write_text("")
    plan = mi.plan_install(mi.target("opencode", tmp_path, {}), STDIO, major=lambda: 1)
    assert mi.jsonc_get(plan.text, ["mcp", "shakerscan", "type"]) == "local"
    plan = mi.plan_install(mi.target("opencode", tmp_path, {}), STDIO, major=lambda: 2)
    assert mi.jsonc_get(plan.text, ["mcp", "servers", "shakerscan", "type"]) == "local"


def test_opencode_moves_an_old_shape_entry_into_the_new_shape(tmp_path):
    (tmp_path / "opencode.json").write_text(
        '{"mcp": {"servers": {"x": {"type": "remote", "url": "https://e.example"}},'
        ' "shakerscan": {"type": "local", "command": ["old"], "enabled": true}}}')
    plan = mi.plan_install(mi.target("opencode", tmp_path, {}), STDIO, major=lambda: 2)
    assert mi.jsonc_get(plan.text, ["mcp", "shakerscan"]) is None
    assert mi.jsonc_get(plan.text, ["mcp", "servers", "x"]) == {"type": "remote", "url": "https://e.example"}


# --- TOML (Codex) -------------------------------------------------------------------------------

CODEX = textwrap.dedent("""\
    # mine
    model = "o3"

    [mcp_servers.shakerscan]
    command = "old"

    [mcp_servers.shakerscan.env]
    A = "b"

    [profiles.fast]
    model = "y"
    """)


def test_codex_table_is_replaced_in_place_and_removed_cleanly():
    entry = mi.entry("codex", STDIO)
    new = mi.toml_set(CODEX, entry)
    assert new.startswith('# mine\nmodel = "o3"\n\n[mcp_servers.shakerscan]\ncommand = "/opt/bin/shakerscan"\n')
    assert "[mcp_servers.shakerscan.env]" not in new and '[profiles.fast]\nmodel = "y"\n' in new
    assert mi.toml_set(new, entry) == new
    if mi._tomllib is not None:
        assert mi._tomllib.loads(new)["mcp_servers"]["shakerscan"] == entry
    removed = mi.toml_remove(new)
    assert "shakerscan" not in removed and removed.endswith('model = "y"\n')


def test_codex_entry_appended_to_a_file_without_one():
    new = mi.toml_set('model = "o3"', mi.entry("codex", STDIO))
    assert new.startswith('model = "o3"\n\n[mcp_servers.shakerscan]\n')


@pytest.mark.parametrize("text", [
    'mcp_servers = { shakerscan = { command = "x" } }\n',
    '[mcp_servers]\nshakerscan = { command = "x" }\n',
])
def test_codex_inline_definitions_are_refused(text):
    with pytest.raises(mi.JsoncError):
        mi.toml_set(text, mi.entry("codex", STDIO))


@pytest.mark.skipif(mi._tomllib is None, reason="needs tomllib (Python 3.11+)")
def test_codex_malformed_toml_is_refused():
    with pytest.raises(mi.JsoncError):
        mi.toml_set("model = \n[broken", mi.entry("codex", STDIO))


# --- hostile files ------------------------------------------------------------------------------


def test_symbolic_and_hard_links_are_refused_and_nothing_written(tmp_path, home, client_exe, probes, capsys):
    project = tmp_path / "p"
    project.mkdir()
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_text("{}")
    (project / ".mcp.json").symlink_to(elsewhere)
    assert run("install", "claude", "--project", str(project), "--url", "http://127.0.0.1:8080",
               "--server-command", client_exe) == 2
    assert "symbolic link" in capsys.readouterr().err
    assert elsewhere.read_text() == "{}" and probes == []
    (project / ".mcp.json").unlink()
    os.link(elsewhere, project / ".mcp.json")
    assert run("install", "claude", "--project", str(project), "--url", "http://127.0.0.1:8080",
               "--server-command", client_exe) == 2
    assert "hard link" in capsys.readouterr().err and elsewhere.read_text() == "{}"


@pytest.mark.parametrize("content", [b'{"mcpServers": {', b"\xff\xfe{}", b"[]"])
def test_unreadable_files_are_refused_with_nothing_written(tmp_path, home, client_exe, probes, capsys, content,
                                                          monkeypatch):
    monkeypatch.setattr(mi, "detected", lambda client, environ: True)  # the same on a machine with no agents
    project = tmp_path / "p"
    (project / ".cursor").mkdir(parents=True)
    (project / ".cursor" / "mcp.json").write_bytes(content)
    before = files(project)
    assert run("install", "all", "--project", str(project), "--url", "http://127.0.0.1:8080",
               "--server-command", client_exe) == 2
    assert "nothing was written" in capsys.readouterr().err.lower()
    assert files(project) == before


def test_a_directory_where_the_file_belongs_is_refused(tmp_path, home, client_exe, probes, capsys):
    (tmp_path / ".mcp.json").mkdir()
    assert run("install", "claude", "--project", str(tmp_path), "--url", "http://127.0.0.1:8080",
               "--server-command", client_exe) == 2
    assert "not a plain file" in capsys.readouterr().err


# --- the command --------------------------------------------------------------------------------


def test_install_every_agent_then_again_changes_nothing(tmp_path, home, client_exe, probes, capsys, monkeypatch):
    monkeypatch.setattr(mi, "detected", lambda client, environ: True)
    project = tmp_path / "p"
    project.mkdir()
    (project / ".mcp.json").write_text('{\n  "other": true,\n  "mcpServers": {\n    "mine": {"command": "x"}\n  }\n}\n')
    assert run("install", "all", "--project", str(project), "--url", "http://127.0.0.1:8080",
               "--server-command", client_exe) == 0
    out = capsys.readouterr().out
    assert "checked:  http://127.0.0.1:8080 lists 31 tools" in out
    assert out.count("check:    ") == 5
    first = files(project)
    assert {".mcp.json", "opencode.json", ".codex/config.toml", ".cursor/mcp.json", ".vscode/mcp.json"} <= set(first)
    assert json.loads(first[".mcp.json"])["mcpServers"]["mine"] == {"command": "x"}
    assert json.loads(first[".mcp.json"])["other"] is True
    assert json.loads(first[".mcp.json"])["mcpServers"]["shakerscan"]["args"] == ["mcp", "--url", "http://127.0.0.1:8080"]
    assert run("install", "all", "--project", str(project), "--url", "http://127.0.0.1:8080",
               "--server-command", client_exe) == 0
    assert capsys.readouterr().out.count("unchanged:") == 5
    assert files(project) == first  # no rewrite, no new backup


def test_dry_run_writes_nothing(project, home, client_exe, probes, capsys):
    assert run("install", "cursor", "--project", str(project), "--url", "http://127.0.0.1:8080",
               "--server-command", client_exe, "--dry-run") == 0
    assert "would write" in capsys.readouterr().out and files(project) == {}


def test_plain_http_on_another_host_needs_lan(project, home, client_exe, probes, capsys):
    assert run("install", "cursor", "--project", str(project), "--url", "http://192.168.1.50:8080",
               "--server-command", client_exe) == 2
    assert "--lan" in capsys.readouterr().err and files(project) == {} and probes == []
    assert run("install", "cursor", "--project", str(project), "--url", "http://192.168.1.50:8080", "--lan",
               "--server-command", client_exe) == 0


def test_no_instance_is_refused_rather_than_registering_the_public_check(project, home, client_exe, probes, capsys):
    assert run("install", "cursor", "--project", str(project), "--server-command", client_exe) == 2
    assert "no ShakerScan instance" in capsys.readouterr().err and files(project) == {}


def test_saved_connection_is_used_without_url_and_without_its_token(tmp_path, home, client_exe, probes, capsys):
    cli.save_profile("https://scanner.example.com", TOKEN)
    assert run("install", "claude", "--project", str(tmp_path), "--server-command", client_exe) == 0
    written = (tmp_path / ".mcp.json").read_text()
    assert json.loads(written)["mcpServers"]["shakerscan"]["args"] == ["mcp"]
    assert TOKEN not in written and TOKEN not in capsys.readouterr().out


def test_a_token_file_is_referenced_by_path_and_needs_https(tmp_path, home, client_exe, probes, capsys):
    token = tmp_path / "token"
    token.write_text(TOKEN)
    assert run("install", "codex", "--project", str(tmp_path), "--url", "http://127.0.0.1:8080",
               "--token-file", str(token), "--server-command", client_exe) == 2
    assert "https" in capsys.readouterr().err
    assert run("install", "codex", "--project", str(tmp_path), "--url", "https://scanner.example.com",
               "--token-file", str(token), "--server-command", client_exe) == 0
    written = (tmp_path / ".codex" / "config.toml").read_text()
    assert str(token) in written and TOKEN not in written


def test_http_endpoint_entry_names_the_variable_never_the_token(tmp_path, home, probes, capsys, monkeypatch):
    monkeypatch.setenv("SHAKERSCAN_API_TOKEN", TOKEN)
    monkeypatch.setattr(mi, "detected", lambda client, environ: True)
    assert run("install", "all", "--project", str(tmp_path), "--http", "https://scanner.example.com/mcp") == 0
    assert probes == [("https://scanner.example.com/mcp", TOKEN)]
    everything = "".join(files(tmp_path).values())
    assert TOKEN not in everything and TOKEN not in capsys.readouterr().out
    assert "Bearer ${SHAKERSCAN_API_TOKEN}" in files(tmp_path)[".mcp.json"]
    assert "Bearer {env:SHAKERSCAN_API_TOKEN}" in files(tmp_path)["opencode.json"]
    assert 'bearer_token_env_var = "SHAKERSCAN_API_TOKEN"' in files(tmp_path)[".codex/config.toml"]


@pytest.mark.parametrize("extra, message", [
    (["--http", "http://scanner.example.com/mcp"], "https"),
    (["--http", "https://user:pw@scanner.example.com/mcp"], "credentials"),
    (["--http", "https://scanner.example.com/mcp", "--token-env", "1BAD"], "not an environment variable"),
    (["--http", "https://scanner.example.com/mcp"], "set SHAKERSCAN_API_TOKEN"),
    (["--token-env", "X"], "goes with --http"),
])
def test_http_refusals(tmp_path, home, probes, capsys, extra, message):
    assert run("install", "cursor", "--project", str(tmp_path), *extra) == 2
    assert message in capsys.readouterr().err and files(tmp_path) == {}


def test_http_token_can_come_from_the_saved_connection_of_that_origin(tmp_path, home, probes):
    cli.save_profile("https://scanner.example.com", TOKEN)
    assert run("install", "cursor", "--project", str(tmp_path), "--http", "https://scanner.example.com/mcp") == 0
    assert probes == [("https://scanner.example.com/mcp", TOKEN)]


def test_uninstall_removes_only_the_entry(tmp_path, home, client_exe, probes, capsys, monkeypatch):
    monkeypatch.setattr(mi, "detected", lambda client, environ: True)
    (tmp_path / "opencode.json").write_text('{"mcp": {"servers": {"x": {"type": "local", "command": ["y"]}}}}')
    run("install", "all", "--project", str(tmp_path), "--url", "http://127.0.0.1:8080", "--server-command", client_exe)
    assert run("uninstall", "all", "--project", str(tmp_path)) == 0
    out = capsys.readouterr().out
    assert out.count("removed from") == 5
    current = {k: v for k, v in files(tmp_path).items() if ".bak" not in k}
    assert "shakerscan" not in "".join(current.values())
    assert json.loads(current["opencode.json"])["mcp"]["servers"] == {"x": {"type": "local", "command": ["y"]}}
    assert run("uninstall", "all", "--project", str(tmp_path)) == 0
    assert capsys.readouterr().out.count("not registered in") == 5


def test_claude_user_scope_goes_through_claude_and_is_idempotent(tmp_path, home, client_exe, probes, monkeypatch, capsys):
    calls = []

    def fake_claude(argv):
        calls.append(list(argv))
        data = json.loads((home / ".claude.json").read_text()) if (home / ".claude.json").exists() else {}
        servers = data.setdefault("mcpServers", {})
        if argv[1] == "remove":
            servers.pop("shakerscan", None)
        else:
            servers["shakerscan"] = {**json.loads(argv[-1]), "env": {}}
        (home / ".claude.json").write_text(json.dumps(data))

    monkeypatch.setattr(mi, "_claude", fake_claude)
    args = ["install", "claude", "--url", "http://127.0.0.1:8080", "--server-command", client_exe]
    assert run(*args) == 0
    assert calls == [["mcp", "add-json", "--scope", "user", "shakerscan",
                      json.dumps({"type": "stdio", "command": client_exe, "args": ["mcp", "--url", "http://127.0.0.1:8080"]})]]
    assert run(*args) == 0 and len(calls) == 1
    assert "unchanged shakerscan (Claude Code user scope)" in capsys.readouterr().out
    assert run("install", "claude", "--url", "http://127.0.0.1:9090", "--server-command", client_exe) == 0
    assert [call[1] for call in calls[1:]] == ["remove", "add-json"]
    assert run("uninstall", "claude") == 0 and calls[-1][1] == "remove"


def test_status_lists_each_agent_and_flags_a_missing_command(tmp_path, home, capsys):
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "mcp.json").write_text(
        json.dumps({"mcpServers": {"shakerscan": {"command": str(tmp_path / "gone"), "args": ["mcp"]}}}))
    (tmp_path / ".mcp.json").write_text("{broken")
    assert run("status", "--project", str(tmp_path)) == 0
    out = capsys.readouterr().out
    assert "command not found" in out and "unreadable" in out and out.count("not registered") >= 7


# --- the probes ---------------------------------------------------------------------------------


def _fixture_server(tmp_path: Path, tools: list[str], error: str = "") -> mi.Server:
    script = tmp_path / "fixture_server.py"
    script.write_text(textwrap.dedent(f"""\
        import json, sys
        for line in sys.stdin:
            message = json.loads(line)
            if "id" not in message:
                continue
            if message["method"] == "initialize":
                result = {{"protocolVersion": "2025-06-18", "capabilities": {{}}, "serverInfo": {{"name": "fixture"}}}}
            elif {error!r}:
                print(json.dumps({{"jsonrpc": "2.0", "id": message["id"], "error": {{"code": -32000, "message": {error!r}}}}}))
                continue
            else:
                result = {{"tools": [{{"name": name}} for name in {tools!r}]}}
            print(json.dumps({{"jsonrpc": "2.0", "id": message["id"], "result": result}}), flush=True)
        """))
    return mi.Server(command=sys.executable, args=(str(script),))


def test_probe_stdio_counts_the_tools(tmp_path):
    assert mi.probe_stdio(_fixture_server(tmp_path, ["shakerscan_targets", "shakerscan_hunt_start"])) == 2


def test_probe_stdio_refuses_the_public_check_only_and_errors(tmp_path):
    with pytest.raises(mi.InstallError, match="public check"):
        mi.probe_stdio(_fixture_server(tmp_path, ["shakerscan_public_check"]))
    with pytest.raises(mi.InstallError, match="API is unavailable"):
        mi.probe_stdio(_fixture_server(tmp_path, [], error="ShakerScan API is unavailable"))
    with pytest.raises(mi.InstallError, match="cannot start"):
        mi.probe_stdio(mi.Server(command=str(tmp_path / "missing"), args=()))


def test_probe_stdio_runs_without_this_shells_connection(tmp_path, monkeypatch):
    monkeypatch.setenv(cli.ENV_TOKEN, TOKEN)
    script = tmp_path / "env_server.py"
    script.write_text(textwrap.dedent("""\
        import json, os, sys
        for line in sys.stdin:
            m = json.loads(line)
            if "id" in m:
                tools = [] if os.environ.get("SHAKERSCAN_API_TOKEN") else [{"name": "a"}]
                print(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": {"tools": tools}}), flush=True)
        """))
    assert mi.probe_stdio(mi.Server(command=sys.executable, args=(str(script),))) == 1


def test_probe_http_speaks_json_and_event_streams_with_the_session():
    seen = []

    def post(url, body, headers, timeout):
        message = json.loads(body)
        seen.append((message.get("method"), headers.get("Mcp-Session-Id"), headers["Authorization"]))
        if message["method"] == "initialize":
            return 200, {"content-type": "application/json", "mcp-session-id": "s1"}, json.dumps(
                {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-06-18"}}).encode()
        if "id" not in message:
            return 202, {}, b""
        page = {} if message["params"].get("cursor") else {"nextCursor": "c2"}
        event = json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": {"tools": [{"name": "a"}, {"name": "b"}], **page}})
        return 200, {"content-type": "text/event-stream"}, f"event: message\ndata: {event}\n\n".encode()

    assert mi.probe_http("https://scanner.example.com/mcp", TOKEN, post=post) == 4
    assert [item[0] for item in seen] == ["initialize", "notifications/initialized", "tools/list", "tools/list"]
    assert all(item[1] == "s1" for item in seen[1:]) and all(item[2] == f"Bearer {TOKEN}" for item in seen)


@pytest.mark.parametrize("status, match", [(401, "refused the token"), (302, "redirects"), (500, "HTTP 500")])
def test_probe_http_refusals(status, match):
    with pytest.raises(mi.InstallError, match=match):
        mi.probe_http("https://scanner.example.com/mcp", TOKEN,
                      post=lambda *a: (status, {"location": "https://elsewhere.example"}, b""))


def test_server_command_is_this_clients_path_without_resolving_links(tmp_path, monkeypatch):
    real = tmp_path / "Cellar" / "1.0" / "shakerscan"
    real.parent.mkdir(parents=True)
    real.write_text("#!/bin/sh\n")
    real.chmod(0o755)
    link = tmp_path / "bin" / "shakerscan"
    link.parent.mkdir()
    link.symlink_to(real)
    monkeypatch.setattr(sys, "argv", [str(link), "mcp", "install"])
    assert mi.server_command(None) == str(link)
    with pytest.raises(mi.InstallError):
        mi.server_command("relative/shakerscan")


def test_the_subcommands_are_dispatched_and_plain_mcp_still_runs_the_server(monkeypatch):
    seen = []
    monkeypatch.setattr(cli, "cmd_mcp", lambda args: seen.append("server") or 0)
    monkeypatch.setitem(cli.COMMANDS, "mcp", cli.cmd_mcp)
    assert cli.main(["mcp"]) == 0 and seen == ["server"]
    with pytest.raises(SystemExit):
        cli.main(["mcp", "install", "nope"])
    assert isinstance(mi.build_parser().parse_args(["status"]), argparse.Namespace)


# --- a deployment's discovery document and its HTTP entry ---------------------------------------

DISCOVERY = {
    "format": "shakerscan-discovery/v1",
    "api_url": "https://scanner.example.com",
    "mcp_servers": [{"url": "/mcp-endpoint", "transport": "streamable-http", "auth": "bearer",
                     "tools": ["shakerscan_targets", "shakerscan_findings"]}],
}


@pytest.fixture
def fake_deployment():
    """A local fixture HTTP server: the discovery document and a JSON-only MCP endpoint (no event
    stream, no session) that requires the bearer token."""
    import http.server
    import threading

    seen = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):  # quiet
            pass

        def _send(self, status, body=b"", kind="application/json"):
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            seen.append(("GET", self.path, self.headers.get("Authorization")))
            if self.path == "/.well-known/shakerscan":
                self._send(200, json.dumps(DISCOVERY).encode())
            else:
                self._send(404)

        def do_POST(self):
            message = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append(("POST", message.get("method"), self.headers.get("Mcp-Session-Id")))
            if self.path != "/mcp-endpoint":
                return self._send(404)
            if self.headers.get("Authorization") != f"Bearer {TOKEN}":
                return self._send(401)
            if "id" not in message:
                return self._send(202)
            if message["method"] == "initialize":
                assert message["params"]["protocolVersion"] in {"2025-11-25", "2025-06-18", "2025-03-26"}
                result = {"protocolVersion": message["params"]["protocolVersion"], "capabilities": {}}
            else:
                result = {"tools": [{"name": name} for name in DISCOVERY["mcp_servers"][0]["tools"]]}
            self._send(200, json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}).encode())

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}", seen
    server.shutdown()


def test_discovery_names_the_endpoint_and_the_endpoint_answers_json(fake_deployment):
    base, seen = fake_deployment
    endpoint = mi.discover_endpoint(base)
    assert endpoint == base + "/mcp-endpoint"
    assert seen[0] == ("GET", "/.well-known/shakerscan", None)  # no credentials on discovery
    assert mi.probe_http(endpoint, TOKEN) == 2
    with pytest.raises(mi.InstallError, match="refused the token"):
        mi.probe_http(endpoint, "wrong")


@pytest.mark.parametrize("document, match", [
    ({"format": "other/v1", "mcp_servers": []}, "not a shakerscan-discovery/v1"),
    ({**DISCOVERY, "mcp_servers": []}, "no MCP server"),
    ({**DISCOVERY, "mcp_servers": [{"url": "https://elsewhere.example/mcp"}]}, "another origin"),
    ({**DISCOVERY, "mcp_servers": [{"url": "/m", "transport": "sse", "auth": "bearer"}]}, "not streamable HTTP"),
    ({**DISCOVERY, "mcp_servers": [{"url": "/m", "auth": {"type": "basic"}}]}, "not streamable HTTP"),
    ({**DISCOVERY, "mcp_servers": [{"url": "/m", "auth": {"token": "x"}}]}, "not streamable HTTP"),
    ({**DISCOVERY, "mcp_servers": [{"url": "/m", "auth": ["bearer"]}]}, "not streamable HTTP"),
])
def test_discovery_refusals(document, match):
    get = lambda url, headers, timeout: (200, {}, json.dumps(document).encode())  # noqa: E731
    with pytest.raises(mi.InstallError, match=match):
        mi.discover_endpoint("https://scanner.example.com", get=get)
    with pytest.raises(mi.InstallError, match="HTTP 404"):
        mi.discover_endpoint("https://scanner.example.com", get=lambda *a: (404, {}, b""))


def test_discovery_accepts_the_enterprise_gateways_document():
    """The shape an Enterprise gateway publishes: `schema` rather than `format`, and `auth` as an
    object naming the scheme and which token it takes."""
    document = {
        "schema": "shakerscan-discovery/v1",
        "mcp_servers": [{"name": "shakerscan-enterprise", "url": "/_enterprise/mcp",
                         "transport": "streamable-http",
                         "auth": {"type": "bearer", "token": "service-token"}}],
    }
    get = lambda url, headers, timeout: (200, {}, json.dumps(document).encode())  # noqa: E731
    assert mi.discover_endpoint("https://scanner.example.com", get=get) == "https://scanner.example.com/_enterprise/mcp"


def _deployment_on_https(monkeypatch, base):
    """Point https://scanner.example.com at the local fixture server."""
    real_get, real_post = mi.http_get, mi.http_post
    swap = lambda url: url.replace("https://scanner.example.com", base)  # noqa: E731
    monkeypatch.setattr(mi, "http_get", lambda url, headers, timeout: real_get(swap(url), headers, timeout))
    monkeypatch.setattr(mi, "http_post", lambda url, body, headers, timeout: real_post(swap(url), body, headers, timeout))


def test_install_from_the_deployment_address(project, home, client_exe, fake_deployment, monkeypatch, capsys):
    base, _seen = fake_deployment
    _deployment_on_https(monkeypatch, base)
    monkeypatch.setenv("SHAKERSCAN_API_TOKEN", TOKEN)
    monkeypatch.setattr(mi, "_opencode_major", lambda: 2)
    monkeypatch.setattr(mi, "detected", lambda client, environ: True)
    # a local stdio entry is already there: the HTTP entry sits beside it as shakerscan-enterprise
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"shakerscan": {"command": client_exe, "args": ["mcp"]}}}))
    assert run("install", "all", "--project", str(project), "--http", "https://scanner.example.com") == 0
    out = capsys.readouterr().out
    assert "https://scanner.example.com/mcp-endpoint lists 2 tools" in out
    written = files(project)
    claude = json.loads(written[".mcp.json"])["mcpServers"]
    assert claude["shakerscan"] == {"command": client_exe, "args": ["mcp"]}
    assert claude["shakerscan-enterprise"]["url"] == "https://scanner.example.com/mcp-endpoint"
    opencode = json.loads(written["opencode.json"])["mcp"]["servers"]["shakerscan"]
    assert opencode["oauth"] is False and opencode["type"] == "remote"
    assert TOKEN not in "".join(written.values()) and TOKEN not in out
    # again: nothing changes; uninstall removes both names and nothing else
    before = {k: v for k, v in files(project).items() if ".bak" not in k}
    assert run("install", "all", "--project", str(project), "--http", "https://scanner.example.com") == 0
    assert {k: v for k, v in files(project).items() if ".bak" not in k} == before
    assert run("uninstall", "claude", "--project", str(project)) == 0
    assert json.loads((project / ".mcp.json").read_text()) == {"mcpServers": {}}


def test_http_entry_keeps_the_shakerscan_name_without_a_local_entry_and_its_remote_name_after():
    remote = mi.Server(url="https://scanner.example.com/mcp-endpoint", token_env="T")
    assert mi.entry_name(remote, lambda name: None) == "shakerscan"
    assert mi.entry_name(remote, lambda name: {"url": "https://x"} if name == "shakerscan" else None) == "shakerscan"
    assert mi.entry_name(remote, lambda name: {"command": "/bin/x"} if name == "shakerscan" else None) == \
        "shakerscan-enterprise"
    assert mi.entry_name(remote, lambda name: {} if name == "shakerscan-enterprise" else None) == "shakerscan-enterprise"
    assert mi.entry_name(STDIO, lambda name: {"command": "/bin/x"}) == "shakerscan"


def test_codex_table_takes_the_remote_name_beside_a_local_one(tmp_path):
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex" / "config.toml").write_text('[mcp_servers.shakerscan]\ncommand = "/x"\nargs = ["mcp"]\n')
    plan = mi.plan_install(mi.target("codex", tmp_path, {}), HTTP)
    assert plan.name == "shakerscan-enterprise"
    assert '[mcp_servers.shakerscan]\ncommand = "/x"' in plan.text
    assert '[mcp_servers.shakerscan-enterprise]\nurl = "https://scanner.example.com/mcp"' in plan.text
    removed = mi.plan_uninstall(mi.Target("codex", "project", tmp_path / ".codex" / "config.toml", "codex"))
    assert removed.text is not None and "mcp_servers.shakerscan]" not in removed.text
