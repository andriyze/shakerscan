"""The `shakerscan` client package (client/): one command name, two install channels."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
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
from shakerscan._vendored import load  # noqa: E402

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


def test_the_build_vendors_the_runtime_scripts_for_wheel_and_sdist(tmp_path):
    scripts = ROOT / "scripts"
    assert hatch_build.plan_force_include("wheel", CLIENT) == {
        str(scripts / "shakerscan_mcp.py"): "shakerscan/_mcp.py",
        str(scripts / "v2_cli.py"): "shakerscan/_v2_cli.py",
    }
    assert hatch_build.plan_force_include("sdist", CLIENT) == {
        str(scripts / "shakerscan_mcp.py"): "src/shakerscan/_mcp.py",
        str(scripts / "v2_cli.py"): "src/shakerscan/_v2_cli.py",
    }
    # An unpacked sdist has no repository beside it but carries the copies: nothing to map.
    unpacked = tmp_path / "shakerscan-0.0.0" / "src" / "shakerscan"
    unpacked.mkdir(parents=True)
    for module in ("_mcp.py", "_v2_cli.py"):
        (unpacked / module).write_text("# vendored\n", encoding="utf-8")
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
    assert cli.connection_environment(None, None, None, environ={cli.ENV_URL: "https://scanner.example.com"}) == {}
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
    assert "client:   0.1.0" in result.stdout
    assert result.stdout.rstrip().endswith("launcher tag=2.3.4 args=doctor")
    # A remote instance is a connection check only; no launcher involved.
    remote = _run(
        ["doctor", "--url", "https://127.0.0.2:9", "--timeout", "1"], env={cli.ENV_HOME: str(tmp_path / "engine")}, cwd=tmp_path
    )
    assert "launcher" not in remote.stdout
