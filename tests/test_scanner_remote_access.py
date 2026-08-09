import os
import subprocess
from pathlib import Path


SCANNER_SH = Path(__file__).resolve().parents[1] / "scanner.sh"


def _run_access_configuration(public_host: str) -> list[str]:
    functions = SCANNER_SH.read_text(encoding="utf-8").rsplit("# Parse arguments", 1)[0]
    command = functions + f"""
REMOTE_ACCESS=1
SHAKERSCAN_BIND_HOST=127.0.0.1
SHAKERSCAN_PUBLIC_HOST={public_host}
first_tailscale_ipv4() {{ echo 100.100.100.100; }}
configure_access_mode >/dev/null
printf '%s\n' "$SHAKERSCAN_BIND_HOST" "$SHAKERSCAN_PUBLIC_HOST" "$(api_probe_url)"
"""
    result = subprocess.run(
        ["bash", "-c", command],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.splitlines()


def test_remote_mode_replaces_stale_local_public_host_and_probes_the_bind():
    assert _run_access_configuration("localhost") == [
        "100.100.100.100",
        "100.100.100.100",
        "http://100.100.100.100:8080",
    ]


def test_remote_mode_preserves_real_public_dns_but_probes_the_bind():
    assert _run_access_configuration("scanner.example.test") == [
        "100.100.100.100",
        "scanner.example.test",
        "http://100.100.100.100:8080",
    ]


def test_agent_launcher_exports_remote_api_and_browser_urls(tmp_path):
    functions = SCANNER_SH.read_text(encoding="utf-8").rsplit("# Parse arguments", 1)[0]
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    capture = tmp_path / "agent-env"
    fake_agent = fake_bin / "codex"
    fake_agent.write_text(
        '#!/bin/sh\nprintf "%s\\n%s\\n" "$SHAKERSCAN_API_BASE" "$SHAKERSCAN_UI_BASE" > "$CAPTURE"\n',
        encoding="utf-8",
    )
    fake_agent.chmod(0o755)
    command = functions + """
SHAKERSCAN_BIND_HOST=100.100.100.100
SHAKERSCAN_PUBLIC_HOST=scanner.example.test
start_agent codex
"""
    env = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "CAPTURE": str(capture),
    }
    result = subprocess.run(
        ["bash", "-c", command],
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert capture.read_text(encoding="utf-8").splitlines() == [
        "http://100.100.100.100:8080",
        "http://scanner.example.test:3000",
    ]


def test_agent_launcher_has_non_mutating_help():
    functions = SCANNER_SH.read_text(encoding="utf-8").rsplit("# Parse arguments", 1)[0]
    result = subprocess.run(
        ["bash", "-c", functions + "\nstart_agent --help\n"],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    assert "Usage:" in result.stdout
    assert "codex|claude|opencode" in result.stdout


def test_manual_agent_guidance_exports_remote_urls():
    functions = SCANNER_SH.read_text(encoding="utf-8").rsplit("# Parse arguments", 1)[0]
    command = functions + """
SHAKERSCAN_BIND_HOST=100.100.100.100
SHAKERSCAN_PUBLIC_HOST=scanner.example.test
show_env_help
"""
    result = subprocess.run(
        ["bash", "-c", command],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    assert 'export SHAKERSCAN_API_BASE="http://100.100.100.100:8080"' in result.stdout
    assert 'export SHAKERSCAN_UI_BASE="http://scanner.example.test:3000"' in result.stdout


def test_session_hook_derives_remote_api_from_runtime_env(tmp_path):
    runtime = tmp_path / "runtime"
    hook_dir = runtime / ".claude" / "hooks"
    hook_dir.mkdir(parents=True)
    hook = hook_dir / "session-start.sh"
    hook.write_text(
        (SCANNER_SH.parent / ".claude/hooks/session-start.sh").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    hook.chmod(0o755)
    (runtime / ".env").write_text(
        "SHAKERSCAN_BIND_HOST=100.100.100.100\nSHAKERSCAN_API_PORT=8181\n",
        encoding="utf-8",
    )
    fake_bin = tmp_path / "hook-bin"
    fake_bin.mkdir()
    requests = tmp_path / "requests"
    fake_curl = fake_bin / "curl"
    fake_curl.write_text(
        """#!/bin/sh
printf '%s\n' "$*" >> "$REQUESTS"
case "$*" in
  *queue/stats*) printf '%s\n' '{"running":2,"pending":3}' ;;
esac
""",
        encoding="utf-8",
    )
    fake_curl.chmod(0o755)
    fake_docker = fake_bin / "docker"
    fake_docker.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_docker.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "REQUESTS": str(requests),
    }
    result = subprocess.run(
        ["bash", str(hook)],
        cwd=runtime,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "SCANNER_STATUS=running" in result.stdout
    assert "SCANNER_RUNNING=2" in result.stdout
    assert "SCANNER_PENDING=3" in result.stdout
    assert "http://100.100.100.100:8181/health" in requests.read_text(encoding="utf-8")
