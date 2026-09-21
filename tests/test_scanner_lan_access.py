"""LAN startup and client-only control; no Docker or external traffic in these tests."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "scanner.sh"
sys.path.insert(0, str(ROOT / "client" / "src"))
from shakerscan import cli  # noqa: E402
from shakerscan._vendored import load  # noqa: E402


def _functions() -> str:
    return SCANNER.read_text(encoding="utf-8").rsplit("# Parse arguments", 1)[0]


def _env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if not k.startswith("SHAKERSCAN_")}


def _run(code: str, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-c", _functions() + "\nSCRIPT_DIR=" + shlex.quote(str(tmp_path)) + "\n" + code],
        cwd=ROOT, env=_env(), text=True, capture_output=True, timeout=10,
    )


def test_linux_discovery_excludes_non_lan_and_uses_default_interface(tmp_path):
    result = _run(r'''
command_exists() { [ "$1" = ip ]; }
ip() {
    if [ "$1" = -o ]; then
        cat <<'EOF'
1: lo inet 127.0.0.1/8 scope host lo
2: eth0 inet 192.168.1.50/24 scope global eth0
3: enp0s2 inet 10.20.0.5/24 scope global enp0s2
4: docker0 inet 172.17.0.1/16 scope global docker0
5: br-deadbeef inet 172.18.0.1/16 scope global br-deadbeef
6: tailscale0 inet 100.64.0.2/32 scope global tailscale0
7: wg0 inet 10.0.0.5/24 scope global wg0
8: tun0 inet 10.9.0.1/24 scope global tun0
9: public0 inet 203.0.113.4/24 scope global public0
10: bad0 inet 10.400.0.1/24 scope global bad0
EOF
    else
        printf 'default via 192.168.1.1 dev eth0\n'
    fi
}
lan_ipv4_candidates
select_lan_ipv4
select_lan_ipv4 10.20.0.5
''', tmp_path)
    assert result.returncode == 0, result.stderr
    assert set(result.stdout.splitlines()[:2]) == {"eth0 192.168.1.50", "enp0s2 10.20.0.5"}
    assert result.stdout.splitlines()[2:] == ["192.168.1.50", "10.20.0.5"]


def test_macos_discovery_excludes_down_and_tunnel_interfaces(tmp_path):
    result = _run(r'''
command_exists() { [ "$1" = ifconfig ] || [ "$1" = route ]; }
ifconfig() {
    cat <<'EOF'
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
        inet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        inet 192.168.1.10 netmask 0xffffff00
utun2: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
        inet 10.10.1.2 netmask 0xffffffff
en1: flags=8862<BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        inet 10.5.1.1 netmask 0xffffff00
EOF
}
select_lan_ipv4
''', tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "192.168.1.10"


@pytest.mark.parametrize("address", ["0.0.0.0", "127.0.0.1", "203.0.113.3", "100.64.0.2", "192.168.1.99"])
def test_lan_rejects_unassigned_or_non_lan_override(tmp_path, address):
    result = _run("lan_ipv4_candidates() { echo 'eth0 192.168.1.50'; }\n"
                  f"select_lan_ipv4 {shlex.quote(address)}\n", tmp_path)
    assert result.returncode != 0
    assert "assigned RFC1918" in result.stderr


@pytest.mark.parametrize("candidates", ["", "eth0 192.168.1.50\nen1 10.10.0.1"])
def test_lan_no_address_or_ambiguity_fails_closed(tmp_path, candidates):
    result = _run("lan_ipv4_candidates() { printf '%s\\n' " + shlex.quote(candidates) + "; }\n"
                  "lan_default_interface() { :; }\nselect_lan_ipv4\n", tmp_path)
    assert result.returncode != 0
    assert "--bind-host" in result.stderr
    assert not (tmp_path / ".env").exists()


def test_lan_ignores_cached_and_tailscale_addresses_and_persists_only_ui_api(tmp_path):
    result = _run(r'''
LAN_ACCESS=1
REMOTE_ACCESS=0
SHAKERSCAN_BIND_HOST=100.64.0.2
SHAKERSCAN_PUBLIC_HOST=old.example.com
SHAKERSCAN_PUBLIC_API_URL=https://old.example.com
SHAKERSCAN_TRUSTED_REMOTE_TRANSPORT=tailscale
SHAKERSCAN_API_PORT=8181
SHAKERSCAN_UI_PORT=3333
SHAKERSCAN_DATA_BIND_HOST=127.0.0.1
lan_ipv4_candidates() { echo 'eth0 192.168.1.50'; }
first_tailscale_ipv4() { echo 100.64.0.2; }
configure_access_mode
persist_remote_access_env
printf 'BOUND=%s\nPUBLIC=%s\nAPI=%s\nDATA=%s\nTRUST=%s\n' "$SHAKERSCAN_BIND_HOST" "$SHAKERSCAN_PUBLIC_HOST" "$SHAKERSCAN_PUBLIC_API_URL" "$SHAKERSCAN_DATA_BIND_HOST" "${SHAKERSCAN_TRUSTED_REMOTE_TRANSPORT:-none}"
print_lan_client_help
''', tmp_path)
    assert result.returncode == 0, result.stderr
    for expected in ("BOUND=192.168.1.50", "PUBLIC=192.168.1.50", "API=http://192.168.1.50:8181", "DATA=127.0.0.1", "TRUST=none"):
        assert expected in result.stdout
    assert "shakerscan api --url http://192.168.1.50:8181 GET /health" in result.stdout
    assert "shakerscan mcp --url http://192.168.1.50:8181" in result.stdout
    assert "http://192.168.1.50:3333" in result.stdout
    saved = (tmp_path / ".env").read_text()
    assert "SHAKERSCAN_BIND_HOST=192.168.1.50" in saved
    assert "SHAKERSCAN_DATA_BIND_HOST" not in saved
    assert (tmp_path / ".env").stat().st_mode & 0o777 == 0o600


def test_fresh_default_stays_loopback_and_explicit_reset_is_persistent(tmp_path):
    result = _run(r'''
first_tailscale_ipv4() { echo 100.64.0.2; }
configure_access_mode
printf 'DEFAULT=%s\n' "$SHAKERSCAN_BIND_HOST"
SHAKERSCAN_BIND_HOST=127.0.0.1
SHAKERSCAN_PUBLIC_HOST=localhost
SHAKERSCAN_BIND_HOST_EXPLICIT=1
persist_remote_access_env
''', tmp_path)
    assert result.returncode == 0, result.stderr
    assert "DEFAULT=127.0.0.1" in result.stdout
    assert "SHAKERSCAN_BIND_HOST=127.0.0.1" in (tmp_path / ".env").read_text()


def _entrypoint(tmp_path: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    before, after = SCANNER.read_text(encoding="utf-8").rsplit("# Parse arguments", 1)
    overrides = r'''
lan_ipv4_candidates() { echo 'eth0 192.168.1.50'; }
first_tailscale_ipv4() { echo 100.64.0.2; }
configure_runtime_mode() { :; }
ensure_command_dependencies() { :; }
print_banner() { :; }
start_services() { persist_remote_access_env; echo STARTED; }
restart_services() { persist_remote_access_env; echo RESTARTED; }
'''
    script = tmp_path / "scanner.sh"
    script.write_text(before + overrides + "\n# Parse arguments" + after, encoding="utf-8")
    return subprocess.run(["bash", str(script), *args], env=_env(), capture_output=True, text=True, timeout=10)


@pytest.mark.parametrize("command", ["start", "restart"])
def test_lan_entrypoint_and_idempotent_help(tmp_path, command):
    result = _entrypoint(tmp_path, [command, "--lan", "--help"])
    assert result.returncode == 0, result.stderr
    assert "--lan" in result.stdout
    assert not (tmp_path / ".env").exists()
    result = _entrypoint(tmp_path, [command, "--lan"])
    assert result.returncode == 0, result.stderr
    assert "shakerscan mcp --url http://192.168.1.50:8080" in result.stdout
    assert "SHAKERSCAN_BIND_HOST=192.168.1.50" in (tmp_path / ".env").read_text()


@pytest.mark.parametrize("args", [["start", "--lan", "--remote"], ["start", "--tailscale", "--lan"], ["stop", "--lan"]])
def test_incompatible_lan_flags_fail_before_mutation(tmp_path, args):
    result = _entrypoint(tmp_path, args)
    assert result.returncode != 0
    assert not (tmp_path / ".env").exists()
    assert "STARTED" not in result.stdout


@pytest.fixture
def clean_client(monkeypatch, tmp_path):
    for key in list(os.environ):
        if key.startswith("SHAKERSCAN_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv(cli.ENV_HOME, str(tmp_path / "no-engine"))
    monkeypatch.setenv(cli.ENV_CONFIG_DIR, str(tmp_path / "config"))
    monkeypatch.setattr(cli, "public_request_json", lambda *a, **kw: pytest.fail("public request in LAN mode"))


@pytest.mark.parametrize("use_environment", [False, True])
def test_client_only_api_and_mcp_select_lan_and_never_public(monkeypatch, clean_client, use_environment):
    url = "http://192.168.1.50:8080"
    opts = [] if use_environment else ["--url", url]
    if use_environment:
        monkeypatch.setenv(cli.ENV_URL, url)
        monkeypatch.setenv(cli.ENV_ALLOW_REMOTE, "true")
    real_api = load("_api_cli")
    requests = []
    def fake_call(request, **kwargs):
        requests.append(request)
        return 200, '{"status":"ok"}'
    monkeypatch.setattr(real_api, "call", fake_call)
    assert cli.main(["api", *opts, "GET", "/health"]) == 0
    assert cli.main(["api", *opts, "POST", "/scans", '{"target":"http://lab.example.test"}']) == 0
    assert [r.full_url for r in requests] == [url + "/health", url + "/scans"]
    assert all(r.get_header("Authorization") is None for r in requests)
    assert json.loads(requests[1].data)["target"] == "http://lab.example.test"
    real_mcp = load("_mcp")
    def fake_main():
        assert os.environ[cli.ENV_URL] == url
        assert os.environ[cli.ENV_ALLOW_REMOTE] == "true"
        assert not os.environ.get(cli.ENV_TOKEN)
        return 1
    monkeypatch.setattr(real_mcp, "main", fake_main)
    assert cli.main(["mcp", *opts]) == 1
    assert os.environ[cli.ENV_URL] == url
