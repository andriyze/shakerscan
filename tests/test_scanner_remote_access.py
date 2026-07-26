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
