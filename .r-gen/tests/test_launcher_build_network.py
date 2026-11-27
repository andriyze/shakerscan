"""The macOS host-network build default must not break builds on a Compose that refuses it.

Compose 5.6 builds through bake, which rejects `build.network: host` with "additional
privileges requested: pass --allow=network.host" and has no flag to grant it, so every
`scanner.sh rebuild` on macOS failed in the scanner_runtime phase.
"""

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run_ensure(tmp_path: Path, *, host_builds: bool, auto_host: int, network: str) -> tuple[subprocess.CompletedProcess, str]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    calls = tmp_path / "calls"
    host_rc = 0 if host_builds else 1
    (fake_bin / "docker").write_text(
        "#!/bin/sh\n"
        f"echo \"$*\" >> '{calls}'\n"
        "[ \"$1\" = compose ] || exit 0\n"
        "for a in \"$@\"; do case $a in -f) next=1;; *) [ -n \"$next\" ] && file=$a; next=;; esac; done\n"
        f"grep -q 'network: host' \"$file\" && exit {host_rc}\n"
        "exit 0\n"
    )
    (fake_bin / "docker").chmod(0o755)
    script = (
        'YELLOW=""; NC=""; DOCKER_COMPOSE_CMD=(docker compose); '
        f"BUILD_NETWORK_AUTO_HOST={auto_host}; export SHAKERSCAN_BUILD_NETWORK={network}; "
        f'source <(sed -n "/^docker_cli()/,/^}}$/p" {ROOT}/scanner.sh); '
        f'source <(sed -n "/^resolve_compose_command()/,/^}}$/p" {ROOT}/scanner.sh); '
        f'source <(sed -n "/^ensure_build_network_supported()/,/^}}$/p" {ROOT}/scanner.sh); '
        'ensure_build_network_supported; echo "network=$SHAKERSCAN_BUILD_NETWORK"'
    )
    result = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, cwd=ROOT,
        env={**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}"},
    )
    return result, calls.read_text() if calls.exists() else ""


def test_auto_host_falls_back_to_default_when_compose_refuses_it(tmp_path):
    result, calls = _run_ensure(tmp_path, host_builds=False, auto_host=1, network="host")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().endswith("network=default")
    assert "cannot build with host networking" in result.stdout
    assert "image rm shakerscan-build-network-probe:local" in calls


def test_auto_host_is_kept_when_compose_can_build_with_it(tmp_path):
    result, _ = _run_ensure(tmp_path, host_builds=True, auto_host=1, network="host")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "network=host"


def test_an_operator_chosen_host_network_is_never_changed_or_probed(tmp_path):
    result, calls = _run_ensure(tmp_path, host_builds=False, auto_host=0, network="host")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "network=host"
    assert calls == ""


def test_every_local_build_entry_point_checks_the_build_network():
    script = (ROOT / "scanner.sh").read_text()
    for entry in ("build_images() {", "rebuild_images() {"):
        body = script[script.index(entry):]
        body = body[: body.index("\n}\n")]
        assert body.index("set_build_env") < body.index("ensure_build_network_supported")


def test_start_from_a_checkout_checks_the_build_network_before_building():
    # `start` in local-build mode calls build_local_images directly (no build or rebuild), which is
    # the first run on a fresh macOS checkout.
    script = (ROOT / "scanner.sh").read_text()
    body = script[script.index("build_local_images() {"):]
    body = body[: body.index("\n}\n")]
    assert body.index("ensure_build_network_supported") < body.index("build_local_scanner_family")
