"""Freeze which Python entrypoints may create child processes in shipped images."""

from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "api"

API_PROCESS_SUBPROCESS_MODULES = {
    "api/asm_inventory.py",
    "api/command_arsenal.py",
    "api/model_intake/router.py",
}
NON_API_ENTRYPOINT_SUBPROCESS_MODULES = {
    "api/gungnir_worker.py",
    "api/model_intake_firecracker_runner.py",
    "api/worker.py",
}


def _subprocess_modules() -> set[str]:
    found: set[str] = set()
    for path in API.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            owner = node.func.value
            direct_subprocess = (
                isinstance(owner, ast.Name)
                and owner.id == "subprocess"
                and node.func.attr in {"run", "Popen"}
            )
            async_subprocess = (
                isinstance(owner, ast.Name)
                and owner.id == "asyncio"
                and node.func.attr == "create_subprocess_exec"
            )
            if direct_subprocess or async_subprocess:
                found.add(path.relative_to(ROOT).as_posix())
    return found


def test_subprocess_entrypoints_match_the_reviewed_image_boundary():
    assert _subprocess_modules() == (
        API_PROCESS_SUBPROCESS_MODULES | NON_API_ENTRYPOINT_SUBPROCESS_MODULES
    )


def test_api_process_has_no_unreviewed_direct_go_scanner_execution():
    forbidden = {
        "httpx", "katana", "subfinder", "ffuf", "nuclei", "dalfox", "naabu",
    }
    direct_exec_sources = {
        path: (ROOT / path).read_text(encoding="utf-8")
        for path in API_PROCESS_SUBPROCESS_MODULES
    }
    # Command Arsenal may resolve these paths for an explicit version probe, but
    # the API must not gain a target-execution argv for a Go scanner.
    arsenal = direct_exec_sources.pop("api/command_arsenal.py")
    assert "_probe_version" in arsenal
    for source in direct_exec_sources.values():
        for binary in forbidden:
            assert f'"/opt/tools/{binary}"' not in source


def test_api_process_execution_reasons_remain_narrow_and_named():
    asm = (API / "asm_inventory.py").read_text(encoding="utf-8")
    arsenal = (API / "command_arsenal.py").read_text(encoding="utf-8")
    model_intake = (API / "model_intake" / "router.py").read_text(encoding="utf-8")

    assert '"curl", "-sS"' in asm
    assert "version probe" in arsenal
    assert 'shutil.which("docker")' in model_intake
    assert "subprocess.Popen" in model_intake


def test_api_image_omits_worker_executables_and_defaults_to_non_root():
    dockerfile = (ROOT / "scanner" / "Dockerfile.api").read_text(encoding="utf-8")
    assert "FROM ${SCANNER_RUNTIME_IMAGE} AS scanner-runtime" in dockerfile
    assert "FROM mcr.microsoft.com/playwright/python:v1.62.0-noble@sha256:" in dockerfile
    assert "COPY --from=scanner-runtime /opt/tools" not in dockerfile
    assert "test ! -e /opt/tools" in dockerfile
    assert "USER 10001:10001" in dockerfile


def test_release_api_uses_host_identity_and_socket_supplementary_group():
    compose = (ROOT / "docker-compose.release.yml").read_text(encoding="utf-8")
    assert 'user: "${SHAKERSCAN_API_UID:-10001}:${SHAKERSCAN_API_GID:-10001}"' in compose
    assert '"${SHAKERSCAN_DOCKER_GID:-0}"' in compose
    launcher = (ROOT / "scanner.sh").read_text(encoding="utf-8")
    assert "stat -c '%g' /var/run/docker.sock" in launcher
    assert "write_dotenv_value SHAKERSCAN_DOCKER_GID" in launcher


def test_release_api_storage_init_preserves_private_sandbox_and_shares_worker_dirs():
    compose = (ROOT / "docker-compose.release.yml").read_text(encoding="utf-8")
    assert "api-storage-init:" in compose
    assert "condition: service_completed_successfully" in compose
    assert "-path /results/model-intake-sandbox -prune" in compose
    assert "chmod g+rws" in compose
    assert "network_mode: none" in compose
    worker_entrypoint = (ROOT / "scanner" / "entrypoint.sh").read_text(encoding="utf-8")
    api_entrypoint = (ROOT / "scanner" / "api-entrypoint.sh").read_text(encoding="utf-8")
    assert "umask 0002" in worker_entrypoint
    assert "umask 0002" in api_entrypoint
