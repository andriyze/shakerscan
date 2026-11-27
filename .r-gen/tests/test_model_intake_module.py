"""Model Intake is an optional module (2.10): off for a new install, kept on for an existing one.

Compose puts its four services in the ``model-intake`` profile; the launcher pulls and starts them
only when SHAKERSCAN_MODEL_INTAKE_ENABLED is on; the installer records it off for a new install
only; the API refuses changes with 409 module_not_installed while existing records stay readable,
and /health reports the module as disabled rather than as a missing worker.
"""
from __future__ import annotations

import asyncio
import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[1]
SERVICES = {"model-intake-signer-db-init", "model-intake-signer", "model-intake-worker", "model-intake-sandbox"}


@pytest.mark.parametrize("compose_file", ["docker-compose.release.yml", "docker-compose.yml"])
def test_every_model_intake_service_is_in_its_profile_and_nothing_else_depends_on_one(compose_file):
    services = yaml.safe_load((ROOT / compose_file).read_text())["services"]
    assert {name for name in services if name.startswith("model-intake")} == SERVICES
    for name in SERVICES:
        assert services[name].get("profiles") == ["model-intake"], name
    for name, service in services.items():
        if name in SERVICES:
            continue
        depends = service.get("depends_on") or {}
        assert not set(depends) & SERVICES, f"{name} would fail to start with Model Intake off"
    api_env = services["api"]["environment"]
    assert "SHAKERSCAN_MODEL_INTAKE_ENABLED=${SHAKERSCAN_MODEL_INTAKE_ENABLED:-true}" in api_env


def _launcher_function(name: str) -> str:
    text = (ROOT / "scanner.sh").read_text()
    match = re.search(rf"^{re.escape(name)}\(\) \{{\n(.*?)^\}}\n", text, re.S | re.M)
    assert match, name
    return match.group(1)


def test_the_launcher_starts_model_intake_only_when_on_and_removes_it_on_stop():
    load = _launcher_function("load_access_env")
    assert 'value="${SHAKERSCAN_MODEL_INTAKE_ENABLED:-$(read_dotenv_value SHAKERSCAN_MODEL_INTAKE_ENABLED)}"' in load
    assert 'case "${value:-true}" in' in load.split("SHAKERSCAN_MODEL_INTAKE_ENABLED:-$(read_dotenv")[1]
    start = _launcher_function("start_services")
    assert "if model_intake_enabled; then" in start
    assert "compose --profile model-intake up --no-build -d" in start
    assert "compose --profile model-intake stop model-intake-worker model-intake-sandbox model-intake-signer" in start
    outside = _launcher_function("containers_outside_compose_down")
    assert "$2 ~ /^model-intake-/" in outside
    command = _launcher_function("model_intake_cmd")
    for needle in ("compose --profile model-intake pull model-intake-signer model-intake-worker model-intake-sandbox",
                   "write_dotenv_value SHAKERSCAN_MODEL_INTAKE_ENABLED true",
                   "write_dotenv_value SHAKERSCAN_MODEL_INTAKE_ENABLED false",
                   "compose --profile model-intake rm -s -f $MODEL_INTAKE_SERVICES",
                   'docker_cli image rm "$image"'):
        assert needle in command, needle
    assert "docker image rm -f" not in command and "docker image rm --force" not in command


def _install_default(existing_env: str | None, tmp_path: Path) -> str:
    """Run the installer's .env default step exactly as written in install/index.sh."""
    text = (ROOT / "install" / "index.sh").read_text()
    step = text[text.index('touch "$INSTALL_STAGE/.env"'):text.index(': > "$INSTALL_STAGE/$OWNED_MANIFEST_NAME"')]
    install_dir, stage = tmp_path / "install", tmp_path / "stage"
    install_dir.mkdir(parents=True); stage.mkdir(parents=True)
    if existing_env is not None:
        (install_dir / ".env").write_text(existing_env)
        (stage / ".env").write_text(existing_env)
    subprocess.run(["sh", "-c", step], check=True,
                   env={"INSTALL_DIR": str(install_dir), "INSTALL_STAGE": str(stage), "PATH": "/usr/bin:/bin"})
    return (stage / ".env").read_text()


def test_a_new_install_records_model_intake_off_and_an_upgrade_keeps_its_setting(tmp_path):
    assert _install_default(None, tmp_path / "new") == "SHAKERSCAN_MODEL_INTAKE_ENABLED=false\n"
    # An install that predates the setting keeps Model Intake on (the launcher's default).
    assert "SHAKERSCAN_MODEL_INTAKE_ENABLED" not in _install_default("POSTGRES_PASSWORD=x\n", tmp_path / "old")
    assert _install_default("SHAKERSCAN_MODEL_INTAKE_ENABLED=true\n", tmp_path / "on") == (
        "SHAKERSCAN_MODEL_INTAKE_ENABLED=true\n")


class _Request:
    def __init__(self, method: str):
        self.method = method


def test_with_the_module_off_changes_are_refused_and_records_stay_readable(monkeypatch):
    from model_intake import router as module
    monkeypatch.setenv("SHAKERSCAN_MODEL_INTAKE_ENABLED", "false")
    for method in ("POST", "PATCH", "PUT", "DELETE"):
        with pytest.raises(HTTPException) as refused:
            asyncio.run(module._require_module_for_changes(_Request(method)))
        assert refused.value.status_code == 409
        assert refused.value.detail["reason_code"] == "module_not_installed"
        assert "shakerscan model-intake enable" in refused.value.detail["detail"]
    for method in ("GET", "HEAD", "OPTIONS"):
        asyncio.run(module._require_module_for_changes(_Request(method)))
    assert module._model_intake_worker_readiness() == {
        "enabled": False, "status": "disabled", "reason": "module_not_installed"}


@pytest.mark.parametrize("value", [None, "true", "1", "on"])
def test_the_module_is_on_by_default_and_when_set(monkeypatch, value):
    from model_intake import router as module
    if value is None:
        monkeypatch.delenv("SHAKERSCAN_MODEL_INTAKE_ENABLED", raising=False)
    else:
        monkeypatch.setenv("SHAKERSCAN_MODEL_INTAKE_ENABLED", value)
    assert module.model_intake_enabled()
    asyncio.run(module._require_module_for_changes(_Request("POST")))


@pytest.mark.parametrize("subcommand", ["enable", "disable"])
def test_enabling_or_disabling_recreates_the_api_with_the_start_environment(tmp_path, subcommand):
    """2.10 candidate certification: `model-intake enable` recreated the API without the
    launcher's environment, so it lost its install directory and reported a runner command for
    ~/.shakerscan instead of the install it runs from."""
    script = "\n".join([
        "set -eu",
        f'SCRIPT_DIR="{tmp_path}"; USE_PREBUILT=1; DEFAULT_PREBUILT_IMAGE_TAG=2.10.0',
        'GREEN=""; BLUE=""; NC=""; SHAKERSCAN_PULL_IMAGES=0',
        "is_truthy() { case \"${1:-}\" in 1|true|yes|on) return 0;; *) return 1;; esac; }",
        "get_build_version() { echo abc1234; }",
        "get_release_version() { echo 2.10.0; }",
        "write_dotenv_value() { :; }",
        'compose() { case "$*" in *"--force-recreate api"*) '
        'printf "api-recreated dir=%s release=%s\\n" "${SHAKERSCAN_RUNTIME_DIR:-}" "${SCANNER_RELEASE_VERSION:-}";; esac; }',
        'MODEL_INTAKE_SERVICES="model-intake-signer"',
        "set_build_env() {\n" + _launcher_function("set_build_env") + "}",
        "model_intake_cmd() {\n" + _launcher_function("model_intake_cmd") + "}",
        f"model_intake_cmd {subcommand}",
    ])
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True,
                         env={"PATH": os.environ["PATH"], "HOME": str(tmp_path / "home")}).stdout
    assert f"api-recreated dir={tmp_path} release=2.10.0" in out
