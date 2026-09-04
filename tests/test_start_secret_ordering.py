"""Every required secret must exist before startup ever invokes Compose.

A 2.1.0 upgrade on a VPS died with "MODEL_INTAKE_SIGNER_DATABASE_PASSWORD is required". The hosted
installer had created a new install directory beside an older install's Docker volumes. With a
Postgres data volume present and no recorded password, the datastore step brought PostgreSQL up to
rotate the credential -- and that `compose up` interpolates the whole compose file, which fails
closed on the signer secret that had not been generated yet. `set -e` then killed the script with a
misleading error and a half-written .env.

These tests run the real scanner.sh functions, in the order prepare_runtime_files calls them,
against a Compose stub that refuses to run unless the signer secret exists, and pin the new guard
that refuses to silently take over another install directory's data volume.
"""

from __future__ import annotations

import os
import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "scanner.sh").read_text(encoding="utf-8")

FUNCTIONS = (
    "read_dotenv_value",
    "write_dotenv_value",
    "generate_datastore_secret",
    "postgres_data_volume_exists",
    "ensure_runtime_datastore_credentials",
    "ensure_model_intake_operator_credential",
    "ensure_model_intake_local_session_secret",
    "ensure_model_intake_signer_credentials",
)
ENSURES = tuple(name for name in FUNCTIONS if name.startswith("ensure_"))


def _extract(name: str) -> str:
    marker = f"\n{name}() {{\n"
    assert marker in SCRIPT, f"{name} is missing from scanner.sh"
    body = SCRIPT.split(marker, 1)[1].split("\n}\n", 1)[0]
    return f"{name}() {{\n{body}\n}}\n"


def _ensure_order_in_prepare_runtime_files() -> list[str]:
    body = SCRIPT.split("\nprepare_runtime_files() {\n", 1)[1].split("\n}\n", 1)[0]
    return [
        line.strip() for line in body.splitlines()
        if line.strip() in ENSURES
    ]


# A Compose stub with the real interpolation contract: the release compose fails closed on every
# required secret, so any call without all of them is the bug.
COMPOSE_STUB = r'''
compose() {
  for required in POSTGRES_PASSWORD REDIS_PASSWORD MODEL_INTAKE_SIGNER_DATABASE_PASSWORD; do
    if [ -z "${!required:-}" ]; then
      echo "error while interpolating: required variable $required is missing a value" >&2
      return 1
    fi
  done
  case "$*" in
    "up -d postgres") return 0 ;;
    "exec -T postgres pg_isready -U scanner") return 0 ;;
    "exec -T postgres psql"*) cat >/dev/null; return 0 ;;
  esac
  return 0
}
'''


def _run(tmp_path, *, existing_env: str, command: str, volume_exists: bool, adopt: bool, order):
    (tmp_path / ".env").write_text(existing_env)
    harness = "\n".join([
        "set -e",
        f'SCRIPT_DIR="{tmp_path}"',
        'RED=""; NC=""',
        'command_exists() { [ "$1" = docker ]; }',
        f'docker() {{ [ "{int(volume_exists)}" = "1" ]; }}',
        COMPOSE_STUB,
        *(_extract(name) for name in FUNCTIONS),
        f'COMMAND="{command}"',
        *order,
        'echo ORDER_COMPLETED',
    ])
    env = {
        **os.environ,
        "POSTGRES_PASSWORD": "", "REDIS_PASSWORD": "",
        "MODEL_INTAKE_SIGNER_DATABASE_PASSWORD": "", "MODEL_INTAKE_SIGNER_INTERNAL_TOKEN": "",
        "MODEL_INTAKE_OPERATOR_TOKEN": "", "MODEL_INTAKE_LOCAL_SESSION_SECRET": "",
        "SHAKERSCAN_ADOPT_EXISTING_DATA": "1" if adopt else "0",
    }
    result = subprocess.run(["bash", "-c", harness], capture_output=True, text=True, env=env)
    values = {}
    for line in (tmp_path / ".env").read_text().splitlines():
        key, _, value = line.partition("=")
        values[key] = value
    return result, values


def test_prepare_runtime_files_ensures_the_datastore_last():
    order = _ensure_order_in_prepare_runtime_files()
    assert set(order) == set(ENSURES)
    assert order[-1] == "ensure_runtime_datastore_credentials", order


def test_rotation_on_an_existing_volume_finds_every_secret_already_present(tmp_path):
    # The exact incident shape: empty .env, existing data volume, `start`. The datastore step
    # rotates the Postgres credential through Compose, and that call must not fail closed on a
    # signer secret that startup has not generated yet.
    result, values = _run(
        tmp_path, existing_env="", command="start", volume_exists=True, adopt=True,
        order=_ensure_order_in_prepare_runtime_files(),
    )
    assert result.returncode == 0, result.stderr
    assert "ORDER_COMPLETED" in result.stdout
    for key in ("POSTGRES_PASSWORD", "REDIS_PASSWORD",
                "MODEL_INTAKE_SIGNER_DATABASE_PASSWORD", "MODEL_INTAKE_SIGNER_INTERNAL_TOKEN"):
        assert len(values.get(key, "")) >= 32, key


def test_the_pre_fix_order_reproduces_the_incident(tmp_path):
    # Datastore first (the old order) hits the interpolation failure on the signer secret and,
    # under set -e, nothing after it runs: the misleading error and half-written .env from the VPS.
    old_order = ["ensure_runtime_datastore_credentials", *[n for n in ENSURES if n != "ensure_runtime_datastore_credentials"]]
    result, values = _run(
        tmp_path, existing_env="", command="start", volume_exists=True, adopt=True, order=old_order,
    )
    assert result.returncode != 0
    assert "MODEL_INTAKE_SIGNER_DATABASE_PASSWORD is missing" in result.stderr
    assert "ORDER_COMPLETED" not in result.stdout
    assert "MODEL_INTAKE_SIGNER_DATABASE_PASSWORD" not in values


def test_a_foreign_data_volume_fails_closed_unless_adopted(tmp_path):
    # An existing volume with no recorded Postgres password is another install directory's data.
    result, values = _run(
        tmp_path, existing_env="", command="start", volume_exists=True, adopt=False,
        order=_ensure_order_in_prepare_runtime_files(),
    )
    assert result.returncode != 0
    assert "already exists, but" in result.stderr and "SHAKERSCAN_HOME" in result.stderr
    assert "POSTGRES_PASSWORD" not in values
    # A recorded password that merely differs is the supported weak-default rotation, not foreign data.
    result, values = _run(
        tmp_path, existing_env="POSTGRES_PASSWORD=short\n", command="start", volume_exists=True, adopt=False,
        order=_ensure_order_in_prepare_runtime_files(),
    )
    assert result.returncode == 0, result.stderr
    assert len(values["POSTGRES_PASSWORD"]) >= 32
