"""The release API's group_add never lists one group twice.

The API needs the Docker socket's group and the Model Intake sandbox group. A non-root operator
whose PRIMARY group owns the socket (after `newgrp docker` or `sg docker -c ...`) got the same id
for both, Compose 2.40 refused the file ("services.api.group_add items at 0 and 1 are equal"), and
the launcher then blamed the image pull and the network. These tests drive the real scanner.sh
functions with stubbed `id`/`stat`/`docker` commands (unit fixtures, not a live install) and, when
Docker Compose is installed, validate the rendered release file with `docker compose config`.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
RELEASE_COMPOSE = ROOT / "docker-compose.release.yml"
FUNCTIONS = (ROOT / "scanner.sh").read_text(encoding="utf-8").rsplit("# Parse arguments", 1)[0]


def _fake_host(tmp_path: Path, uid: str, gid: str, socket_gid: str) -> Path:
    """`id` reports uid/gid, `stat` reports the socket's group; ownership changes are recorded only."""
    fake = tmp_path / "bin"
    fake.mkdir()
    (fake / "id").write_text(
        f'#!/bin/sh\ncase "$1" in -u) echo {uid};; -g) echo {gid};; *) exec /usr/bin/id "$@";; esac\n',
        encoding="utf-8",
    )
    real_stat = shutil.which("stat") or "/usr/bin/stat"
    (fake / "stat").write_text(
        '#!/bin/sh\nfor last in "$@"; do :; done\n'
        f'if [ "$last" = /var/run/docker.sock ]; then echo {socket_gid}; exit 0; fi\nexec {real_stat} "$@"\n',
        encoding="utf-8",
    )
    for command in ("chgrp", "chown"):
        (fake / command).write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (fake / "getent").write_text("#!/bin/sh\nexit 2\n", encoding="utf-8")
    for path in fake.iterdir():
        path.chmod(0o755)
    return fake


def _prepare(tmp_path: Path, *, uid: str, gid: str, socket_gid: str, sandbox_owner: tuple[str, str] | None = None):
    fake = _fake_host(tmp_path, uid, gid, socket_gid)
    install = tmp_path / "install"
    install.mkdir(mode=0o700)
    if sandbox_owner:
        # An existing install: the launcher reads the private queue's owner back with stat.
        (install / "results" / "model-intake-sandbox").mkdir(parents=True)
        real_stat = shutil.which("stat") or "/usr/bin/stat"
        (fake / "stat").write_text(
            '#!/bin/sh\nfor last in "$@"; do :; done\n'
            f'if [ "$last" = /var/run/docker.sock ]; then echo {socket_gid}; exit 0; fi\n'
            'case "$last" in results/model-intake-sandbox)\n'
            f'  case "$*" in *%u*) echo {sandbox_owner[0]};; *) echo {sandbox_owner[1]};; esac; exit 0;;\nesac\n'
            f'exec {real_stat} "$@"\n',
            encoding="utf-8",
        )
    script = FUNCTIONS + f'\nSCRIPT_DIR="{install}"; cd "$SCRIPT_DIR" || exit 9; prepare_runtime_files\n'
    env = {key: value for key, value in os.environ.items() if not key.startswith(("SHAKERSCAN_", "MODEL_INTAKE_"))}
    # The function goes on to require release files this bare directory does not have; the
    # identities it records before that are what matter here.
    subprocess.run(
        ["bash", "-s"], input=script, cwd=ROOT, capture_output=True, text=True, timeout=60, check=False,
        env={**env, "PATH": f"{fake}:{os.environ['PATH']}", "HOME": str(tmp_path)},
    )
    values = {}
    for line in (install / ".env").read_text(encoding="utf-8").splitlines():
        key, _, value = line.partition("=")
        values[key] = value
    return values


def _api_group_add(values: dict[str, str]) -> list[str]:
    """The api service's group_add as Compose interpolates it from these values."""
    api = yaml.safe_load(RELEASE_COMPOSE.read_text(encoding="utf-8"))["services"]["api"]

    def interpolate(item: str) -> str:
        return re.sub(
            r"\$\{([A-Z0-9_]+):-([^}]*)\}",
            lambda match: values.get(match.group(1)) or match.group(2),
            str(item),
        )

    return [interpolate(item) for item in api["group_add"]]


def _compose_config(tmp_path: Path, values: dict[str, str]) -> subprocess.CompletedProcess:
    text = RELEASE_COMPOSE.read_text(encoding="utf-8")
    required = set(re.findall(r"\$\{([A-Z0-9_]+):?\?", text))
    env_file = tmp_path / "compose.env"
    env_file.write_text(
        "".join(f"{key}=fixture-{key.lower()}\n" for key in sorted(required))
        + "".join(f"{key}={value}\n" for key, value in values.items()),
        encoding="utf-8",
    )
    env = {key: value for key, value in os.environ.items() if not key.startswith(("SHAKERSCAN_", "MODEL_INTAKE_"))}
    return subprocess.run(
        ["docker", "compose", "--project-directory", str(tmp_path), "--env-file", str(env_file),
         "-f", str(RELEASE_COMPOSE), "config", "--quiet"],
        capture_output=True, text=True, timeout=60, check=False, env=env,
    )


def _compose_available() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "compose", "version"], capture_output=True, timeout=30, check=False).returncode == 0


def test_no_service_in_any_compose_file_can_render_a_group_twice_from_one_key():
    # Two entries naming the same key would always collide; every group_add must use distinct keys.
    for compose in ROOT.glob("docker-compose*.yml"):
        services = yaml.safe_load(compose.read_text(encoding="utf-8")).get("services", {})
        for name, service in services.items():
            items = [str(item) for item in service.get("group_add", [])]
            assert len(items) == len(set(items)), (compose.name, name, items)


def test_primary_group_equal_to_the_socket_group_renders_no_duplicate(tmp_path):
    values = _prepare(tmp_path, uid="1000", gid="109", socket_gid="109")
    # The sandbox stays the operator's identity; only the API's second entry changes.
    assert values["MODEL_INTAKE_SANDBOX_GID"] == "109"
    assert values["SHAKERSCAN_DOCKER_GID"] == "109"
    groups = _api_group_add(values)
    assert groups[0] == "109"  # one entry covers both the socket and the sandbox group
    assert len(groups) == len(set(groups)), groups
    assert values["SHAKERSCAN_API_SANDBOX_GROUP_GID"] == "65534"


def test_ordinary_non_root_install_keeps_both_groups(tmp_path):
    values = _prepare(tmp_path, uid="1000", gid="1000", socket_gid="109")
    assert values["MODEL_INTAKE_SANDBOX_GID"] == "1000"
    assert _api_group_add(values) == ["109", "1000"]


def test_root_install_keeps_the_sandbox_account_group(tmp_path):
    values = _prepare(tmp_path, uid="0", gid="0", socket_gid="109")
    assert values["MODEL_INTAKE_SANDBOX_GID"] == "10001"
    assert values["SHAKERSCAN_API_GID"] == "10002"
    assert _api_group_add(values) == ["109", "10001"]


def test_an_upgrade_keeps_the_recorded_sandbox_owner(tmp_path):
    # An old root-run install's private queue belongs to 10001; a later non-root start under
    # `sg docker` keeps that identity, and the API still gets the sandbox group.
    values = _prepare(tmp_path, uid="1000", gid="109", socket_gid="109", sandbox_owner=("10001", "10001"))
    assert values["MODEL_INTAKE_SANDBOX_UID"] == "10001"
    assert values["MODEL_INTAKE_SANDBOX_GID"] == "10001"
    assert _api_group_add(values) == ["109", "10001"]


def test_api_sandbox_group_choice_never_equals_the_socket_group():
    script = FUNCTIONS + "\n" + "\n".join(
        f'echo "$(api_sandbox_group_gid {docker} {sandbox} {api})"'
        for docker, sandbox, api in (
            ("109", "1000", "1000"),
            ("109", "109", "109"),
            ("109", "109", "2000"),
            ("65534", "65534", "65534"),
            ("0", "10001", "10002"),
        )
    ) + "\n"
    result = subprocess.run(["bash", "-s"], input=script, cwd=ROOT, capture_output=True, text=True, timeout=60, check=False)
    assert result.stdout.split() == ["1000", "65534", "2000", "65533", "10001"]


def test_compose_calls_derive_the_key_for_installs_without_it(tmp_path):
    # Commands such as `scale` or `reset` run Compose without preparing runtime files first; an
    # .env written by an older release has no key, and must still yield its sandbox group.
    install = tmp_path / "install"
    install.mkdir()
    (install / ".env").write_text("SHAKERSCAN_DOCKER_GID=109\nMODEL_INTAKE_SANDBOX_GID=109\nSHAKERSCAN_API_GID=109\n")
    script = FUNCTIONS + f'\nSCRIPT_DIR="{install}"\nexport_api_sandbox_group\necho "$SHAKERSCAN_API_SANDBOX_GROUP_GID"\n'
    env = {key: value for key, value in os.environ.items() if not key.startswith(("SHAKERSCAN_", "MODEL_INTAKE_"))}
    result = subprocess.run(["bash", "-s"], input=script, cwd=ROOT, capture_output=True, text=True, timeout=60, check=False, env=env)
    assert result.stdout.strip() == "65534"
    launcher = (ROOT / "scanner.sh").read_text(encoding="utf-8")
    entry = launcher.rsplit("# Parse arguments", 1)[1]
    assert entry.index("\nsync_api_sandbox_group\n") < entry.index("\ncase $COMMAND in")


def _sync(install: Path) -> subprocess.CompletedProcess:
    script = FUNCTIONS + f'\nSCRIPT_DIR="{install}"\nsync_api_sandbox_group\n'
    env = {key: value for key, value in os.environ.items() if not key.startswith(("SHAKERSCAN_", "MODEL_INTAKE_"))}
    return subprocess.run(["bash", "-s"], input=script, cwd=ROOT, capture_output=True, text=True, timeout=60, check=False, env=env)


@pytest.mark.parametrize("recorded", ["", "SHAKERSCAN_API_SANDBOX_GROUP_GID=65534\n"])
def test_launcher_start_writes_a_missing_or_stale_key_to_env_for_sudo_compose(tmp_path, recorded):
    # `sudo docker compose` drops the environment, so Compose reads only .env. A sudo-mode `reset`
    # on an upgraded .env must still give the API the sandbox group: here one that is neither the
    # API's primary group, nor 10001, nor the socket group.
    install = tmp_path / "install"
    install.mkdir()
    (install / ".env").write_text(
        "SHAKERSCAN_DOCKER_GID=109\nMODEL_INTAKE_SANDBOX_GID=2000\nSHAKERSCAN_API_GID=1000\n" + recorded
    )
    result = _sync(install)
    assert result.returncode == 0, result.stderr
    lines = (install / ".env").read_text().splitlines()
    assert [line for line in lines if line.startswith("SHAKERSCAN_API_SANDBOX_GROUP_GID=")] == [
        "SHAKERSCAN_API_SANDBOX_GROUP_GID=2000"
    ]


def test_launcher_start_creates_no_env_outside_an_install(tmp_path):
    result = _sync(tmp_path)
    assert result.returncode == 0, result.stderr
    assert not (tmp_path / ".env").exists()


def test_start_returns_the_key_to_the_sandbox_group_once_the_socket_group_resolves(tmp_path):
    # The provisional (host-stat) socket group equals the operator's primary group, so the
    # provisional key is the placeholder; the socket group seen inside a container differs, and
    # the recorded key must then be the sandbox group again.
    install = tmp_path / "install"
    (install / "scripts").mkdir(parents=True)
    (install / "scripts" / "target_upgrade_backup.sh").write_text("ensure_target_upgrade_backup() { :; }\n")
    stubs = """
prepare_runtime_files() {
    export MODEL_INTAKE_SANDBOX_GID=109 SHAKERSCAN_API_GID=109 SHAKERSCAN_DOCKER_GID=109
    write_dotenv_value MODEL_INTAKE_SANDBOX_GID 109
    write_dotenv_value SHAKERSCAN_API_GID 109
    write_dotenv_value SHAKERSCAN_DOCKER_GID 109
    record_api_sandbox_group
    echo "provisional=$SHAKERSCAN_API_SANDBOX_GROUP_GID"
}
resolve_docker_socket_gid() { printf '0\\n'; }
persist_remote_access_env() { :; }
warn_if_ui_port_has_foreign_listener() { :; }
resolve_start_workers() { printf '1\\n'; }
set_build_env() { :; }
pull_prebuilt_images() { :; }
record_runtime_mode() { :; }
compose() { :; }
compose_up() { echo "up-key=$SHAKERSCAN_API_SANDBOX_GROUP_GID"; }
start_clean_slate_reason() { :; }
running_compose_service_count() { printf '1\\n'; }
running_device_worker_count() { printf '0\\n'; }
wait_for_url() { :; }
verify_running_build_identity() { :; }
verify_specialized_worker_identity() { :; }
"""
    script = (
        FUNCTIONS + stubs
        + f'\nSCRIPT_DIR="{install}"; cd "$SCRIPT_DIR" || exit 9\nWORKERS=1; USE_PREBUILT=1\n'
        + "API_IMAGE=api:test; SCANNER_IMAGE=worker:test; UI_IMAGE=ui:test\nstart_services\n"
    )
    env = {key: value for key, value in os.environ.items() if not key.startswith(("SHAKERSCAN_", "MODEL_INTAKE_"))}
    result = subprocess.run(
        ["bash", "-s"], input=script, cwd=ROOT, capture_output=True, text=True, timeout=60, check=False,
        env={**env, "HOME": str(tmp_path)},
    )
    assert "provisional=65534" in result.stdout, result.stdout + result.stderr
    assert "up-key=109" in result.stdout, result.stdout + result.stderr
    values = dict(line.split("=", 1) for line in (install / ".env").read_text().splitlines())
    assert values["SHAKERSCAN_DOCKER_GID"] == "0"
    assert values["SHAKERSCAN_API_SANDBOX_GROUP_GID"] == "109"


@pytest.mark.skipif(not _compose_available(), reason="Docker Compose is not installed")
def test_rendered_release_file_validates_with_docker_compose(tmp_path):
    for uid, gid, socket_gid in (("1000", "109", "109"), ("1000", "1000", "109"), ("0", "0", "109")):
        case = tmp_path / f"{uid}-{gid}"
        case.mkdir()
        values = _prepare(case, uid=uid, gid=gid, socket_gid=socket_gid)
        result = _compose_config(case, values)
        assert result.returncode == 0, (uid, gid, result.stderr)


@pytest.mark.skipif(not _compose_available(), reason="Docker Compose is not installed")
def test_the_old_rendering_is_what_compose_rejects(tmp_path):
    # Guards the premise: the same group in both entries is a validation error, not a pull error.
    result = _compose_config(tmp_path, {"SHAKERSCAN_DOCKER_GID": "109", "SHAKERSCAN_API_SANDBOX_GROUP_GID": "109"})
    assert result.returncode != 0
    assert "group_add" in result.stderr


def test_a_compose_validation_failure_is_not_reported_as_a_pull_failure(tmp_path):
    fake = tmp_path / "bin"
    fake.mkdir()
    calls = tmp_path / "calls"
    (fake / "docker").write_text(
        "#!/bin/sh\n"
        f'echo "$*" >> "{calls}"\n'
        'case "$*" in\n'
        '  "compose version") echo "Docker Compose version v2.40.3"; exit 0;;\n'
        '  *" config "*|*" config") echo "services.api.group_add items at 0 and 1 are equal" >&2; exit 15;;\n'
        '  *) exit 1;;\n'
        "esac\n",
        encoding="utf-8",
    )
    (fake / "docker").chmod(0o755)
    script = FUNCTIONS + (
        '\nUSE_PREBUILT=1; COMPOSE_FILE_ARGS=(-f docker-compose.release.yml)\n'
        f'SCRIPT_DIR="{tmp_path}"\n'
        "pull_prebuilt_images || echo \"status=$?\"\n"
    )
    env = {key: value for key, value in os.environ.items() if not key.startswith(("SHAKERSCAN_", "MODEL_INTAKE_"))}
    result = subprocess.run(
        ["bash", "-s"], input=script, cwd=ROOT, capture_output=True, text=True, timeout=60, check=False,
        env={**env, "PATH": f"{fake}:{os.environ['PATH']}", "HOME": str(tmp_path)},
    )
    assert "status=1" in result.stdout
    assert "services.api.group_add items at 0 and 1 are equal" in result.stderr
    assert "rejected the ShakerScan configuration" in result.stderr
    assert "not cached" not in result.stderr
    assert "Docker Hub" not in result.stderr
    assert not any(" pull " in f" {line} " for line in calls.read_text().splitlines())
