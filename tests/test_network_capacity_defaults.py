"""Real launcher functions against inert Compose; no Docker or target traffic."""
import os
from pathlib import Path
import shlex
import subprocess

import pytest

from api.devices.readiness import capacity_state

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / 'scanner.sh').read_text()


def function(name):
    body = SCRIPT.split(f'\n{name}() {{', 1)[1].split('\n}', 1)[0]
    return f'{name}() {{{body}\n}}'


def run(tmp_path, code, **env):
    functions = '\n'.join(function(name) for name in (
        'read_dotenv_value', 'write_dotenv_value', 'load_access_env', 'devices_cmd',
    ))
    return subprocess.run(['bash', '-c', f'''set -eu
RED=''; GREEN=''; YELLOW=''; NC=''; USE_PREBUILT=1
SCRIPT_DIR={shlex.quote(str(tmp_path))}
api_base_url() {{ printf 'http://localhost:8080'; }}
compose() {{ printf 'compose:%s\\n' "$*"; return "${{COMPOSE_RESULT:-0}}"; }}
{functions}
{code}
'''], capture_output=True, text=True,
        env={**{k: v for k, v in os.environ.items() if k != 'SHAKERSCAN_NETWORK_WORKER_ENABLED'}, **env},
        timeout=10)


def test_fresh_install_default_and_explicit_stop_start_are_persisted(tmp_path):
    result = run(tmp_path, '''
load_access_env
test "$SHAKERSCAN_NETWORK_WORKER_ENABLED" = true
devices_cmd stop
unset SHAKERSCAN_NETWORK_WORKER_ENABLED
load_access_env
test "$SHAKERSCAN_NETWORK_WORKER_ENABLED" = false
devices_cmd start
unset SHAKERSCAN_NETWORK_WORKER_ENABLED
load_access_env
test "$SHAKERSCAN_NETWORK_WORKER_ENABLED" = true
''')
    assert result.returncode == 0, result.stdout + result.stderr
    assert (tmp_path / '.env').read_text() == 'SHAKERSCAN_NETWORK_WORKER_ENABLED=true\n'


@pytest.mark.parametrize('value', ['false', '0', 'off', 'FALSE'])
def test_environment_opt_out_is_normalized(tmp_path, value):
    result = run(tmp_path, 'load_access_env; test "$SHAKERSCAN_NETWORK_WORKER_ENABLED" = false',
                 SHAKERSCAN_NETWORK_WORKER_ENABLED=value)
    assert result.returncode == 0, result.stderr


def test_failed_enable_does_not_replace_persisted_opt_out(tmp_path):
    (tmp_path / '.env').write_text('SHAKERSCAN_NETWORK_WORKER_ENABLED=false\n')
    result = run(tmp_path, 'load_access_env; devices_cmd start', COMPOSE_RESULT='9')
    assert result.returncode == 1
    assert 'automatic startup enabled' not in result.stdout
    assert (tmp_path / '.env').read_text() == 'SHAKERSCAN_NETWORK_WORKER_ENABLED=false\n'


def test_invalid_configuration_fails_before_startup(tmp_path):
    result = run(tmp_path, 'load_access_env', SHAKERSCAN_NETWORK_WORKER_ENABLED='maybe')
    assert result.returncode != 0
    assert 'must be true or false' in result.stderr


def test_readiness_moves_from_starting_to_unavailable_and_current_capacity():
    args = dict(enabled=True, configured=True, reports=[], capable_count=0)
    starting = capacity_state(**args, elapsed=119)
    assert starting['status'] == 'starting' and starting['remedy'] is None
    missing = capacity_state(**args, elapsed=120)
    assert missing['status'] == 'not_ready'
    assert 'shakerscan devices start' in missing['remedy']
    ready = capacity_state(**{**args, 'reports': [{'build_current': True}], 'capable_count': 1}, elapsed=200)
    assert ready['status'] == 'ready'


@pytest.mark.parametrize('current,reason', [
    (False, 'device_worker_build_stale'), (True, 'device_worker_missing_nmap_naabu_or_build_identity'),
])
def test_stale_or_incapable_worker_is_never_ready(current, reason):
    result = capacity_state(enabled=True, configured=True, reports=[{'build_current': current}],
                            capable_count=0, elapsed=200)
    assert result['status'] == 'not_ready' and result['reason'] == reason
    assert 'shakerscan devices restart' in result['remedy']
    assert './scanner.sh' not in result['remedy']


def test_disabled_capacity_and_feature_do_not_claim_startup():
    args = dict(enabled=True, configured=False, reports=[], capable_count=0, elapsed=0)
    assert capacity_state(**args)['reason'] == 'network_worker_disabled'
    assert capacity_state(**{**args, 'enabled': False})['reason'] == 'feature_disabled'


@pytest.mark.parametrize('running,configured,expected', [
    (1, 'true', 1), (1, 'false', 0), (0, 'true', 0),
])
def test_rebuild_supplies_default_capacity_only_on_a_running_stack(tmp_path, running, configured, expected):
    harness = f'''set -eu
RED=''; GREEN=''; YELLOW=''; BLUE=''; NC=''
SCRIPT_DIR={shlex.quote(str(ROOT))}
SHAKERSCAN_NETWORK_WORKER_ENABLED={configured}
prepare_runtime_files() {{ :; }}
set_build_env() {{ :; }}
begin_build_receipt() {{ :; }}
check_build_storage() {{ :; }}
running_scan_worker_count() {{ printf '{running}'; }}
running_device_worker_count() {{ printf '0'; }}
running_compose_service_count() {{ printf '{running}'; }}
build_local_scanner_family() {{ :; }}
run_build_step() {{ :; }}
record_runtime_mode() {{ :; }}
compose() {{ printf 'compose:%s\\n' "$*"; }}
refresh_workers_after_rebuild() {{ :; }}
refresh_running_service_after_rebuild() {{ :; }}
refresh_device_worker_after_rebuild() {{ printf 'network:%s\\n' "$1"; }}
wait_for_url() {{ :; }}
api_probe_url() {{ printf 'http://api'; }}
ui_probe_url() {{ printf 'http://ui'; }}
verify_running_build_identity() {{ :; }}
verify_specialized_worker_identity() {{ printf 'verified-network:%s\\n' "$2"; }}
finish_build_receipt() {{ :; }}
{function('rebuild_images')}
rebuild_images
'''
    result = subprocess.run(['bash', '-c', harness], capture_output=True, text=True,
                            timeout=10, env=os.environ)
    assert result.returncode == 0, result.stdout + result.stderr
    assert f'network:{expected}\n' in result.stdout
    if running:
        assert f'verified-network:{expected}\n' in result.stdout
