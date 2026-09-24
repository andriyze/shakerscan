"""Execute launcher helpers in Bash; never contact Docker or a scan target."""
from __future__ import annotations

import json
from pathlib import Path
import re
import shlex
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / 'scanner.sh').read_text()


def function(name: str) -> str:
    match = re.search(rf'(?m)^{re.escape(name)}\(\) \{{\n.*?^\}}\n', SCRIPT, re.S)
    assert match, name
    return match.group()


def bash(script, stdin='', cwd=None):
    return subprocess.run(['bash', '-c', script], input=stdin, text=True,
                          capture_output=True, timeout=15, cwd=cwd)


def scope(*paths):
    result = bash(function('rebuild_scope_for_paths') + '\nrebuild_scope_for_paths', '\n'.join(paths))
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


@pytest.mark.parametrize('paths,expected', [
    (['ui/src/app/page.tsx', 'ui/public/logo.png'], 'ui'),
    (['api/worker.py'], 'scanner'),
    (['scanner/Dockerfile', 'scanner/scanner_tools/discovery.py'], 'scanner'),
    (['api/worker.py', 'ui/src/lib/api.ts'], 'all'),
    (['api/model_intake_signer.Dockerfile'], 'all'),
    (['api/model_intake_signer_auth.py'], 'all'),
    (['scanner.sh'], 'all'),
    (['docker-compose.yml'], 'all'),
    (['install/MANIFEST.sha256'], 'all'),
    (['skills/hunt/SKILL.md'], 'scanner'),
    (['skills/web/32-service-protocol-and-device-investigation.md'], 'scanner'),
    (['AGENTS.md'], 'scanner'),
    (['scanner/docs/example.md'], 'scanner'),
    (['ui/src/readme.md'], 'ui'),
    (['docs/releases/2.5.3.md', 'README.md', 'tests/test_x.py', '.github/workflows/ci.yml'], 'none'),
    ([], 'none'),
    (['docs/a.md', 'ui/src/x.ts'], 'ui'),
    (['unexpected-file'], 'all'),
])
def test_scope_is_the_smallest_family_that_covers_the_change(paths, expected):
    assert scope(*paths) == expected


def test_image_snapshot_diff_names_what_was_rebuilt():
    before='worker=aaa\napi=bbb\nui=\n'
    after='worker=aaa\napi=ccc\nui=ddd\nsigner=\n'
    result=bash(function('diff_image_snapshots') +
                f'\ndiff_image_snapshots {shlex.quote(before)} {shlex.quote(after)}')
    assert result.returncode == 0, result.stderr
    assert {r.split()[0]:r.split()[3] for r in result.stdout.splitlines()} == {
        'worker':'unchanged','api':'rebuilt','ui':'new','signer':'missing'}


def test_snapshot_includes_config_and_uses_current_project_and_docker_cli():
    helpers=function('rebuild_image_tags')+function('snapshot_image_ids')
    code=helpers+'''
COMPOSE_PROJECT_NAME=ec2-hunt
SCANNER_LOCAL_WORKER_IMAGE=custom-worker:local
MODEL_INTAKE_SANDBOX_IMAGE=custom-model:local
docker_cli() {
    [ "$4" = '{{json .Config}}|{{json .RootFS.Layers}}' ] || return 9
    printf '{"Env":["MODE=%s"]}|["unchanged-layer"]' "$MODE"
}
MODE=before
snapshot_image_ids
MODE=after
snapshot_image_ids
'''
    result=bash(code)
    assert result.returncode == 0, result.stderr
    rows=result.stdout.splitlines()
    assert len(rows)==10
    assert [r.split('=')[0] for r in rows[:5]] == [
        'custom-worker:local','custom-model:local','ec2-hunt-api:latest',
        'ec2-hunt-ui:latest','ec2-hunt-model-intake-signer:latest']
    assert all(a.split('=')[1] and a!=b for a,b in zip(rows[:5],rows[5:]))


def receipt_harness(path):
    names=['write_build_receipt','begin_build_receipt','finish_build_receipt','run_build_step']
    return '\n'.join(function(n) for n in names)+f'''
RED=''; BLUE=''; YELLOW=''; GREEN=''; NC=''
GIT_COMMIT=test-revision
BUILD_RECEIPT_FILE={shlex.quote(str(path))}
BUILD_RECEIPT_ACTIVE=0
docker_storage_free_kb() {{ return 1; }}
dirty_paths() {{ printf 'api/worker.py\\nui/public/logo.png\\n'; }}
'''


def test_receipt_carries_steps_images_dirty_paths_and_smoke(tmp_path):
    receipt=tmp_path/'receipt.json'
    result=bash(receipt_harness(receipt)+'''
begin_build_receipt rebuild scanner
BUILD_STEP_TIMINGS="scanner_runtime=12 api_overlay=3 "
BUILD_IMAGE_RESULTS="worker aaa bbb rebuilt
api - ccc new"
BUILD_SMOKE_RESULT=passed
finish_build_receipt
''')
    assert result.returncode==0,result.stderr
    data=json.loads(receipt.read_text())
    assert data['schema_version']=='shakerscan-build-receipt/v1'
    assert (data['scope'],data['status'])==('scanner','completed')
    assert data['steps']==[{'phase':'scanner_runtime','seconds':12},{'phase':'api_overlay','seconds':3}]
    assert data['images']==[{'tag':'worker','before':'aaa','after':'bbb','result':'rebuilt'},
                           {'tag':'api','before':None,'after':'ccc','result':'new'}]
    assert data['dirty_paths']==['api/worker.py','ui/public/logo.png']
    assert data['smoke']=='passed'


def test_new_receipt_does_not_inherit_previous_timings_or_smoke(tmp_path):
    receipt=tmp_path/'receipt.json'
    result=bash(receipt_harness(receipt)+'''
BUILD_STEP_TIMINGS='old=99 '
BUILD_IMAGE_RESULTS='old aaa bbb rebuilt'
BUILD_SMOKE_RESULT=passed
begin_build_receipt rebuild all
''')
    assert result.returncode==0,result.stderr
    data=json.loads(receipt.read_text())
    assert data['steps']==[] and data['images']==[] and data['smoke'] is None


def git(cwd,*args):
    return subprocess.check_output(['git','-C',str(cwd),*args],text=True).strip()


def test_baseline_rejects_partial_dirty_and_unknown_receipts(tmp_path):
    git(tmp_path,'init','-q')
    git(tmp_path,'-c','user.name=Test','-c','user.email=test@example.test','commit','--allow-empty','-qm','base')
    sha=git(tmp_path,'rev-parse','HEAD')
    receipt=tmp_path/'receipt.json'
    helpers=function('dirty_paths')+function('rebuild_changed_paths')
    valid={'schema_version':'shakerscan-build-receipt/v1','status':'completed','phase':'complete',
           'scope':'all','source_revision':sha,'dirty_paths':[]}
    for overrides, expected in [({},0),({'scope':'ui'},1),({'scope':'scanner'},1),
                               ({'source_revision':sha+'-dirty'},1),({'dirty_paths':['api/a.py']},1),
                               ({'source_revision':'-invalid'},1),({'status':'failed'},1)]:
        receipt.write_text(json.dumps(valid|overrides))
        result=bash(helpers+f'\nBUILD_RECEIPT_FILE={shlex.quote(str(receipt))}\nrebuild_changed_paths',cwd=tmp_path)
        assert result.returncode==expected,(overrides,result.stderr)


def test_rename_tracks_both_old_and_new_scope(tmp_path):
    git(tmp_path,'init','-q')
    (tmp_path/'api').mkdir();(tmp_path/'api/code.py').write_text('one\n')
    git(tmp_path,'add','.')
    git(tmp_path,'-c','user.name=Test','-c','user.email=test@example.test','commit','-qm','base')
    (tmp_path/'docs').mkdir();git(tmp_path,'mv','api/code.py','docs/code.py')
    result=bash(function('dirty_paths')+'\ndirty_paths',cwd=tmp_path)
    assert result.returncode==0,result.stderr
    assert set(result.stdout.splitlines())=={'api/code.py','docs/code.py'}


def rebuild_harness(tmp_path, args, changed='ui/src/page.tsx', counts=0, extra=''):
    receipt=tmp_path/'receipt.json'
    code=receipt_harness(receipt)+function('rebuild_scope_for_paths')+function('diff_image_snapshots')+function('rebuild_images')+f'''
prepare_runtime_files() {{ :; }}
set_build_env() {{ :; }}
check_build_storage() {{ :; }}
rebuild_changed_paths() {{ printf '%s\\n' {shlex.quote(changed)}; }}
dirty_paths() {{ :; }}
snapshot_image_ids() {{ printf 'worker=a\\nmodel=b\\napi=c\\nui=d\\nsigner=e\\n'; }}
print_build_summary() {{ :; }}
running_scan_worker_count() {{ echo {counts}; }}
running_device_worker_count() {{ echo 0; }}
running_compose_service_count() {{ echo {counts}; }}
compose() {{ echo "compose:$*"; }}
build_local_scanner_family() {{ echo 'build:scanner'; }}
record_runtime_mode() {{ :; }}
refresh_workers_after_rebuild() {{ :; }}
refresh_running_service_after_rebuild() {{ :; }}
refresh_device_worker_after_rebuild() {{ :; }}
wait_for_url() {{ :; }}
api_probe_url() {{ echo 'http://127.0.0.1:8080'; }}
ui_probe_url() {{ echo 'http://127.0.0.1:3000'; }}
verify_running_build_identity() {{ :; }}
verify_running_ui_identity() {{ :; }}
verify_specialized_worker_identity() {{ :; }}
post_rebuild_smoke() {{ BUILD_SMOKE_RESULT=passed; echo "smoke:$*"; }}
fail_build() {{ write_build_receipt failed "$1" "$2"; return "$1"; }}
{extra}
rebuild_images {args}
'''
    return bash(code),receipt


def test_explicit_all_is_not_silently_reduced_to_auto_ui(tmp_path):
    result,path=rebuild_harness(tmp_path,'all')
    assert result.returncode==0,result.stderr
    assert 'build:scanner' in result.stdout
    assert 'compose:build ui model-intake-signer' in result.stdout
    assert json.loads(path.read_text())['scope']=='all'


def test_last_scope_wins_without_retaining_old_service_selection(tmp_path):
    result,path=rebuild_harness(tmp_path,'scanner ui all')
    assert result.returncode==0,result.stderr
    assert json.loads(path.read_text())['scope']=='all'


def test_auto_uses_ui_without_rebuilding_workers(tmp_path):
    result,path=rebuild_harness(tmp_path,'')
    assert result.returncode==0,result.stderr
    assert 'build:scanner' not in result.stdout and 'compose:build ui' in result.stdout
    assert json.loads(path.read_text())['smoke']=='not_run:ui_only'


def test_no_cache_with_auto_forces_full_build(tmp_path):
    result,path=rebuild_harness(tmp_path,'--no-cache',changed='README.md')
    assert result.returncode==0,result.stderr
    assert json.loads(path.read_text())['scope']=='all'


def test_scoped_scanner_smoke_runs_and_failure_fails_receipt(tmp_path):
    result,path=rebuild_harness(tmp_path,'scanner',counts=1,
        extra='post_rebuild_smoke() { BUILD_SMOKE_RESULT=failed:1; return 1; }')
    assert result.returncode==1,result.stdout
    data=json.loads(path.read_text())
    assert data['status']=='failed' and data['phase']=='smoke'
    assert 'Rebuild complete' not in result.stdout


def test_no_smoke_is_explicitly_recorded(tmp_path):
    result,path=rebuild_harness(tmp_path,'all --no-smoke',counts=1)
    assert result.returncode==0,result.stderr
    assert json.loads(path.read_text())['smoke']=='not_run:operator_skipped'


def test_stopped_stack_is_not_falsely_reported_as_smoke_pass():
    result=bash(function('post_rebuild_smoke')+'''\npost_rebuild_smoke 0 0
printf '%s' "$BUILD_SMOKE_RESULT"
''')
    assert result.returncode==0,result.stderr
    assert result.stdout=='not_run:no_rebuilt_running_services'


def test_missing_expected_worker_fails_smoke():
    result=bash(function('post_rebuild_smoke')+'''
BLUE='';NC=''
docker_cli() { :; }
post_rebuild_smoke 0 1
exit $?
''')
    assert result.returncode==1
    assert 'worker is not running' in result.stderr


def test_scanner_smoke_uses_timeout_correct_ffuf_flag_and_no_shell():
    result=bash(function('post_rebuild_smoke')+'''
BLUE='';NC=''
docker_cli() { if [ "$1" = ps ]; then echo worker-1; else printf 'docker:%s\\n' "$*"; fi; }
post_rebuild_smoke 0 1
''')
    assert result.returncode==0,result.stderr
    assert 'docker:exec worker-1 timeout 30 /opt/tools/ffuf -V' in result.stdout
    assert 'docker:exec worker-1 timeout 30 /opt/tools/nuclei -version' in result.stdout
    assert ' sh -c ' not in result.stdout
