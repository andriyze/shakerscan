"""The actual CI reporting arguments must reject incomplete synthetic evidence."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('workflow,job', [('release-candidate', 'certify')])
def test_ci_summary_rejects_a_missing_required_assertion(workflow, job, tmp_path):
    doc = yaml.safe_load((ROOT / '.github/workflows' / f'{workflow}.yml').read_text())
    steps = doc['jobs'][job]['steps']
    report = next(step for step in steps if 'scripts/summarize_e2e_debt.py ' in step.get('run', ''))
    assert 'always()' in report['if'] and not report.get('continue-on-error', False)
    tokens = shlex.split(report['run'].replace('\\\n', ' '))
    args, areas, checks = [], set(), []
    for index, token in enumerate(tokens):
        if token in {'--require-area', '--require-check'}:
            value = tokens[index + 1]
            args.extend([token, value])
            if token == '--require-area': areas.add(value)
            else: checks.append(tuple(value.split(':', 1)))
    assert areas == {'platform', 'ai_gate', 'model_intake', 'dast', 'hunt'}
    assert len(checks) == 3
    card = {'gate': 'pass', 'areas': [
        {'area': area, 'gate': 'pass', 'rows': [
            {'name': name, 'passed': True} for owner, name in checks if owner == area
        ] or [{'name': 'synthetic baseline', 'passed': True}]}
        for area in sorted(areas)
    ]}
    path = tmp_path / 'scorecard.json'
    command = [sys.executable, str(ROOT / 'scripts/summarize_e2e_debt.py'), str(path), *args]
    path.write_text(json.dumps(card))
    assert subprocess.run(command, capture_output=True, timeout=5).returncode == 0
    # A successful upstream gate must not hide a required assertion that did not run.
    owner, name = checks[-1]
    area = next(area for area in card['areas'] if area['area'] == owner)
    area['rows'] = [row for row in area['rows'] if row['name'] != name]
    path.write_text(json.dumps(card))
    result = subprocess.run(command, capture_output=True, timeout=5)
    assert result.returncode == 1
    assert json.loads(result.stdout)['policy_validated'] is False


@pytest.mark.parametrize('selected_area', ['all', 'platform', 'ai_gate', 'model_intake', 'dast', 'hunt'])
def test_pr_ci_summary_rejects_missing_selected_evidence(selected_area, tmp_path):
    doc = yaml.safe_load((ROOT / '.github/workflows/e2e-pr.yml').read_text())
    report = next(step for step in doc['jobs']['smoke']['steps']
                  if 'scripts/summarize_e2e_debt.py ' in step.get('run', ''))
    assert 'always()' in report['if'] and not report.get('continue-on-error', False)
    required = {
        'platform': [],
        'ai_gate': [],
        'model_intake': [
            'MI-6 caller cannot supply its own trust anchor',
            'MI-6A expired and wrong durable anchors do not verify',
            'MI-6B operator-created durable anchor verifies exact signature',
            'MI-6C deactivated durable anchor stops verification',
        ],
        'dast': [
            'D-2 retains request-based SQLi result',
            'D-3 retains request-based XSS result',
        ],
        'hunt': [
            'H-18 adaptive real-target methodology produces a verified finding',
            'H-19 authorization proof materializes into a Hunt-attributed finding',
            'H-20 protected and shared objects remain unverified',
        ],
    }
    names = required if selected_area == 'all' else {selected_area: required[selected_area]}
    card = {'gate': 'pass', 'areas': [
        {'area': area, 'gate': 'pass', 'rows': [
            {'name': name, 'passed': True} for name in checks
        ] or [{'name': 'synthetic baseline', 'passed': True}]}
        for area, checks in names.items()
    ]}
    artifacts = tmp_path / 'artifacts'
    artifacts.mkdir()
    scorecard = artifacts / 'e2e-scorecard.json'
    command = report['run'].replace(
        'scripts/summarize_e2e_debt.py', str(ROOT / 'scripts/summarize_e2e_debt.py'))
    env = {**os.environ, 'E2E_AREA': selected_area}

    scorecard.write_text(json.dumps(card))
    assert subprocess.run(['bash', '-e', '-c', command], cwd=tmp_path, env=env,
                          capture_output=True, timeout=5).returncode == 0

    owner = selected_area if selected_area != 'all' else 'hunt'
    if required[owner]:
        card['areas'][list(names).index(owner)]['rows'].pop()
    else:
        card['areas'].pop()
    scorecard.write_text(json.dumps(card))
    result = subprocess.run(['bash', '-e', '-c', command], cwd=tmp_path, env=env,
                            capture_output=True, timeout=5)
    assert result.returncode == 1


@pytest.mark.parametrize('workflow,job,flag,suite', [
    ('maintenance-regressions', 'collection-upload-postgres', 'COLLECTION_POSTGRES_REQUIRED', 'test_collection_atomic_retry_postgres.py'),
    ('data-lifecycle', 'acceptance', 'LIFECYCLE_POSTGRES_REQUIRED', 'test_data_lifecycle_postgres.py'),
])
def test_database_acceptance_is_required_not_silently_skipped(workflow, job, flag, suite):
    doc = yaml.safe_load((ROOT / '.github/workflows' / f'{workflow}.yml').read_text())
    job = doc['jobs'][job]
    assert job['env'][flag] == '1'
    run = next(step['run'] for step in job['steps'] if suite in step.get('run', ''))
    assert 'testcase' in run and "'skipped'" in run
    assert '--junitxml=' in run
    assert job['services']['postgres']['env']['POSTGRES_DB'].startswith('shakerscan_')
