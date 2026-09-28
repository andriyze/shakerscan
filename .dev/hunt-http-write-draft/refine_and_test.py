#!/usr/bin/env python3
"""Temporary authoring support; never shipped in the implementation PR."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

root = Path(sys.argv[1]).resolve()
artifacts = Path(sys.argv[2]).resolve()
artifacts.mkdir(parents=True, exist_ok=True)


def replace_once(text: str, before: str, after: str) -> str:
    if text.count(before) != 1:
        raise ValueError(f"Expected one exact source anchor: {before[:100]!r}")
    return text.replace(before, after, 1)


if sys.argv[3] == 'refine':
    path = root / 'skills/web/31-edge-waf-and-origin-exposure-validation.md'
    text = path.read_text(encoding='utf-8')
    text = replace_once(text, 'version: 1.0.0\n', 'version: 1.0.1\n')
    text = replace_once(text,
        '- technique: method-and-content-type-switching\n  requires: a request capability carrying a body; http.request is limited to GET, HEAD and OPTIONS\n',
        '- technique: raw-body-and-multipart-content-type-switching\n  requires: a raw-byte or multipart request capability; authorized JSON/form writes use http.request\n')
    text = replace_once(text, '- preflight-and-verb-surface\n',
        '- preflight-and-verb-surface\n- authorized-json-and-form-method-comparison\n')
    text = replace_once(text,
        "The remaining method work — `POST`, `PUT`, `DELETE`, and the `X-HTTP-Method-Override` and `_method`\nconventions — is deferred; this runtime's `http.request` carries no body.",
        "For an explicitly authorized state-changing investigation, `http.request` also supports\n`POST`, `PUT`, `PATCH` and `DELETE` with one `json_body` or `form_body`. Read the live schema\nand use the Hunt's saved state-changing authority; do not request a new authorization per verb.\nCompare only endpoints and effects the operator placed in scope, and retain the actual method,\nbody kind and response evidence. Accepted method-override headers and form fields may be tested\nthrough that same path; verify which headers the runtime actually sent. Arbitrary raw encodings,\nmultipart uploads and synchronized exchanges still require their own implemented transport.")
    path.write_text(text, encoding='utf-8')
    raise SystemExit(0)

spec = importlib.util.spec_from_file_location('repository_test_runner', root / 'scripts/run_complete_python_suite.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
files = [
    'tests/test_hunt_http_write_contract.py',
    'tests/test_hunt_http_write_integration.py',
    'tests/test_hunt_http_capability.py',
    'tests/test_hunt_standing_authorization.py',
    'tests/test_hunt_start_adjustments.py',
    'tests/test_hunt_start_contract.py',
    'tests/test_hunt_device_parity.py',
    'tests/test_hunt_semantic_registry.py',
    'tests/test_hunt_redirects.py',
    'tests/test_hunt_session_service_authority.py',
    'tests/test_hunt_operator_execution.py',
    'tests/test_hunt_service_execution.py',
    'tests/test_hunt_device_traffic.py',
]
results = []
for filename in files:
    path = root / filename
    styles = runner._package_import_styles(path, root)
    if styles == {'package', 'compatibility'}:
        raise ValueError(f'Mixed import layouts in {filename}')
    env = runner._environment(root, package_native='package' in styles)
    report = artifacts / (path.stem + '.xml')
    process = subprocess.run(
        [sys.executable, '-m', 'pytest', '-q', '-p', 'no:cacheprovider', filename, f'--junitxml={report}'],
        cwd=root, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=240,
    )
    print(f'\n### {filename} [{sorted(styles)}] ###\n{process.stdout}', flush=True)
    (artifacts / (path.stem + '.txt')).write_text(process.stdout, encoding='utf-8')
    results.append({'file': filename, 'exit_code': process.returncode, 'import_styles': sorted(styles)})
(artifacts / 'isolated-results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
runner.merge_junit_reports(tuple(artifacts / (Path(p).stem + '.xml') for p in files), artifacts / 'combined-tests.xml')
raise SystemExit(1 if any(row['exit_code'] for row in results) else 0)
