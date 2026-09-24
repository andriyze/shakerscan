"""Publish only verified Git blobs for connector-side atomic tree assembly.

Temporary batch validation helper. It never moves a ref, merges, releases, or deploys.
The checked-in plain-text patches are applied to an exact base and the complete product
tree must equal the locally tested tree before any Git objects are uploaded.
"""
from __future__ import annotations
import base64
import json
import os
from pathlib import Path
import subprocess
import urllib.request

BASE = '2e67d1926d2b35767990c5db8d056738767034da'
EXPECTED = 'bbc97da32d9649c0fc5f84f89e43d49a291c34c7'
REPO = 'andriyze/shakerscan'

def git(*args):
    return subprocess.check_output(['git', *args], text=True).strip()

assert os.environ['GITHUB_REPOSITORY'] == REPO
assert os.environ['GITHUB_REF'] == 'refs/heads/feat/hunt-operator-workflows'
assert git('write-tree') == EXPECTED
subprocess.run(['git', 'diff', '--exit-code'], check=True)
paths = git('diff', '--cached', '--name-only', BASE).splitlines()
entries = []
for path in paths:
    mode_sha, indexed_path = git('ls-files', '--stage', '--', path).split('\t', 1)
    mode, expected_sha, stage = mode_sha.split()
    assert stage == '0' and indexed_path == path and mode in {'100644', '100755'}
    assert not path.startswith('.github/operator-batch/')
    data = Path(path).read_bytes()
    request = urllib.request.Request(
        f'https://api.github.com/repos/{REPO}/git/blobs',
        data=json.dumps({'content': base64.b64encode(data).decode(), 'encoding': 'base64'}).encode(),
        headers={'Authorization': 'Bearer ' + os.environ['GH_TOKEN'],
                 'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json',
                 'X-GitHub-Api-Version': '2022-11-28'}, method='POST')
    with urllib.request.urlopen(request, timeout=30) as response:
        sha = json.load(response)['sha']
    if sha != expected_sha:
        raise RuntimeError(f'Git blob mismatch for {path}')
    entries.append({'path': path, 'mode': mode, 'type': 'blob', 'sha': sha})
result = {'base': BASE, 'expected_tree': EXPECTED, 'entries': entries}
Path('/tmp/operator-validation/blob-index.json').write_text(json.dumps(result, indent=2) + '\n')
print('VERIFIED_BLOB_INDEX=' + json.dumps(result))
