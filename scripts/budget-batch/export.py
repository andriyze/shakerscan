"""Publish only verified Git blobs, not commits, branches, releases or deployments."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import urllib.request
import xml.etree.ElementTree as ET

OUT = Path('/tmp/budget-results')
EXPECTED = '5dc4a8d266a0c28b3a8bfb7571c44ef221b1d4a4'
PARENT = '76653d344228eed9ce1cdfe59786a230ce119eb0'

def git(*args):
    return subprocess.check_output(['git', *args])

assert git('write-tree').decode().strip() == EXPECTED
subprocess.run(['git', 'diff', '--exit-code'], check=True)
summary = {}
for name in ('native-nse.xml', 'budget-postgres.xml', 'v2-full-python.xml'):
    cases = list(ET.parse(OUT / name).getroot().iter('testcase'))
    assert cases, name
    assert not any(c.find('failure') is not None or c.find('error') is not None for c in cases), name
    skipped = sum(c.find('skipped') is not None for c in cases)
    if name != 'v2-full-python.xml':
        assert skipped == 0, name
    summary[name] = {'passed': len(cases)-skipped, 'skipped': skipped, 'failures': 0, 'errors': 0}
ui = json.loads((OUT / 'browser-results.json').read_text())['stats']
assert ui['expected'] >= 8 and not (ui['unexpected'] or ui['flaky'] or ui['skipped']), ui
summary['budget-browser'] = ui
entries = []
for raw in git('diff', '--name-only', '-z', PARENT, 'HEAD').split(b'\0'):
    if not raw:
        continue
    path = raw.decode()
    mode, kind, sha = git('ls-tree', 'HEAD', '--', path).decode().split('\t', 1)[0].split()
    assert kind == 'blob' and mode in ('100644', '100755'), path
    data = Path(path).read_bytes()
    assert hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == sha
    request = urllib.request.Request(
        'https://api.github.com/repos/' + os.environ['GITHUB_REPOSITORY'] + '/git/blobs',
        data=json.dumps({'content': base64.b64encode(data).decode(), 'encoding': 'base64'}).encode(),
        headers={'Authorization': 'Bearer ' + os.environ['EXPORT_TOKEN'],
                 'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json'}, method='POST',
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        result = json.load(response)
    assert result['sha'] == sha, (path, result)
    entries.append({'path': path, 'mode': mode, 'type': kind, 'sha': sha})
record = {'parent': PARENT, 'product_tree': EXPECTED, 'tests': summary, 'tree_elements': entries}
(OUT / 'verified-tree.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps({'product_tree': EXPECTED, 'files': len(entries), 'tests': summary}, indent=2))
