"""One-use reviewed maintenance patch. Source-pinned; no live scans or operator data I/O.

The payload is a gzip-compressed unified Git diff in immutable repository Git blobs.
Decode it with Python gzip/base64 or read the resulting commit for the full source diff.
This script verifies every original file, applies atomically with git apply, and removes
itself. It never force-pushes or changes another branch.
"""
from pathlib import Path
import base64, gzip, hashlib, json, os, subprocess, urllib.request

EXPECTED = {'.dockerignore': '808d2a962f9c4babb2a55d5a39f6f8059d43eebd3094c6b088e4624ea2a89f64', '.github/workflows/data-lifecycle.yml': None, '.gitignore': '356be38f591cc7b1e00d577a2d8e77f15c3796b314a1dbebd7e8d28b2449b0e6', 'api/api.py': '0d4ce36670d2711708ba0b63be79e313da495d27f0b163cfa4be993cac58e9cc', 'api/data_lifecycle/__init__.py': None, 'api/data_lifecycle/inventory.py': None, 'api/data_lifecycle/router.py': None, 'api/data_lifecycle/service.py': None, 'api/finding_routes/router.py': '307ac82425efd73470c87bd7ff14e322e5d3266a4cc193320109b3990ea6b711', 'api/targets/router.py': '82a7d3fb85b2459a12db64a9603c09429efe2fd05f6e7998e673dc495bdf5167', 'config/v2_surface_disposition.yaml': '70dd2a2416bc6d088b788d59578bb4fa1608908be156d53080710160d403e65b', 'docs/INTERACTIVE_SESSIONS_GUIDE.md': '8c6d9e2338b86f48b5a49e0fea630a4e8ea68908c79d3320030d3226e79a4448', 'docs/archive/AUDIT-2026-07.md': 'e404c8ee9865c3dfbcb5117a3d1adc4c5d00769f61875558cdd6f6802a475723', 'docs/archive/README.md': '8cda760e7849b22976ce616a41e640290a7c36087a0a4b5c2fac0422f0aea303', 'docs/archive/ai-native-refactor-audit.md': 'a4036329e90bec4ecaae7ac3e7c64c36bfdb438bbc5d7bd1dccdca6dd91fdd23', 'docs/archive/audit-evidence-2026-07.md': '6eeb84b1435473e780660f1476273bb796bd9a424f02594ddb9a51dabdc8c346', 'docs/archive/data-lifecycle-retention-and-portability-plan.md': '741355c537512a23cfd06083dd8e25813e0ade45a15e04701ff78f06cb7250d8', 'docs/archive/deep-hunt-architecture.md': '9f985099ed00058c8fc9c6f9ff17a6cf53c4cf2685fe220e89a2d3932397c076', 'docs/archive/interactive-sessions-guide.md': '5d91e2a053ccbd9e79c93d0195226d887481990a8723ead8ed637c0d8f73e2ce', 'docs/archive/model-intake-security-review-roadmap.md': '30e3efae1ca8e7795926f8f81b47af73a3fbb004ac28f68c6536184e239149e1', 'docs/archive/proposed-next-steps-2026-07.md': '21d27a46464825f1e25484d4f2bf86c042458ce26ebd3003313c7c54decd563e', 'docs/archive/smart-scan-policy.md': '138037a884f7b277d3270dec970ede6318da3f790fa939c1dbf9fdfddc3a39f4', 'docs/archive/source-assisted-scanning-and-microvm-isolation-proposal.md': '821f80a104581208b5dd70552c34a2bb464905ca949e85c5b36fda892411cdbe', 'docs/archive/v2-re-audit-2026-08-20.md': 'cab918ccc80474f06d653741114b1bf6379713e7e8d45c9cbaa46ddf8d71437f', 'docs/data-lifecycle-retention-and-portability-plan.md': '58c86ec0eba68103f0ea70467fcefbd934c447e1ce100b332f85562d5964d69c', 'docs/functionality-reference.md': 'a29375e158b07036a2316ef840393a0a6632c4614c6fc086fb6e72e7eca0a4c9', 'docs/model-intake-security-review-roadmap.md': 'fc78c651c2a1c377d58e97a81fe7cdf54a1ee0f7eb0945a6e2aaba2f4c5ddb11', 'docs/proposed-next-steps.md': 'af39f11a4070200a5ff18cf131bd695609fc9faac7932b2eb5c14ad8acf207b5', 'scripts/check_public_repo_hygiene.py': None, 'tests/test_data_exposure.py': 'b6a9de79316c48de9d76ccfc1171bafaf1a245629e77c51fbc32a43ca587f231', 'tests/test_data_lifecycle.py': None, 'tests/test_data_lifecycle_postgres.py': None, 'tests/test_public_repo_hygiene.py': None, 'ui/src/app/findings/[id]/page.tsx': '82f2b11807ad878a69bc14e20cffe13bf3494ca9c05783d33d0ffb22cf2a4c98', 'ui/src/app/findings/page.tsx': '8bba3a271c76019620d008aa646acb10f10474fcd709a7d7cbfdc1084fef81da', 'ui/src/app/targets/page.tsx': '977ce7810a11343880db1db14ce4df3a2a37d5b87a69a22c7c66f330d2af4326', 'ui/src/components/lifecycle/DeleteRecordsButton.tsx': None, 'ui/src/components/ui/ConfirmDialog.tsx': 'e556426fb07909f49404b6778bd7e6d2cfcc309d032a6629d85060fb828317db', 'ui/src/lib/api.ts': 'd7096294d8a64d137cda8da84683f100b408b933b469c9a640fec47cfc5daf46', 'ui/src/lib/dataLifecycle.ts': None, 'ui/tests/browser/data-lifecycle.spec.ts': None}
DELETED = ['docs/archive/AUDIT-2026-07.md', 'docs/archive/ai-native-refactor-audit.md', 'docs/archive/audit-evidence-2026-07.md', 'docs/archive/data-lifecycle-retention-and-portability-plan.md', 'docs/archive/deep-hunt-architecture.md', 'docs/archive/interactive-sessions-guide.md', 'docs/archive/model-intake-security-review-roadmap.md', 'docs/archive/proposed-next-steps-2026-07.md', 'docs/archive/smart-scan-policy.md', 'docs/archive/source-assisted-scanning-and-microvm-isolation-proposal.md', 'docs/archive/v2-re-audit-2026-08-20.md']
PAYLOAD_BLOBS = ['a61147997e6af5af2ed95071703ddd671766b73b', '1627815adf0f9baec1903082792bebdb629bab75', '00c3852b0083cbe8ade6830487fdfd8a278fe1b0', '5703926c8a75ca2d4540f1726db1124731fa3364', '41a56473c1b83f65634736cc0661ca05144664a3', 'f34f93a67ca05a262265a17b18b0fcf86a33965f', '6fac2be1adfa5f3ecce395c0d0e07acbc24dd6ec', '1b753cf3580ed75d21bcef0beb3f8b9dc3a7383d']
PATCH_SHA256 = '359671e42c724019d68ba74850028e1c84d56dd36b7fbc77fe68581f41ce24df'
root = Path(__file__).resolve().parents[1]
assert os.environ.get('GITHUB_REF') == 'refs/heads/2.3.1', 'Maintenance is branch-scoped'
for name, expected in EXPECTED.items():
    path = root / name
    assert not path.is_symlink(), f'Refusing symlink: {name}'
    actual = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
    assert actual == expected, f'Source changed: {name}; reconcile instead of overwriting'
parts = []
for sha in PAYLOAD_BLOBS:
    request = urllib.request.Request(
        f'https://api.github.com/repos/andriyze/shakerscan/git/blobs/{sha}',
        headers={'Authorization': 'Bearer ' + os.environ['GH_TOKEN'],
                 'Accept': 'application/vnd.github+json', 'User-Agent': 'shakerscan-maintenance'})
    with urllib.request.urlopen(request, timeout=30) as response:
        blob = json.load(response)
    content = base64.b64decode(blob['content'])
    digest = hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest()
    assert digest == sha, 'Git blob integrity check failed'
    parts.append(content)
patch = gzip.decompress(base64.b64decode(b''.join(parts)))
assert hashlib.sha256(patch).hexdigest() == PATCH_SHA256, 'Reviewed patch digest mismatch'
subprocess.run(['git', 'apply', '--check', '-'], cwd=root, input=patch, check=True)
subprocess.run(['git', 'apply', '-'], cwd=root, input=patch, check=True)
for name in DELETED:
    (root / name).unlink()
# Workflow publication is performed by the connector, not by the Actions token.
(root / '.github/workflows/data-lifecycle.yml').unlink()
Path(__file__).unlink()
allowed = sorted(set(EXPECTED) | {'scripts/_maintenance_2_3_1.py', 'docs/generated/public-openapi-manifest.json', 'ui/src/lib/publicApi.generated.ts', 'docs/functionality-reference.md'})
Path('/tmp/shakerscan-reviewed-paths.json').write_text(json.dumps(allowed))
print(f'Applied reviewed maintenance patch: {len(EXPECTED)} paths')
