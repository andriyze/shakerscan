"""Temporary, idempotent source transformations for PR #295. Not shipped in the final tree."""
from pathlib import Path
import hashlib


def checked(path, expected):
    data = Path(path).read_bytes()
    blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
    if blob != expected:
        raise SystemExit(f'Unreviewed source at {path}: {blob}')
    return data.decode()


helper = Path('ui/src/lib/deviceScanPresentation.mjs')
if "from './networkScanCoverage.mjs'" not in helper.read_text():
    source = checked(helper, 'b7613f3870099cb23dd6e8d1e3a8161da3d6f159')
    start = source.index('const TCP_SCOPE_LABELS = {')
    helper.write_text(source[:start] + "export { devicePortCoverage, deviceServiceDetails } from './networkScanCoverage.mjs'\n")

page = Path('ui/src/app/devices/[id]/page.tsx')
if '<DevicePortCoverage coverage={portCoverage}' not in page.read_text():
    source = checked(page, '630f22ce2993410e45441976dec9e2bb1d8b2b24')
    source = source.replace("import { RetireDeviceButton } from '@/components/RetireDeviceButton'", "import { RetireDeviceButton } from '@/components/RetireDeviceButton'\nimport { DevicePortCoverage } from '@/components/DevicePortCoverage'", 1)
    start = source.index('      {portCoverage && (')
    end = source.index('      {selectedScanId && (', start)
    page.write_text(source[:start] + '      {portCoverage && <DevicePortCoverage coverage={portCoverage} />}\n\n' + source[end:])

tests = Path('ui/tests/device-port-coverage.test.mjs')
if 'overlapping batch counters are not a unique examination total' not in tests.read_text():
    source = checked(tests, '3c833c1b5460471786db87cf72f72cf8b7d12770')
    source = source.replace('without a classification the remainder is "not open", never closed', 'overlapping batch counters are not a unique examination total')
    source = source.replace('[130, 3, 127, null, null]', '[null, 3, null, null, null]')
    source = source.replace("      tcp_scope: 'all_tcp',", "      tcp_scope: 'all_tcp',\n      tcp_discovery_complete: true,", 1)
    source = source.replace('coverage.fingerprint.identified, coverage.fingerprint.withVersion', 'coverage.identification.identified, coverage.identification.withVersion')
    tests.write_text(source)
