import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const card = readFileSync(path.join(root, 'src/components/TargetPostureCard.tsx'), 'utf8')
const detail = readFileSync(path.join(root, 'src/app/scans/[id]/page.tsx'), 'utf8')
const api = readFileSync(path.join(root, 'src/lib/api.ts'), 'utf8')

test('the scan page shows target posture with per-section provenance', () => {
  assert.match(detail, /getTargetPosture\(postureTargetId, scan\?\.id \? String\(scan\.id\) : undefined\)/)
  assert.match(detail, /<TargetPostureCard posture=\{targetPosture\} currentScanId=\{String\(scan\.id\)\}/)
  assert.match(card, /observed in this scan/)
  assert.match(card, /from another scan/)
  assert.match(card, /not examined yet/)
  for (const title of ['Security headers', 'TLS', 'DNS', 'Network and hosting']) {
    assert.match(card, new RegExp(title))
  }
})

test('absence is stated per section instead of implied', () => {
  assert.match(card, /No completed scan has examined TLS for this target/)
  assert.match(card, /Plain-HTTP targets have no TLS posture/)
  assert.match(card, /Informational only; never scored/)
})

test('the API client reads the posture route and surfaces server errors', () => {
  assert.match(api, /export async function getTargetPosture\(targetId: string, scanId\?: string\): Promise<TargetPosture>/)
  assert.match(api, /\/targets\/\$\{encodeURIComponent\(targetId\)\}\/posture/)
  assert.match(api, /getApiErrorMessage\(res, 'Failed to fetch target posture'\)/)
})
