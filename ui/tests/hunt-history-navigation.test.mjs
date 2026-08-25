import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const hunt = readFileSync(path.join(root, 'src/app/hunt/page.tsx'), 'utf8')
const device = readFileSync(path.join(root, 'src/app/devices/[id]/page.tsx'), 'utf8')
const redirect = readFileSync(path.join(root, 'src/app/devices/[id]/agent/page.tsx'), 'utf8')

test('legacy device investigation links preserve and load the exact run', () => {
  assert.match(device, /legacy_run=\$\{encodeURIComponent\(run\.id\)\}/)
  assert.match(redirect, /query\.set\('legacy_run', run\)/)
  assert.match(hunt, /searchParams\.get\('legacy_run'\)/)
  assert.match(hunt, /getDeviceAgentSession\(legacyRunId\)/)
})

test('legacy history is clearly read-only and links its deterministic scans', () => {
  assert.match(device, /Legacy device-agent history/)
  assert.match(hunt, /Legacy device-agent run · read only/)
  assert.match(hunt, /href=\{`\/scans\/\$\{scanId\}`\}/)
  assert.match(hunt, /Open current Hunt launcher/)
})
