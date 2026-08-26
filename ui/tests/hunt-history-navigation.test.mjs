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

test('canonical Hunt history has durable exact-run links and audit details', () => {
  assert.match(hunt, /listHuntsV2\(\{ targetId: selectedChoice\.id, limit: 12 \}\)/)
  assert.match(hunt, /searchParams\.get\('run'\)/)
  assert.match(hunt, /getHuntV2\(runId\)/)
  assert.match(hunt, /Recent Hunts for this target/)
  assert.match(hunt, /&run=\$\{encodeURIComponent\(run\.hunt_id\)\}/)
  assert.match(hunt, /Run ID/)
  assert.match(hunt, /Back to launcher and history/)
  assert.match(hunt, /Capability action ledger/)
  assert.match(hunt, /Canonical receipts and content-safe outcomes/)
  assert.match(hunt, /action\.result\.reference_ids/)
  assert.match(hunt, /href=\{`\/scans\/\$\{scanId\}`\}/)
  assert.match(hunt, /href=\{`\/findings\/\$\{findingId\}`\}/)
  assert.match(hunt, /Audit identifiers/)
})

test('a newly started Hunt immediately becomes a reload-safe exact-run URL', () => {
  assert.match(hunt, /window\.history\.pushState\(/)
  assert.match(
    hunt,
    /`\/hunt\?target=\$\{encodeURIComponent\(created\.target_id\)\}&run=\$\{encodeURIComponent\(created\.hunt_id\)\}`/,
  )
})

test('open Hunt sessions do not imply background network execution', async () => {
  const { huntStatusLabel, HUNT_SESSION_NON_AUTONOMOUS_NOTICE } = await import(
    '../src/lib/labels.ts'
  )
  // "active" must not read as "the system is working on it".
  assert.equal(huntStatusLabel('active'), 'agent session open')
  assert.doesNotMatch(huntStatusLabel('active'), /running|scanning|in progress/i)
  assert.equal(huntStatusLabel('stopped_by_user'), 'stopped by user')
  // The notice must keep saying the run is not autonomous and makes no
  // background traffic, however the sentence is worded.
  assert.match(HUNT_SESSION_NON_AUTONOMOUS_NOTICE, /not investigate autonomously/)
  assert.match(HUNT_SESSION_NON_AUTONOMOUS_NOTICE, /not running background traffic/)
  assert.match(HUNT_SESSION_NON_AUTONOMOUS_NOTICE, /only when your coding agent submits/)
  assert.match(hunt, /HUNT_SESSION_NON_AUTONOMOUS_NOTICE/)
})
