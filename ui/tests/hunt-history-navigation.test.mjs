import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const hunt = readFileSync(path.join(root, 'src/app/hunt/page.tsx'), 'utf8')
const runView = ['HuntRunView.tsx', 'HuntTimeline.tsx', 'HuntDetails.tsx']
  .map((file) => readFileSync(path.join(root, 'src/components/hunt', file), 'utf8')).join('\n')
const device = readFileSync(path.join(root, 'src/app/devices/[id]/page.tsx'), 'utf8')

test('nothing of the removed legacy device-agent history remains in the UI', () => {
  // The legacy engine, its read and cancel routes and the history view built on them are gone.
  assert.ok(!existsSync(path.join(root, 'src/components/history/LegacyDeviceInvestigation.tsx')))
  assert.ok(!existsSync(path.join(root, 'src/app/devices/[id]/agent/page.tsx')))
  const api = readFileSync(path.join(root, 'src/lib/api.ts'), 'utf8')
  for (const source of [hunt, device, api]) {
    assert.ok(!source.includes('legacy_run'))
    assert.ok(!source.includes('/device-agent/'))
    assert.ok(!source.includes('DeviceAgentSession'))
  }
})

test('canonical Hunt history has durable exact-run links and audit details', () => {
  const runList = readFileSync(path.join(root, 'src/components/hunt/HuntRunList.tsx'), 'utf8')
  assert.match(hunt, /<HuntHistoryList \/>/)
  assert.match(hunt, /searchParams\.get\('run'\)/)
  assert.match(hunt, /getHuntV2\(runId\)/)
  assert.match(runList, /&run=\$\{encodeURIComponent\(hunt\.hunt_id\)\}/)
  assert.match(hunt, /<HuntRunView hunt=\{hunt\}/)
  assert.match(runView, /Run ID/)
  assert.match(runView, /<Link href="\/hunt" [^>]*>.*Hunts<\/Link>/)
  assert.match(runView, /Canonical receipts and content-safe outcomes/)
  assert.match(runView, /action\.result\.reference_ids/)
  assert.match(runView, /href=\{`\/scans\/\$\{scanId\}`\}/)
  assert.match(runView, /href=\{`\/findings\/\$\{findingId\}`\}/)
  assert.match(runView, /Audit identifiers/)
  // Each call shows what it was called with and why it failed, from the server's record export.
  assert.match(runView, /\/hunts\/\$\{pathSegment\(hunt\.hunt_id\)\}\/record/)
  assert.match(runView, /aria-label="Called with"/)
  assert.match(runView, /outcome\.errors\.map/)
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
  assert.match(runView, /HUNT_SESSION_NON_AUTONOMOUS_NOTICE/)
})

test('finding investigation starts a canonical Hunt, not a Research episode', async () => {
  const { readFileSync } = await import('node:fs')
  const path = await import('node:path')
  const { fileURLToPath } = await import('node:url')
  const uiRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
  const findingPage = readFileSync(
    path.join(uiRoot, 'src/app/findings/[id]/page.tsx'),
    'utf8',
  )
  const client = readFileSync(path.join(uiRoot, 'src/lib/api.ts'), 'utf8')

  // One investigation runtime owns this action.
  assert.match(findingPage, /startHuntV2Native\(/)
  assert.ok(!findingPage.includes('launchResearchEpisode'))
  assert.ok(!findingPage.includes('getResearchReadiness'))
  // It must land on canonical Hunt, not the legacy run page.
  assert.match(findingPage, /router\.push\(`\/hunt\?run=/)
  // The launch handler must not route to the legacy run page. A /deep-hunt link
  // may still appear elsewhere on the page as read-only campaign provenance.
  const launchHandler = findingPage.slice(
    findingPage.indexOf('async function handleAutonomousInvestigation'),
    findingPage.indexOf('const evidence = useMemo'),
  )
  assert.ok(launchHandler.length > 200)
  assert.ok(!launchHandler.includes('/deep-hunt/'))
  assert.ok(!launchHandler.includes('launchResearch'))
  // The finding stays the subject of the run.
  assert.match(findingPage, /Verify finding \$\{finding\.id\}/)
  // ...and the Hunt's seed: its briefing opens with this finding.
  assert.match(launchHandler, /seedFindingIds: \[finding\.id\]/)
  const huntClient = readFileSync(path.join(uiRoot, 'src/lib/huntV2.ts'), 'utf8')
  assert.match(huntClient, /seed_finding_ids: request\.seedFindingIds/)
  // The migrated client methods are gone, so nothing can start one by accident.
  assert.ok(!client.includes('export async function launchResearchEpisode'))
  assert.ok(!client.includes('export async function getResearchReadiness'))
})
