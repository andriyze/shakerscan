import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const read = (file) => readFileSync(path.join(root, file), 'utf8')

function sources(dir) {
  return readdirSync(path.join(root, dir), { withFileTypes: true }).flatMap((entry) => {
    const rel = path.join(dir, entry.name)
    if (entry.isDirectory()) return sources(rel)
    return /\.(tsx?|mjs)$/.test(entry.name) && !/\.test\./.test(entry.name) ? [rel] : []
  })
}

// A raw setInterval keeps a poll running in a hidden tab, overlaps a slow answer and ignores
// Retry-After. Network polls go through usePoll; only these local clocks (no request) remain.
const CLOCK_TICKERS = new Map([
  ['src/app/deep-hunt/runs/[id]/page.tsx', /setInterval\(\(\) => setNow\(Date\.now\(\)\), 1000\)/],
  ['src/app/scans/page.tsx', /setInterval\(\(\) => setDurationTickMs\(Date\.now\(\)\), LIVE_DURATION_REFRESH_MS\)/],
  ['src/components/ui/LastUpdated.tsx', /setInterval\(\(\) => setTick\(t => t \+ 1\), 10000\)/],
])

test('no page polls the API with a raw setInterval', () => {
  const offenders = []
  for (const file of sources('src')) {
    const text = read(file)
    const count = (text.match(/setInterval\(/g) || []).length
    if (!count) continue
    const clock = CLOCK_TICKERS.get(file)
    if (count === 1 && clock?.test(text)) continue
    offenders.push(`${file} (${count})`)
  }
  assert.deepEqual(offenders, [])
})

test('converted polls keep their pace and stop when nothing is live', () => {
  const finding = read('src/app/findings/[id]/page.tsx')
  assert.match(finding, /usePoll\(fetchFinding, \{ intervalMs: 4000, live: hasPendingRetest/)

  const devices = read('src/app/devices/page.tsx')
  assert.match(devices, /READINESS_LIVE_REFRESH_MS = 3_000/)
  assert.match(devices, /live: !workerReady/)

  const device = read('src/app/devices/[id]/page.tsx')
  assert.match(device, /usePoll\(load, \{ intervalMs: DEVICE_LIVE_REFRESH_MS/)
  assert.match(device, /intervalMs: 5_000, live: selectedScanLive/)
  assert.match(device, /intervalMs: 3_000, live: activityLive/)
  assert.doesNotMatch(device, /setTimeout\(refresh/)

  const deepHunt = read('src/app/deep-hunt/runs/[id]/page.tsx')
  assert.match(deepHunt, /\{ intervalMs: 2500, live: runLive \}/)
  assert.match(deepHunt, /intervalMs: 15000, live: runLive, enabled: Boolean\(campaignId\)/)
  assert.match(deepHunt, /if \(!runLive\) return/)

  const schedules = read('src/app/schedules/page.tsx')
  assert.match(schedules, /intervalMs: SCHEDULES_REFRESH_MS, live: anyScheduleEnabled/)

  const timeline = read('src/app/timeline/page.tsx')
  assert.match(timeline, /idleIntervalMs: IDLE_REFRESH_MS, live: timelineLive/)
  assert.match(timeline, /onRefresh=\{timelinePoll\.refresh\}/)

  const intake = read('src/app/model-intake/page.tsx')
  assert.match(intake, /usePoll\(loadAutomaticReviews, \{ intervalMs: 5_000, enabled: automaticReviewRunning/)

  const inventory = read('src/components/targets/TargetInventory.tsx')
  assert.match(inventory, /enabled: scanningNow/)
})
