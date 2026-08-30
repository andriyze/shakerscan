import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const hunt = readFileSync(path.join(root, 'src/app/hunt/page.tsx'), 'utf8')

test('Hunt exposes a real label and description for capability filtering', () => {
  assert.match(hunt, /label="Capability allowlist \(optional\)"/)
  assert.match(hunt, /hint="Leave empty for the server-defined capabilities allowed by this target and policy\."/)
  assert.doesNotMatch(hunt, /<Field label="Capability allowlist \(optional\)">\s*<div>/)
})

test('Hunt explains why it cannot start before privileged prerequisites are ready', () => {
  assert.match(hunt, /const startBlockedReason =/)
  assert.match(hunt, /Confirm that you are authorized to use the selected capabilities/)
  assert.match(hunt, /Create or paste a target-bound approval receipt/)
  assert.match(hunt, /disabled=\{Boolean\(startBlockedReason\)\}/)
  assert.match(hunt, /aria-describedby="hunt-start-guidance"/)
  assert.match(hunt, /<p role="alert"/)
})

test('Hunt presents compact adaptive methodologies without preloading the catalog', () => {
  assert.match(hunt, />Methodologies</)
  assert.match(hunt, /At most three suggestions are returned; methodology bodies are never preloaded\./)
  assert.match(hunt, /applying one does not grant or restrict the Hunt&apos;s existing capabilities/)
  assert.match(hunt, /suggestHuntSkills\(hunt\.hunt_id\)/)
  assert.doesNotMatch(hunt, /map\(.*methodology/i)
})
