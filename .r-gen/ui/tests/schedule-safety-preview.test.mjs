import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

const source = fs.readFileSync(new URL('../src/app/schedules/page.tsx', import.meta.url), 'utf8')

test('new schedules require an explicit target and disabled schedules have no next run', () => {
  assert.doesNotMatch(source, /Pre-select first target/)
  assert.doesNotMatch(source, /setFormTargetId\(data\.targets\[0\]\.id\)/)
  assert.match(source, /Paused — no next run/)
  assert.match(source, /disabled=\{\(!formTargetId && !editingSchedule\)/)
})

test('schedule form previews authority and explains jittered dispatch', () => {
  assert.match(source, /Effective execution policy/)
  assert.match(source, /Testing permission: Passive checks only/)
  assert.match(source, /Credentials: None/)
  assert.match(source, /Next jittered dispatch:/)
  assert.match(source, /Dispatch jitter ±/)
})
