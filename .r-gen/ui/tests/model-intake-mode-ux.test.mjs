import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const page = readFileSync(path.join(root, 'src/app/model-intake/page.tsx'), 'utf8')

test('Model Intake exposes its workflow modes as a single-choice control', () => {
  assert.match(page, /role="group"[^>]+aria-label="Model Intake workflow mode"/)
  assert.match(page, /aria-pressed=\{workflowMode === 'automatic'\}/)
  assert.match(page, /aria-pressed=\{workflowMode === 'advanced'\}/)
})
