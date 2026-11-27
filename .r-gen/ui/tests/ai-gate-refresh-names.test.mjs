import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

const page = readFileSync(new URL('../src/app/ai-gate/page.tsx', import.meta.url), 'utf8')

test('each refresh control on the AI Gate page says what it refreshes', () => {
  assert.match(page, /onClick=\{loadInventory\}[^>]*>\s*<RefreshCw[^>]*\/>\s*Refresh inventory\s*<\/button>/)
  assert.match(page, /onClick=\{loadTargets\}[^>]*>\s*<RefreshCw[^>]*\/>\s*Refresh targets\s*<\/button>/)
  assert.doesNotMatch(page, /<RefreshCw[^>]*\/>\s*Refresh\s*<\/button>/)
})
