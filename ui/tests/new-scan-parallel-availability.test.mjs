import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

const root = path.resolve(import.meta.dirname, '..')
const page = fs.readFileSync(path.join(root, 'src/app/scan/new/page.tsx'), 'utf8')

test('New Scan offers the parallel topology where the deployment advertises parallel_scan', () => {
  // A managed deployment can allow parallel scans without granting worker administration, so
  // the option follows the parallel_scan capability as well as worker_admin. A standalone
  // engine has no policy and keeps the full surface (featureEnabled returns true).
  assert.match(page, /\{\(featureEnabled\('parallel_scan'\) \|\| featureEnabled\('worker_admin'\)\) && <label className=\{`rounded-lg border p-4 \$\{topology === 'parallel'/)
  assert.match(page, /<input type="radio" name="scan-topology" value="parallel"/)
})
