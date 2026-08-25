import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'


const root = path.resolve(import.meta.dirname, '..')
const api = fs.readFileSync(path.join(root, 'src/lib/api.ts'), 'utf8')
const layout = fs.readFileSync(path.join(root, 'src/app/layout.tsx'), 'utf8')
const runtime = fs.readFileSync(path.join(root, 'src/app/api/runtime-config/route.ts'), 'utf8')


test('installed UI loads its launcher-published API origin before client code', () => {
  assert.match(layout, /<script src="\/api\/runtime-config"/)
  assert.match(api, /window\.__SHAKERSCAN_API_URL__/)
  assert.match(runtime, /process\.env\.NEXT_PUBLIC_API_URL/)
  assert.match(runtime, /Cache-Control.*no-store/)
  assert.match(runtime, /parsed\.username \|\| parsed\.password/)
})
