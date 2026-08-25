import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'


const root = path.resolve(import.meta.dirname, '..')
const api = fs.readFileSync(path.join(root, 'src/lib/api.ts'), 'utf8')
const apiConfig = fs.readFileSync(path.join(root, 'src/lib/apiConfig.ts'), 'utf8')
const layout = fs.readFileSync(path.join(root, 'src/app/layout.tsx'), 'utf8')
const runtime = fs.readFileSync(path.join(root, 'src/app/api/runtime-config/route.ts'), 'utf8')
const aiGate = fs.readFileSync(path.join(root, 'src/app/ai-gate/page.tsx'), 'utf8')


test('installed UI loads its launcher-published API origin before client code', () => {
  assert.match(layout, /<script src="\/api\/runtime-config"/)
  assert.match(api, /export \{ API_URL, getApiUrl \} from '.\/apiConfig'/)
  assert.match(apiConfig, /window\.__SHAKERSCAN_API_URL__/)
  assert.match(runtime, /process\.env\.NEXT_PUBLIC_API_URL/)
  assert.match(runtime, /Cache-Control.*no-store/)
  assert.match(runtime, /parsed\.username \|\| parsed\.password/)
})

test('AI Gate export links use the launcher runtime API origin', () => {
  assert.match(aiGate, /getApiUrl/)
  assert.match(aiGate, /setRuntimeApiUrl\(getApiUrl\(\)\)/)
  assert.doesNotMatch(aiGate, /process\.env\.NEXT_PUBLIC_API_URL/)
  assert.doesNotMatch(aiGate, /http:\/\/localhost:8080/)
  assert.doesNotMatch(aiGate, /const API_URL/)
})
