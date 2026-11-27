import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

const root = path.resolve(import.meta.dirname, '..')
const api = fs.readFileSync(path.join(root, 'src/lib/api.ts'), 'utf8')
const page = fs.readFileSync(path.join(root, 'src/app/devices/[id]/page.tsx'), 'utf8')

test('device collection summaries tolerate list responses without request previews', () => {
  assert.match(api, /requests: Array\.isArray\(collection\.summary\?\.requests\) \? collection\.summary\.requests : \[\]/)
  assert.match(api, /methods: collection\.summary\?\.methods \|\| \{\}/)
  assert.match(api, /port_hints: Array\.isArray/)
  assert.match(page, /onToggle=\{\(event\) => \{ if \(event\.currentTarget\.open\) void loadRequestPreview\(collection\.id\) \}\}/)
  assert.match(page, /requestPreviews\[collection\.id\]\.requests\.map/)
})

test('device detail and list share the canonical readiness gate', () => {
  assert.match(page, /getDeviceReadiness\(\)/)
  assert.match(page, /setWorkerReady\(readiness\.enabled && readiness\.status === 'ready'\)/)
  assert.match(page, /disabled=\{!workerReady\}/)
  assert.match(page, /if \(!workerReady\) \{/)
})
