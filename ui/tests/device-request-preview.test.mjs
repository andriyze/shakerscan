import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

const devicePage = fs.readFileSync(new URL('../src/app/devices/[id]/page.tsx', import.meta.url), 'utf8')
const apiClient = fs.readFileSync(new URL('../src/lib/api.ts', import.meta.url), 'utf8')

test('device collection previews are loaded from the detail endpoint on demand', () => {
  assert.match(devicePage, /getDeviceRequestCollection/)
  assert.match(devicePage, /onToggle=/)
  assert.match(devicePage, /Loading redacted requests/)
  assert.match(devicePage, /requestPreviews\[collection\.id\]\.requests\.map/)
  assert.match(apiClient, /request-collections\/\$\{encodeURIComponent\(collectionId\)\}/)
  assert.match(apiClient, /summary\.requests_preview/)
})

