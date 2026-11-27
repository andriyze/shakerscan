import assert from 'node:assert/strict'
import test from 'node:test'
import { createRequire } from 'node:module'


const require = createRequire(import.meta.url)
const config = require('../next.config.js')


test('production responses use one fail-closed browser security policy', async () => {
  assert.equal(config.poweredByHeader, false)
  const rules = await config.headers()
  assert.equal(rules.length, 1)
  assert.equal(rules[0].source, '/:path*')
  const headers = Object.fromEntries(
    rules[0].headers.map(({ key, value }) => [key.toLowerCase(), value]),
  )
  assert.equal(headers['x-content-type-options'], 'nosniff')
  assert.equal(headers['x-frame-options'], 'DENY')
  assert.equal(headers['referrer-policy'], 'strict-origin-when-cross-origin')
  assert.match(headers['permissions-policy'], /camera=\(\)/)
  assert.match(headers['content-security-policy'], /frame-ancestors 'none'/)
  assert.match(headers['content-security-policy'], /object-src 'none'/)
  assert.match(headers['content-security-policy'], /connect-src 'self' http: https: ws: wss:/)
})
