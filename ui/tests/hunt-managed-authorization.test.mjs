import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const hunt = readFileSync(path.join(root, 'src/app/hunt/page.tsx'), 'utf8')
const capabilities = readFileSync(path.join(root, 'src/lib/workspaceCapabilities.ts'), 'utf8')

test('a managed deployment that authorizes targets itself is named, not guessed', () => {
  assert.match(capabilities, /export function managedTargetAuthorizationIsAutomatic\(\): boolean \{/)
  // Manual mode keeps the capability enabled; automatic reports it unavailable.
  assert.match(capabilities, /policy\.features\?\.target_authorization\?\.state === 'unavailable'/)
  // A standalone deployment has no policy and must never be treated as automatic.
  assert.match(capabilities, /if \(!policy \|\| policy\.schema !== 'shakerscan\.workspace-capabilities\/v1' \|\| policy\.mode !== 'managed'\) return false/)
})

test('Hunt reuses stored target authorization for selected credentials too', () => {
  assert.match(hunt, /target\.authorized_for_active_testing === true/)
  assert.match(hunt, /const effectiveAuthorization = authorizationConfirmed \|\| standingAuthorized/)
  assert.match(hunt, /const receiptRequired = privileged && !standingAuthorized/)
  assert.match(hunt, /privileged && !effectiveAuthorization/)
  assert.doesNotMatch(hunt, /selectedCredentialCount === 0 && managedTargetAuthorizationIsAutomatic/)
  assert.match(hunt, /authorizationConfirmed: effectiveAuthorization/)
})
