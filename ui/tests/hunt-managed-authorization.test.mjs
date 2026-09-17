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

test('Hunt does not demand a receipt an operator has no way to create', () => {
  // The routes that mint a receipt (/arsenal/scope/preview, /arsenal/approvals) are
  // administrator-only under the gateway, so requiring one from an operator on a fresh
  // target left the documented active-Hunt journey with no way through.
  assert.match(hunt, /const receiptRequired = privileged/)
  assert.match(hunt, /&& !\(selectedCredentialCount === 0 && managedTargetAuthorizationIsAutomatic\(\)\)/)
  // Every gate that previously keyed on `privileged` now keys on the narrower condition.
  assert.match(hunt, /: receiptRequired && !approvalReceipt\.trim\(\)/)
  assert.match(hunt, /if \(receiptRequired && !approvalReceipt\.trim\(\)\) \{/)
  assert.match(hunt, /required=\{receiptRequired\}/)
  assert.doesNotMatch(hunt, /privileged && !approvalReceipt\.trim\(\)/)
})

test('credential use still requires its own target-bound approval receipt', () => {
  // selectedCredentialCount === 0 is part of the relaxation, so any selected credential
  // keeps the receipt mandatory even under automatic target authorization.
  assert.match(hunt, /selectedCredentialCount === 0 && managedTargetAuthorizationIsAutomatic\(\)/)
  assert.match(hunt, /Credential use requires a target-bound approval receipt\./)
  // The separate authorization confirmation is untouched.
  assert.match(hunt, /if \(privileged && !authorizationConfirmed\) \{/)
})
