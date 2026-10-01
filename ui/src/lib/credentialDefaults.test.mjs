import assert from 'node:assert/strict'
import test from 'node:test'

import { defaultHuntCredentialIds, preferredCredentialId } from './credentialDefaults.ts'

const credential = (id, slot, extra = {}) => ({ id, name: id, principal_slot: slot, execution_compatible: true, ...extra })

test('a target starts with its own credential before one shared with it', () => {
  const profiles = [credential('b-shared', 'primary', { shared: true }), credential('z-own', 'primary')]
  assert.equal(preferredCredentialId(profiles, (p) => p.principal_slot === 'primary'), 'z-own')
})

test('inactive, incompatible and excluded credentials are never chosen', () => {
  const profiles = [credential('expired', 'primary', { execution_compatible: false }), credential('ok', 'primary')]
  assert.equal(preferredCredentialId(profiles, () => true), 'ok')
  assert.equal(preferredCredentialId(profiles, () => true, ['ok']), '')
  assert.equal(preferredCredentialId([], () => true), '')
})

test('a Hunt fills primary, secondary and service, and never an SSH identity', () => {
  const ids = defaultHuntCredentialIds([
    credential('admin', 'primary'), credential('reader', 'secondary'), credential('robot', 'service'),
    credential('root', 'ssh'),
  ])
  assert.deepEqual(ids, { primary: 'admin', secondary: 'reader', service: 'robot', ssh: '' })
})
