import assert from 'node:assert/strict'
import test from 'node:test'

import { signatureAlgorithmLabel } from './tlsNames.mjs'

test('a signature algorithm has one name whichever way the scanner reported it', () => {
  // The same algorithm as an OID and as a library name.
  assert.equal(signatureAlgorithmLabel('1.2.840.10045.4.3.3'), 'ECDSA with SHA-384')
  assert.equal(signatureAlgorithmLabel('ecdsa-with-SHA384'), 'ECDSA with SHA-384')
  assert.equal(signatureAlgorithmLabel('1.2.840.113549.1.1.11'), 'RSA with SHA-256')
  assert.equal(signatureAlgorithmLabel('sha256WithRSAEncryption'), 'RSA with SHA-256')
  assert.equal(signatureAlgorithmLabel('1.3.101.112'), 'Ed25519')
})

test('a hash alone, an unknown OID and an unknown name stay honest', () => {
  assert.equal(signatureAlgorithmLabel('sha384'), 'SHA-384')
  assert.equal(signatureAlgorithmLabel('1.2.3.4.5'), 'Algorithm 1.2.3.4.5')
  assert.equal(signatureAlgorithmLabel('gost-2012'), 'gost-2012')
  assert.equal(signatureAlgorithmLabel(null), '')
  assert.equal(signatureAlgorithmLabel(''), '')
})
