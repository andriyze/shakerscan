import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const uiRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const repoRoot = path.resolve(uiRoot, '..')
const page = readFileSync(path.join(uiRoot, 'src/app/credentials/page.tsx'), 'utf8')
const contract = readFileSync(path.join(repoRoot, 'api/runtime/credentials.py'), 'utf8')

function pythonFrozenset(source, name) {
  const match = source.match(new RegExp(`${name} = frozenset\\(\\{([^}]*)\\}\\)`))
  assert.ok(match, `${name} not found in api/runtime/credentials.py`)
  return match[1]
    .split(',')
    .map((item) => item.trim().replace(/^["']|["']$/g, ''))
    .filter(Boolean)
    .sort()
}

function typescriptList(source, name) {
  const match = source.match(new RegExp(`const ${name}: CredentialAuthKind\\[\\] = \\[([^\\]]*)\\]`))
  assert.ok(match, `${name} not found in the credentials page`)
  return match[1]
    .split(',')
    .map((item) => item.trim().replace(/^["']|["']$/g, ''))
    .filter(Boolean)
    .sort()
}

// The username/secret requirement was previously restated in four places with no shared
// constant and drifted. The backend now owns it; this asserts the client mirror stays equal
// so a newly added pair kind cannot be accepted by the API and rejected by the form.
test('client identity-pair kinds match the backend constant exactly', () => {
  assert.deepEqual(
    typescriptList(page, 'IDENTITY_PAIR_KINDS'),
    pythonFrozenset(contract, 'IDENTITY_PAIR_KINDS'),
  )
})

test('neither half of an identity pair is individually required', () => {
  // Username is required only for SSH; the secret only for non-pair kinds.
  assert.match(page, /if \(isSsh\(draft\.authKind\) && !draft\.username\.trim\(\)\)/)
  assert.match(page, /required=\{isSsh\(draft\.authKind\)\}/)
  assert.match(page, /required=\{!isIdentityPair\(draft\.authKind\)\}/)
})

test('a pair kind with neither half is rejected before submit', () => {
  assert.match(page, /if \(!draft\.username\.trim\(\) && !draft\.secret\.trim\(\)\)/)
  assert.match(page, /Enter a username, a secret, or both\./)
})

test('an empty half is omitted from the payload rather than sent blank', () => {
  assert.match(page, /if \(draft\.secret\.trim\(\)\) payload\.secret = draft\.secret/)
  assert.match(page, /if \(draft\.username\.trim\(\)\) payload\.username = draft\.username/)
})

test('the profile row reports which half a pair-kind profile holds', () => {
  assert.match(page, /function identityComposition\(/)
  assert.match(page, /configuration\.secret_configured/)
  for (const label of ['username \\+ secret', 'username only', 'secret only']) {
    assert.match(page, new RegExp(label))
  }
})
