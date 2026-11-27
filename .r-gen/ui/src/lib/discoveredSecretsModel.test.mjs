import assert from 'node:assert/strict'
import test from 'node:test'

import { SECRETS_PAGE_SIZE, groupSecrets, secretsCommand, shellQuote } from './discoveredSecretsModel.mjs'

const T = '00000000-0000-4000-8000-000000000410'
const O = '00000000-0000-4000-8000-000000000411'
const REF = 'secret://00000000-0000-4000-8000-000000000412'

test('the fallback command carries what the person chose', () => {
  assert.equal(secretsCommand('reveal', T, REF), `shakerscan secrets reveal ${T} ${REF}`)
  assert.equal(secretsCommand('grant', T, REF, { to: O }), `shakerscan secrets grant ${T} ${REF} --to ${O}`)
  assert.equal(secretsCommand('grant', T, REF), `shakerscan secrets grant ${T} ${REF} --to <target-id>`)
  assert.equal(secretsCommand('promote', T, REF, { name: 'Admin API token', authKind: 'bearer_token' }),
    `shakerscan secrets promote ${T} ${REF} --name 'Admin API token' --auth-kind bearer_token`)
  assert.equal(secretsCommand('promote', T, REF, { name: 'Key', authKind: 'api_key_header', headerName: 'X-Api-Key' }),
    `shakerscan secrets promote ${T} ${REF} --name Key --auth-kind api_key_header --header-name X-Api-Key`)
})

test('hostile text stays one inert shell word', () => {
  assert.equal(shellQuote("a'; rm -rf / #"), `'a'"'"'; rm -rf / #'`)
  assert.equal(shellQuote('$(id)`id`'), `'$(id)\`id\`'`)
  assert.equal(shellQuote(''), `''`)
  assert.equal(shellQuote('line\nbreak'), `'line\nbreak'`)
  const command = secretsCommand('promote', T, REF, { name: "x' && curl evil #", authKind: 'cookie' })
  assert.match(command, /--name 'x'"'"' && curl evil #' --auth-kind cookie$/)
})

test('secrets group by kind, field name and owner, in first-seen order', () => {
  const row = (kind, label, found_on = T) => ({ kind, label, found_on })
  const groups = groupSecrets([row('other', ''), row('password', 'DB_PASSWORD'), row('other', ''), row('other', '', O)])
  assert.deepEqual(groups.map(group => [group.kind, group.label, group.rows.length]),
    [['other', 'unnamed field', 2], ['password', 'DB_PASSWORD', 1], ['other', 'unnamed field', 1]])
  assert.equal(SECRETS_PAGE_SIZE, 10)
})
