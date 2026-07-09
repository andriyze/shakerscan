import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createRequire } from 'node:module'
import test from 'node:test'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const out = mkdtempSync(path.join(tmpdir(), 'principal-expectation-'))
execFileSync('npx', ['tsc', 'src/lib/principalExpectation.ts', '--module', 'commonjs', '--target', 'es2022', '--outDir', out, '--skipLibCheck'], { cwd: root })
const require = createRequire(import.meta.url)
const { buildPrincipalExpectationPayload } = require(path.join(out, 'principalExpectation.js'))
test.after(() => rmSync(out, { recursive: true, force: true }))

test('normalizes a principal expectation without inventing optional fields', () => {
  assert.deepEqual(buildPrincipalExpectationPayload({
    method: 'get', path: ' /api/orders/{id} ', principalId: 'principal-1', principalRole: '',
    tenantId: '', expectedAccess: 'deny', expectedHttpStatus: '403',
  }), {
    method: 'GET', path: '/api/orders/{id}', principal_id: 'principal-1', expected_access: 'deny',
    expected_http_status: 403, expectation_source: 'manual',
  })
})

test('rejects an invalid expected HTTP status', () => {
  assert.throws(() => buildPrincipalExpectationPayload({
    method: 'GET', path: '/api/orders', principalId: '', principalRole: 'admin', tenantId: '',
    expectedAccess: 'requires_role', expectedHttpStatus: '99',
  }), /100 to 599/)
})
