import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

const component = fs.readFileSync(new URL('../src/components/ApprovalReceiptField.tsx', import.meta.url), 'utf8')
const scan = fs.readFileSync(new URL('../src/app/scan/new/page.tsx', import.meta.url), 'utf8')
const hunt = fs.readFileSync(new URL('../src/app/hunt/page.tsx', import.meta.url), 'utf8')
const api = fs.readFileSync(new URL('../src/lib/api.ts', import.meta.url), 'utf8')

test('core privileged workflows create target-bound approval receipts in place', () => {
  assert.match(scan, /<ApprovalReceiptField/)
  assert.match(hunt, /<ApprovalReceiptField/)
  assert.match(component, /Create approval for this target/)
  assert.match(component, /Confirm that you are authorized to test this target first/)
  assert.match(component, /Approval scope environment/)
  assert.match(component, /Production blocks private and loopback destinations/)
  assert.match(component, /Lab \/ owned private target/)
  assert.match(api, /createTargetPolicyApprovalReceipt/)
  assert.match(api, /environment = 'production'/)
  assert.match(api, /environment,\n  \}\)/)
  assert.match(api, /confirm_authorized/)
})

test('receipt creation carries the scope binding into Hunt and stays duration-bounded', () => {
  assert.match(hunt, /onScopeReceiptIdChange=\{setScopeReceipt\}/)
  assert.match(hunt, /approvalTtlMinutes/)
  assert.match(scan, /disabledReason=\{batchMode \? 'Create approvals from a single-target Scan; receipts are target-bound\.'/)
  assert.match(component, /Valid for about/)
})
