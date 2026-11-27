import assert from 'node:assert/strict'
import test from 'node:test'

import { BODY_UNMASKABLE_LABEL, BODY_WITHHELD_LABEL, bodyWithheldLabel } from './archiveBodies.mjs'

// External release audit, 2026-10-09 (R2): a masked export leaves a body out (budget, size limit,
// external read budget, or a body that could not be masked) and sends null for it.

test('a body left out for size or budget reads as withheld, not absent', () => {
  for (const reason of ['masking_budget', 'over_masking_limit', 'external_read_budget']) {
    const row = { payload_omitted: ['response_body'], payload_omitted_reasons: { response_body: reason } }
    assert.equal(bodyWithheldLabel(row, 'response'), BODY_WITHHELD_LABEL)
    assert.equal(bodyWithheldLabel(row, 'request'), null)
  }
})

test('a body that could not be masked says so', () => {
  const row = { payload_omitted: ['request_body'], payload_omitted_reasons: { request_body: 'masking_failed' } }
  assert.equal(bodyWithheldLabel(row, 'request'), BODY_UNMASKABLE_LABEL)
})

test('an older server without reasons still marks the omitted side; nothing else is marked', () => {
  assert.equal(bodyWithheldLabel({ payload_omitted: ['request_body'] }, 'request'), BODY_WITHHELD_LABEL)
  assert.equal(bodyWithheldLabel({}, 'response'), null)
  assert.equal(bodyWithheldLabel({ payload_omitted: null, payload_omitted_reasons: null }, 'response'), null)
})
