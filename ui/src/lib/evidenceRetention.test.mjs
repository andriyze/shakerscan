import assert from 'node:assert/strict'
import test from 'node:test'

import {
  buildEvidenceRetentionSweepCriteria,
  buildEvidenceRetentionSweepExecutionRequest,
  evidenceRetentionSweepCriteriaKey,
  evidenceRetentionSweepRecoveryState,
} from './evidenceRetention.ts'

test('retention criteria key changes for every destructive criterion', () => {
  const base = buildEvidenceRetentionSweepCriteria({
    targetId: 'target-a',
    retentionClass: 'standard',
    olderThanDays: '365',
    limit: 200,
    deleteLocalFiles: true,
  })
  const baseKey = evidenceRetentionSweepCriteriaKey(base)

  const variants = [
    { ...base, target_id: 'target-b' },
    { ...base, retention_class: 'short' },
    { ...base, older_than_days: 366 },
    { ...base, limit: 100 },
    { ...base, delete_local_files: false },
  ]
  for (const variant of variants) {
    assert.notEqual(evidenceRetentionSweepCriteriaKey(variant), baseKey)
  }
})

test('retention criteria normalize blank and bounded numeric inputs', () => {
  assert.deepEqual(
    buildEvidenceRetentionSweepCriteria({ targetId: 'target-a', retentionClass: '', olderThanDays: '  ' }),
    { target_id: 'target-a', limit: 200, delete_local_files: true },
  )
  assert.deepEqual(
    buildEvidenceRetentionSweepCriteria({
      targetId: 'target-a',
      retentionClass: 'short',
      olderThanDays: '-10',
      limit: 5000,
      deleteLocalFiles: false,
    }),
    {
      target_id: 'target-a',
      retention_class: 'short',
      older_than_days: 0,
      limit: 1000,
      delete_local_files: false,
    },
  )
})

test('retention execution request contains only the preview and approval bindings', () => {
  const request = buildEvidenceRetentionSweepExecutionRequest({
    previewId: 'preview-123',
    approvalReceiptId: 'approval-456',
  })

  assert.deepEqual(request, {
    dry_run: false,
    preview_id: 'preview-123',
    approval_receipt_id: 'approval-456',
  })
  assert.deepEqual(Object.keys(request).sort(), [
    'approval_receipt_id',
    'dry_run',
    'preview_id',
  ])
})

test('unfinished execution recovery preserves non-default hidden criteria', () => {
  const recovered = evidenceRetentionSweepRecoveryState({
    target_id: 'target-a',
    retention_class: null,
    older_than_days: 73,
    limit: 7,
    delete_local_files: false,
  })

  assert.deepEqual(recovered, {
    targetId: 'target-a',
    retentionClass: '',
    olderThanDays: '73',
    criteriaKey: JSON.stringify({
      scope: 'target',
      target_id: 'target-a',
      retention_class: null,
      older_than_days: 73,
      limit: 7,
      delete_local_files: false,
    }),
  })
})
