export interface EvidenceRetentionSweepCriteria {
  target_id: string
  retention_class?: string
  older_than_days?: number
  limit: number
  delete_local_files: boolean
}

export interface EvidenceRetentionSweepExecutionRequest {
  dry_run: false
  preview_id: string
  approval_receipt_id: string
}

export interface EvidenceRetentionSweepRecoveryState {
  targetId: string
  retentionClass: string
  olderThanDays: string
  criteriaKey: string
}

export function buildEvidenceRetentionSweepCriteria({
  retentionClass,
  olderThanDays,
  targetId,
  limit = 200,
  deleteLocalFiles = true,
}: {
  retentionClass: string
  olderThanDays: string
  targetId: string
  limit?: number
  deleteLocalFiles?: boolean
}): EvidenceRetentionSweepCriteria {
  const parsedDays = olderThanDays.trim() === '' ? undefined : Number(olderThanDays)
  const criteria: EvidenceRetentionSweepCriteria = {
    target_id: targetId,
    limit: Math.max(1, Math.min(1000, Math.trunc(limit) || 200)),
    delete_local_files: deleteLocalFiles,
  }
  if (retentionClass) criteria.retention_class = retentionClass
  if (parsedDays !== undefined && Number.isFinite(parsedDays)) {
    criteria.older_than_days = Math.max(0, Math.min(3650, Math.trunc(parsedDays)))
  }
  return criteria
}

export function evidenceRetentionSweepCriteriaKey(criteria: EvidenceRetentionSweepCriteria): string {
  return JSON.stringify({
    scope: 'target',
    target_id: criteria.target_id,
    retention_class: criteria.retention_class ?? null,
    older_than_days: criteria.older_than_days ?? null,
    limit: criteria.limit,
    delete_local_files: criteria.delete_local_files,
  })
}

export function evidenceRetentionSweepRecoveryState(criteria: {
  target_id: string
  retention_class?: string | null
  older_than_days?: number | null
  limit: number
  delete_local_files: boolean
}): EvidenceRetentionSweepRecoveryState {
  return {
    targetId: criteria.target_id,
    retentionClass: criteria.retention_class || '',
    olderThanDays: criteria.older_than_days == null ? '' : String(criteria.older_than_days),
    criteriaKey: evidenceRetentionSweepCriteriaKey({
      target_id: criteria.target_id,
      retention_class: criteria.retention_class || undefined,
      older_than_days: criteria.older_than_days == null ? undefined : criteria.older_than_days,
      limit: criteria.limit,
      delete_local_files: criteria.delete_local_files,
    }),
  }
}

export function buildEvidenceRetentionSweepExecutionRequest({
  previewId,
  approvalReceiptId,
}: {
  previewId: string
  approvalReceiptId: string
}): EvidenceRetentionSweepExecutionRequest {
  return {
    dry_run: false,
    preview_id: previewId,
    approval_receipt_id: approvalReceiptId,
  }
}
