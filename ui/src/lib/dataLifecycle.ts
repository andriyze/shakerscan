import { API_URL, getApiErrorMessage } from './apiConfig'
import { createApprovalReceipt } from './api'

export type DeletionSelection =
  | { kind: 'target'; target_id: string }
  | { kind: 'findings'; finding_ids: string[]; scan_id?: string }
  | { kind: 'findings'; older_than_days: number; status?: string; root_domain?: string }

export interface DeletionPreview {
  schema: 'shakerscan.record-deletion/v1'
  kind: 'target' | 'findings'
  preview_id: string
  preview_hash: string
  scope_receipt_id: string
  expires_at: string
  root_ids: string[]
  records: Record<'delete' | 'detach' | 'retain' | 'restrict', Record<string, { count: number; state: string; held: boolean }>>
  blockers: string[]
  retained: string[]
  would_delete: number
  dry_run: true
  external_files_deleted: false
}

export interface DeletionResult {
  status: 'deleted'
  deleted: number
  deleted_ids: string[]
  deleted_records: Record<string, number>
  retained: string[]
  external_files_deleted: false
  operation_id: string
  idempotent_replay: boolean
}

export async function archiveRecordTarget(targetId: string): Promise<void> {
  const response = await fetch(`${API_URL}/targets/${encodeURIComponent(targetId)}/archive`, { method: 'POST' })
  if (!response.ok) throw new Error(await getApiErrorMessage(response, 'Could not archive target'))
}

export async function previewRecordDeletion(selection: DeletionSelection): Promise<DeletionPreview> {
  const response = await fetch(`${API_URL}/data-deletion/preview`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(selection),
  })
  if (!response.ok) throw new Error(await getApiErrorMessage(response, 'Could not preview deletion'))
  return response.json()
}

export async function approveRecordDeletion(preview: DeletionPreview): Promise<string> {
  const response = await createApprovalReceipt({
    scope_receipt_id: preview.scope_receipt_id,
    risk_tier: 'dangerous',
    confirmations: ['confirm_authorized', 'confirm_scope_reviewed', 'confirm_delete_records'],
    approved_by: 'interactive_record_deletion',
    action_name: 'data.records.delete',
    action_context: { preview_id: preview.preview_id, preview_hash: preview.preview_hash },
    expires_at: preview.expires_at,
  })
  return response.approval_receipt.id
}

export async function executeRecordDeletion(preview: DeletionPreview, approvalId: string): Promise<DeletionResult> {
  const response = await fetch(`${API_URL}/data-deletion/execute`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ preview_id: preview.preview_id, preview_hash: preview.preview_hash, approval_receipt_id: approvalId }),
  })
  if (!response.ok) throw new Error(await getApiErrorMessage(response, 'Could not delete records'))
  return response.json()
}
