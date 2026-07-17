'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import {
  createApprovalReceipt,
  evidenceExportBundleUrl,
  getEvidenceRetentionExecutions,
  getEvidenceExportManifest,
  getTargets,
  previewScopeReceipt,
  sweepEvidenceRetention,
  type EvidenceExportManifest,
  type EvidenceRetentionSweepResult,
  type Target,
} from '@/lib/api'
import {
  buildEvidenceRetentionSweepCriteria,
  buildEvidenceRetentionSweepExecutionRequest,
  evidenceRetentionSweepCriteriaKey,
  evidenceRetentionSweepRecoveryState,
} from '@/lib/evidenceRetention'
import { Button, ConfirmDialog, RetentionClassBadge, SectionCard, useToast } from '@/components/ui'

const RETENTION_CLASSES = ['standard', 'short', 'sensitive', 'audit', 'legal_hold']

function CountRow({ label, counts }: { label: string; counts?: Record<string, number> }) {
  if (!counts || Object.keys(counts).length === 0) return null
  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="text-xs text-gray-500">{label}:</span>
      {Object.entries(counts).map(([k, v]) => (
        <span key={k} className="rounded bg-gray-800 px-1.5 py-0.5 text-xs text-gray-300">{k.replace(/_/g, ' ')}: {v}</span>
      ))}
    </div>
  )
}

export default function EvidenceRetentionPanel({
  findingId,
  scanId,
}: {
  findingId?: string
  scanId?: string
}) {
  const toast = useToast()
  const [retentionClass, setRetentionClass] = useState('')
  const [manifest, setManifest] = useState<EvidenceExportManifest | null>(null)
  const [manifestLoading, setManifestLoading] = useState(false)

  // Retention sweep state — starts in dry-run (preview) mode.
  const [olderThanDays, setOlderThanDays] = useState('')
  const [targets, setTargets] = useState<Target[]>([])
  const [targetId, setTargetId] = useState('')
  const [targetsLoading, setTargetsLoading] = useState(false)
  const [sweepPreview, setSweepPreview] = useState<EvidenceRetentionSweepResult | null>(null)
  const [sweepPreviewCriteriaKey, setSweepPreviewCriteriaKey] = useState<string | null>(null)
  const [sweepLoading, setSweepLoading] = useState(false)
  const [confirmExecute, setConfirmExecute] = useState(false)
  const [executing, setExecuting] = useState(false)
  const [sweepApprovalReceiptId, setSweepApprovalReceiptId] = useState<string | null>(null)
  const [executionError, setExecutionError] = useState<string | null>(null)
  const [unfinishedExecutions, setUnfinishedExecutions] = useState<EvidenceRetentionSweepResult[]>([])
  const sweepRequestGenerationRef = useRef(0)

  const scope = {
    finding_id: findingId || undefined,
    scan_id: scanId || undefined,
    retention_class: retentionClass || undefined,
  }
  const globalSweepAvailable = !findingId && !scanId
  const sweepCriteria = buildEvidenceRetentionSweepCriteria({ retentionClass, olderThanDays, targetId })
  const currentSweepCriteriaKey = evidenceRetentionSweepCriteriaKey(sweepCriteria)
  const activeSweepPreview = (
    globalSweepAvailable && sweepPreview && (
      sweepPreview.preview_status === 'executing'
      || sweepPreviewCriteriaKey === currentSweepCriteriaKey
    )
      ? sweepPreview
      : null
  )

  const restoreUnfinishedExecution = useCallback((unfinished: EvidenceRetentionSweepResult) => {
    const criteria = unfinished.preview_criteria
    if (!criteria || !unfinished.preview_id || !unfinished.approval_receipt_id) return
    const recovered = evidenceRetentionSweepRecoveryState(criteria)
    sweepRequestGenerationRef.current += 1
    setTargetId(recovered.targetId)
    setRetentionClass(recovered.retentionClass)
    setOlderThanDays(recovered.olderThanDays)
    setSweepPreview(unfinished)
    setSweepPreviewCriteriaKey(recovered.criteriaKey)
    setSweepApprovalReceiptId(unfinished.approval_receipt_id)
    setConfirmExecute(false)
    setExecuting(false)
    setExecutionError('Recovered an unfinished deletion intent after reload. Resume it with the same one-use approval.')
  }, [])

  function invalidateSweepPreview() {
    sweepRequestGenerationRef.current += 1
    setSweepPreview(null)
    setSweepPreviewCriteriaKey(null)
    setSweepLoading(false)
    setConfirmExecute(false)
    setExecuting(false)
    setSweepApprovalReceiptId(null)
    setExecutionError(null)
  }

  useEffect(() => {
    if (!globalSweepAvailable) return
    setTargetsLoading(true)
    Promise.all([
      getTargets({ includeInactive: true, limit: 500 }),
      getEvidenceRetentionExecutions({ limit: 20 }),
    ])
      .then(([targetResponse, executionResponse]) => {
        setTargets(targetResponse.targets || [])
        setUnfinishedExecutions(executionResponse.executions || [])
        const unfinished = executionResponse.executions?.[0]
        if (unfinished) restoreUnfinishedExecution(unfinished)
      })
      .catch((err) => toast.error(err instanceof Error ? err.message : 'Failed to load evidence retention controls'))
      .finally(() => setTargetsLoading(false))
  }, [globalSweepAvailable, restoreUnfinishedExecution, toast])

  useEffect(() => {
    sweepRequestGenerationRef.current += 1
    setSweepPreview(null)
    setSweepPreviewCriteriaKey(null)
    setSweepLoading(false)
    setConfirmExecute(false)
    setExecuting(false)
    setSweepApprovalReceiptId(null)
    setExecutionError(null)
  }, [findingId, scanId])

  useEffect(() => () => {
    sweepRequestGenerationRef.current += 1
  }, [])

  useEffect(() => {
    const previewId = activeSweepPreview?.preview_id
    const expiresAt = activeSweepPreview?.preview_expires_at
    if (!activeSweepPreview?.dry_run || !previewId || !expiresAt || executing || sweepApprovalReceiptId) return
    const delay = new Date(expiresAt).getTime() - Date.now()
    if (!Number.isFinite(delay) || delay <= 0) {
      invalidateSweepPreview()
      return
    }
    const previewGeneration = sweepRequestGenerationRef.current
    const timer = window.setTimeout(() => {
      if (sweepRequestGenerationRef.current !== previewGeneration) return
      sweepRequestGenerationRef.current += 1
      setSweepPreview(null)
      setSweepPreviewCriteriaKey(null)
      setSweepLoading(false)
      setConfirmExecute(false)
      setExecuting(false)
      setSweepApprovalReceiptId(null)
      setExecutionError(null)
    }, delay)
    return () => window.clearTimeout(timer)
  }, [activeSweepPreview?.dry_run, activeSweepPreview?.preview_expires_at, activeSweepPreview?.preview_id, executing, sweepApprovalReceiptId])

  async function loadManifest() {
    setManifestLoading(true)
    try {
      const res = await getEvidenceExportManifest({ ...scope, limit: 500 })
      setManifest(res)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to load manifest')
    } finally {
      setManifestLoading(false)
    }
  }

  function downloadBundle() {
    const url = evidenceExportBundleUrl({ ...scope, limit: 500 })
    window.open(url, '_blank', 'noopener')
  }

  async function runSweepPreview() {
    if (!targetId) {
      toast.error('Select a target before previewing evidence cleanup')
      return
    }
    const requestedCriteria = buildEvidenceRetentionSweepCriteria({ retentionClass, olderThanDays, targetId })
    const requestedCriteriaKey = evidenceRetentionSweepCriteriaKey(requestedCriteria)
    invalidateSweepPreview()
    const requestGeneration = sweepRequestGenerationRef.current
    setSweepLoading(true)
    try {
      const res = await sweepEvidenceRetention({
        dry_run: true,
        ...requestedCriteria,
      })
      if (sweepRequestGenerationRef.current !== requestGeneration) return
      setSweepPreview(res)
      setSweepPreviewCriteriaKey(requestedCriteriaKey)
      toast.info(`${res.candidate_count} evidence object(s) eligible for deletion`)
    } catch (err) {
      if (sweepRequestGenerationRef.current !== requestGeneration) return
      toast.error(err instanceof Error ? err.message : 'Failed to preview sweep')
    } finally {
      if (sweepRequestGenerationRef.current === requestGeneration) setSweepLoading(false)
    }
  }

  async function executeSweep() {
    const preview = activeSweepPreview
    const previewId = preview?.preview_id
    const previewHash = preview?.preview_hash
    const previewExpiresAt = preview?.preview_expires_at
    const previewTargetId = preview?.preview_criteria?.target_id
    const previewTarget = targets.find((target) => target.id === previewTargetId)
    if (!previewId || !previewHash || !previewExpiresAt || !previewTargetId || !previewTarget) {
      toast.error('The retention preview is stale or expired. Run a new dry-run preview.')
      setConfirmExecute(false)
      return
    }
    const expiry = new Date(previewExpiresAt).getTime()
    if ((!Number.isFinite(expiry) || expiry <= Date.now()) && !sweepApprovalReceiptId) {
      toast.error('The retention preview has expired. Run a new dry-run preview.')
      invalidateSweepPreview()
      return
    }
    const executionGeneration = sweepRequestGenerationRef.current
    setExecuting(true)
    setExecutionError(null)
    try {
      let approvalReceiptId = sweepApprovalReceiptId
      if (!approvalReceiptId) {
        const approvalUrl = previewTarget.url.includes('://') ? previewTarget.url : `https://${previewTarget.url}`
        const parsedTargetUrl = new URL(approvalUrl)
        const scopeResponse = await previewScopeReceipt({
          url: approvalUrl,
          target_id: previewTargetId,
          allowed_hosts: [parsedTargetUrl.hostname],
          // Retention changes local stored data; it does not send active traffic
          // to the target. Lab scope allows registered loopback/private targets
          // without widening the exact target/preview/action approval binding.
          environment: 'lab',
        })
        if (sweepRequestGenerationRef.current !== executionGeneration) return
        if (scopeResponse.scope_receipt.verdict === 'blocked') {
          throw new Error(`Target scope is blocked: ${scopeResponse.scope_receipt.blocked_by.join(', ')}`)
        }
        const confirmations = ['confirm_authorized']
        if (scopeResponse.scope_receipt.verdict === 'needs_approval') confirmations.push('confirm_scope_reviewed')
        const approvalResponse = await createApprovalReceipt({
          scope_receipt_id: scopeResponse.scope_receipt.receipt_id,
          risk_tier: 'dangerous',
          confirmations,
          approved_by: 'interactive-ui',
          expires_at: previewExpiresAt,
          action_name: 'evidence.retention_sweep',
          action_context: {
            preview_id: previewId,
            preview_hash: previewHash,
            target_id: previewTargetId,
          },
        })
        if (sweepRequestGenerationRef.current !== executionGeneration) return
        approvalReceiptId = approvalResponse.approval_receipt.id
        setSweepApprovalReceiptId(approvalReceiptId)
      }
      const res = await sweepEvidenceRetention(buildEvidenceRetentionSweepExecutionRequest({
        previewId,
        approvalReceiptId,
      }))
      if (sweepRequestGenerationRef.current !== executionGeneration) return
      toast.success(`Swept ${res.deleted_count} evidence object(s)`)
      setUnfinishedExecutions((items) => items.filter((item) => item.preview_id !== previewId))
      setSweepPreview(null)
      setSweepPreviewCriteriaKey(null)
      setSweepApprovalReceiptId(null)
      setExecutionError(null)
    } catch (err) {
      if (sweepRequestGenerationRef.current !== executionGeneration) return
      const message = err instanceof Error ? err.message : 'Failed to execute sweep'
      toast.error(message)
      if (/expired|stale|run a new preview|target no longer exists/i.test(message)) {
        setUnfinishedExecutions((items) => items.filter((item) => item.preview_id !== previewId))
        invalidateSweepPreview()
      } else {
        setExecutionError(message)
      }
    } finally {
      if (sweepRequestGenerationRef.current === executionGeneration) {
        setExecuting(false)
        setConfirmExecute(false)
      }
    }
  }

  const boundCriteria = activeSweepPreview?.preview_criteria
  const boundTarget = targets.find((target) => target.id === boundCriteria?.target_id)
  const boundCriteriaDescription = boundCriteria
    ? `${boundTarget?.url || boundCriteria.target_id}: ${boundCriteria.retention_class || 'all retention classes'}, ${
        boundCriteria.older_than_days == null
          ? 'policy age defaults'
          : `at least ${boundCriteria.older_than_days} days old`
      }, maximum ${boundCriteria.limit} objects, ${
        boundCriteria.delete_local_files ? 'delete unshared local blobs' : 'preserve local blobs'
      }`
    : 'the last dry-run criteria'
  const reviewablePreview = Boolean(
    activeSweepPreview && (activeSweepPreview.dry_run || activeSweepPreview.preview_status === 'executing')
  )
  const previewCandidates = activeSweepPreview?.candidates || []
  const hasExecutingIntent = activeSweepPreview?.preview_status === 'executing'

  return (
    <SectionCard title={globalSweepAvailable ? 'Export & retention' : 'Export'}>
      <div className="space-y-5">
        <div className="flex flex-wrap items-end gap-3">
          <div>
            <label htmlFor="ev-retention-class" className="mb-1 block text-xs font-medium text-gray-400">Retention class</label>
            <select
              id="ev-retention-class"
              value={retentionClass}
              onChange={(e) => {
                setRetentionClass(e.target.value)
                invalidateSweepPreview()
              }}
              disabled={hasExecutingIntent}
              className="rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none disabled:opacity-60"
            >
              <option value="">All classes</option>
              {RETENTION_CLASSES.map((c) => <option key={c} value={c}>{c.replace(/_/g, ' ')}</option>)}
            </select>
          </div>
          <Button size="sm" variant="secondary" onClick={loadManifest} disabled={manifestLoading}>
            {manifestLoading ? 'Loading…' : 'Preview manifest'}
          </Button>
          <Button size="sm" variant="secondary" onClick={downloadBundle}>Download bundle (zip)</Button>
        </div>

        {manifest && (
          <div className="space-y-2 rounded-lg border border-gray-800 bg-gray-950 p-3">
            <div className="flex flex-wrap items-center gap-3 text-sm text-gray-300">
              <span className="font-medium text-white">{manifest.object_count} object(s)</span>
              <span className="text-xs text-gray-500">manifest {manifest.manifest_hash.slice(0, 12)}…</span>
              <span className="text-xs text-gray-500">content {manifest.content_included ? 'included' : 'excluded'}</span>
            </div>
            <CountRow label="Retention" counts={manifest.retention_counts} />
            <CountRow label="Storage" counts={manifest.storage_counts} />
            <CountRow label="Integrity" counts={manifest.integrity_counts} />
          </div>
        )}

        {globalSweepAvailable ? (
          <div className="border-t border-gray-800 pt-4">
            <h3 className="text-sm font-medium text-white">Target retention cleanup</h3>
            <p className="mt-1 text-xs text-gray-500">
              Cleanup is limited to one selected target and can delete eligible evidence from that target's scans and findings. It never sweeps{' '}
              <RetentionClassBadge retentionClass="legal_hold" />; evidence attached to an active finding is excluded before deletion begins. A fresh dry run
              binds the exact criteria and candidate objects for a short period. Confirmation creates a short-lived approval scoped to that target and preview.
            </p>
            {unfinishedExecutions.length > 0 && (
              <div className="mt-3 rounded-lg border border-amber-800/60 bg-amber-950/20 p-3">
                <label htmlFor="ev-unfinished-retention" className="mb-1 block text-xs font-medium text-amber-200">
                  Unfinished deletion
                </label>
                <select
                  id="ev-unfinished-retention"
                  value={hasExecutingIntent ? activeSweepPreview?.preview_id || '' : ''}
                  onChange={(event) => {
                    const selected = unfinishedExecutions.find((item) => item.preview_id === event.target.value)
                    if (selected) restoreUnfinishedExecution(selected)
                  }}
                  className="w-full max-w-2xl rounded-lg border border-amber-800 bg-gray-950 px-3 py-2 text-sm text-white focus:border-amber-500 focus:outline-none"
                >
                  <option value="">Choose an unfinished exact deletion…</option>
                  {unfinishedExecutions.map((item) => {
                    const target = targets.find((candidate) => candidate.id === item.preview_criteria?.target_id)
                    const started = item.execution_started_at ? new Date(item.execution_started_at).toLocaleString() : 'start time unavailable'
                    return (
                      <option key={item.preview_id || started} value={item.preview_id || ''}>
                        {target?.url || item.preview_criteria?.target_id || 'Unknown target'} — {item.candidate_count} object(s) — {started}
                      </option>
                    )
                  })}
                </select>
                <p className="mt-1 text-xs text-amber-300/80">
                  Select any interrupted intent to resume its original candidate set and one-use approval. Criteria cannot be changed after deletion starts.
                </p>
              </div>
            )}
            <div className="mt-3 flex flex-wrap items-end gap-3">
              <div>
                <label htmlFor="ev-sweep-target" className="mb-1 block text-xs font-medium text-gray-400">Target</label>
                <select
                  id="ev-sweep-target"
                  value={targetId}
                  onChange={(e) => {
                    setTargetId(e.target.value)
                    invalidateSweepPreview()
                  }}
                  disabled={targetsLoading || hasExecutingIntent}
                  className="max-w-xs rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none disabled:opacity-60"
                >
                  <option value="">{targetsLoading ? 'Loading targets…' : 'Select a target…'}</option>
                  {targets.map((target) => (
                    <option key={target.id} value={target.id}>
                      {target.name ? `${target.name} — ` : ''}{target.url.replace(/^https?:\/\//, '')}
                      {target.is_active ? '' : ' (inactive)'}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label htmlFor="ev-older-than" className="mb-1 block text-xs font-medium text-gray-400">Older than (days, optional)</label>
                <input
                  id="ev-older-than"
                  type="number"
                  min={0}
                  max={3650}
                  value={olderThanDays}
                  onChange={(e) => {
                    setOlderThanDays(e.target.value)
                    invalidateSweepPreview()
                  }}
                  placeholder="policy default"
                  disabled={hasExecutingIntent}
                  className="w-40 rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white placeholder-gray-600 focus:border-blue-500 focus:outline-none disabled:opacity-60"
                />
              </div>
              <Button size="sm" variant="secondary" onClick={runSweepPreview} disabled={sweepLoading || !targetId || hasExecutingIntent}>
                {sweepLoading ? 'Previewing…' : 'Preview target cleanup'}
              </Button>
            </div>

            {activeSweepPreview && (
              <div className="mt-3 space-y-3 rounded-lg border border-gray-800 bg-gray-950 p-3">
                <p className="text-sm text-gray-300">
                  {activeSweepPreview.preview_status === 'executing'
                    ? 'Unfinished execution — '
                    : activeSweepPreview.dry_run ? 'Bound dry run — ' : 'Executed — '}
                  <span className="font-medium text-white">{activeSweepPreview.candidate_count}</span> candidate(s)
                  {!activeSweepPreview.dry_run && <>, <span className="font-medium text-white">{activeSweepPreview.deleted_count}</span> deleted</>}
                  {activeSweepPreview.remote_objects && !activeSweepPreview.remote_objects.delete_supported && activeSweepPreview.remote_objects.candidate_count > 0 && (
                    <span className="ml-1 text-xs text-amber-400">(remote objects preserved — remote deletion not yet supported)</span>
                  )}
                </p>
                {reviewablePreview && (
                  <div className="space-y-1 text-xs text-gray-500">
                    <p>Scope: {boundCriteriaDescription}.</p>
                    {activeSweepPreview.preview_status !== 'executing' && activeSweepPreview.preview_expires_at && (
                      <p>One-use preview expires {new Date(activeSweepPreview.preview_expires_at).toLocaleTimeString()}.</p>
                    )}
                  </div>
                )}
                {reviewablePreview && previewCandidates.length > 0 && (
                  <details className="rounded-md border border-gray-800 bg-gray-900/60 p-2">
                    <summary className="cursor-pointer text-xs font-medium text-gray-300">
                      Review the exact {previewCandidates.length} object(s) and storage effects
                    </summary>
                    <div className="mt-2 max-h-64 overflow-auto">
                      <table className="w-full min-w-[680px] text-left text-xs">
                        <thead className="text-gray-500">
                          <tr>
                            <th className="px-2 py-1 font-medium">Evidence object</th>
                            <th className="px-2 py-1 font-medium">Related record</th>
                            <th className="px-2 py-1 font-medium">Class</th>
                            <th className="px-2 py-1 font-medium">Storage consequence</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-800 text-gray-300">
                          {previewCandidates.map((raw, index) => {
                            const candidate = raw as Record<string, unknown>
                            const objectId = String(candidate.id || `candidate-${index + 1}`)
                            const findingId = candidate.finding_id ? String(candidate.finding_id) : ''
                            const scanCandidateId = candidate.scan_id ? String(candidate.scan_id) : ''
                            const plannedAction = String(candidate.planned_blob_action || 'row_only').replace(/_/g, ' ')
                            const storageBackend = String(candidate.storage_backend || '').replace(/_/g, ' ')
                            return (
                              <tr key={objectId}>
                                <td className="px-2 py-1.5 font-mono" title={objectId}>{objectId.slice(0, 12)}…</td>
                                <td className="px-2 py-1.5">
                                  {findingId ? (
                                    <a className="text-blue-400 hover:text-blue-300" href={`/findings/${findingId}`}>Finding {findingId.slice(0, 8)}…</a>
                                  ) : scanCandidateId ? (
                                    <a className="text-blue-400 hover:text-blue-300" href={`/scans/${scanCandidateId}`}>Scan {scanCandidateId.slice(0, 8)}…</a>
                                  ) : 'Unlinked'}
                                </td>
                                <td className="px-2 py-1.5">{String(candidate.retention_class || 'unknown')}</td>
                                <td className="px-2 py-1.5">{plannedAction}{storageBackend ? ` (${storageBackend})` : ''}</td>
                              </tr>
                            )
                          })}
                        </tbody>
                      </table>
                    </div>
                  </details>
                )}
                {reviewablePreview && activeSweepPreview.candidate_count > 0 && (
                  <div className="space-y-2">
                    <div className="flex flex-wrap items-end gap-3">
                      <p className="flex-1 text-xs text-gray-500">
                        {sweepApprovalReceiptId
                          ? 'A one-use approval is already bound to this preview. Retry resumes the same deletion intent safely.'
                          : 'Confirming creates a short-lived dangerous-action approval bound only to this target and preview.'}
                      </p>
                    <Button
                      size="sm"
                      variant="danger"
                      onClick={() => setConfirmExecute(true)}
                      disabled={!activeSweepPreview.preview_id || !activeSweepPreview.preview_hash || !activeSweepPreview.preview_expires_at}
                    >
                        {sweepApprovalReceiptId ? 'Retry deletion' : 'Delete previewed objects'}
                    </Button>
                    </div>
                    {executionError && (
                      <p role="alert" className="text-xs text-amber-300">
                        The deletion did not finish in this browser request. Retry uses the same preview and approval; it will not widen the cohort. Last error: {executionError}
                      </p>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        ) : (
          <div className="border-t border-gray-800 pt-4">
            <h3 className="text-sm font-medium text-white">Retention cleanup is target-scoped</h3>
            <p className="mt-1 text-xs text-gray-500">
              Deletion is not available in this finding- or scan-scoped view because a retention sweep can affect evidence
              beyond this one record. <a href="/evidence" className="text-blue-400 hover:text-blue-300">Open the unfiltered Evidence page</a>{' '}
              to choose a target and review a fresh preview.
            </p>
          </div>
        )}
      </div>

      <ConfirmDialog
        open={confirmExecute}
        title="Delete expired evidence?"
        message={`${sweepApprovalReceiptId ? 'This resumes the existing one-use approval and deletion intent.' : 'This creates a short-lived approval bound to this target and preview.'} It permanently deletes only the ${activeSweepPreview?.candidate_count ?? 0} reviewed object(s) (${boundCriteriaDescription}). Newly eligible objects are not included. Legal-hold evidence is never included; evidence attached to an active finding is excluded before deletion begins.`}
        confirmLabel={sweepApprovalReceiptId ? 'Resume deletion' : 'Delete evidence'}
        danger
        busy={executing}
        onConfirm={executeSweep}
        onCancel={() => setConfirmExecute(false)}
      />
    </SectionCard>
  )
}
