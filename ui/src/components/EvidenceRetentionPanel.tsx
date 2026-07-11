'use client'

import { useState } from 'react'
import {
  evidenceExportBundleUrl,
  getEvidenceExportManifest,
  sweepEvidenceRetention,
  type EvidenceExportManifest,
  type EvidenceRetentionSweepResult,
} from '@/lib/api'
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
  const [sweepPreview, setSweepPreview] = useState<EvidenceRetentionSweepResult | null>(null)
  const [sweepLoading, setSweepLoading] = useState(false)
  const [approvalReceiptId, setApprovalReceiptId] = useState('')
  const [confirmExecute, setConfirmExecute] = useState(false)
  const [executing, setExecuting] = useState(false)

  const scope = {
    finding_id: findingId || undefined,
    scan_id: scanId || undefined,
    retention_class: retentionClass || undefined,
  }

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
    setSweepLoading(true)
    try {
      const res = await sweepEvidenceRetention({
        dry_run: true,
        retention_class: retentionClass || undefined,
        older_than_days: olderThanDays ? Number(olderThanDays) : undefined,
        limit: 200,
      })
      setSweepPreview(res)
      toast.info(`${res.candidate_count} evidence object(s) eligible for deletion`)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to preview sweep')
    } finally {
      setSweepLoading(false)
    }
  }

  async function executeSweep() {
    setExecuting(true)
    try {
      const res = await sweepEvidenceRetention({
        dry_run: false,
        retention_class: retentionClass || undefined,
        older_than_days: olderThanDays ? Number(olderThanDays) : undefined,
        limit: 200,
        delete_local_files: true,
        approval_receipt_id: approvalReceiptId.trim(),
      })
      toast.success(`Swept ${res.deleted_count} evidence object(s)`)
      setSweepPreview(res)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to execute sweep')
    } finally {
      setExecuting(false)
      setConfirmExecute(false)
    }
  }

  return (
    <SectionCard title="Export & retention">
      <div className="space-y-5">
        <div className="flex flex-wrap items-end gap-3">
          <div>
            <label htmlFor="ev-retention-class" className="mb-1 block text-xs font-medium text-gray-400">Retention class</label>
            <select
              id="ev-retention-class"
              value={retentionClass}
              onChange={(e) => setRetentionClass(e.target.value)}
              className="rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
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

        <div className="border-t border-gray-800 pt-4">
          <h3 className="text-sm font-medium text-white">Retention sweep</h3>
          <p className="mt-1 text-xs text-gray-500">
            Deletes expired evidence per retention policy. Never sweeps <RetentionClassBadge retentionClass="legal_hold" />{' '}
            or evidence attached to active findings. Preview first; executing requires an approval receipt.
          </p>
          <div className="mt-3 flex flex-wrap items-end gap-3">
            <div>
              <label htmlFor="ev-older-than" className="mb-1 block text-xs font-medium text-gray-400">Older than (days, optional)</label>
              <input
                id="ev-older-than"
                type="number"
                min={0}
                value={olderThanDays}
                onChange={(e) => setOlderThanDays(e.target.value)}
                placeholder="policy default"
                className="w-40 rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white placeholder-gray-600 focus:border-blue-500 focus:outline-none"
              />
            </div>
            <Button size="sm" variant="secondary" onClick={runSweepPreview} disabled={sweepLoading}>
              {sweepLoading ? 'Previewing…' : 'Preview sweep (dry run)'}
            </Button>
          </div>

          {sweepPreview && (
            <div className="mt-3 space-y-3 rounded-lg border border-gray-800 bg-gray-950 p-3">
              <p className="text-sm text-gray-300">
                {sweepPreview.dry_run ? 'Dry run — ' : 'Executed — '}
                <span className="font-medium text-white">{sweepPreview.candidate_count}</span> candidate(s)
                {!sweepPreview.dry_run && <>, <span className="font-medium text-white">{sweepPreview.deleted_count}</span> deleted</>}
                {sweepPreview.remote_objects && !sweepPreview.remote_objects.delete_supported && sweepPreview.remote_objects.candidate_count > 0 && (
                  <span className="ml-1 text-xs text-amber-400">(remote objects preserved — remote deletion not yet supported)</span>
                )}
              </p>
              {sweepPreview.dry_run && sweepPreview.candidate_count > 0 && (
                <div className="flex flex-wrap items-end gap-3">
                  <div className="flex-1">
                    <label htmlFor="ev-approval" className="mb-1 block text-xs font-medium text-gray-400">Approval receipt ID</label>
                    <input
                      id="ev-approval"
                      type="text"
                      value={approvalReceiptId}
                      onChange={(e) => setApprovalReceiptId(e.target.value)}
                      placeholder="Paste an approval receipt from Command Arsenal"
                      className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white placeholder-gray-600 focus:border-blue-500 focus:outline-none"
                    />
                  </div>
                  <Button
                    size="sm"
                    variant="danger"
                    onClick={() => setConfirmExecute(true)}
                    disabled={!approvalReceiptId.trim()}
                  >
                    Execute deletion
                  </Button>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      <ConfirmDialog
        open={confirmExecute}
        title="Delete expired evidence?"
        message={`This permanently deletes ${sweepPreview?.candidate_count ?? 0} eligible evidence object(s). Legal-hold and active-finding evidence are always preserved.`}
        confirmLabel="Delete evidence"
        danger
        busy={executing}
        onConfirm={executeSweep}
        onCancel={() => setConfirmExecute(false)}
      />
    </SectionCard>
  )
}
