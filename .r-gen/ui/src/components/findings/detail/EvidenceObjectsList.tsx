'use client'

import Link from '@/components/WorkspaceLink'
import type { EvidenceObject } from '@/lib/api'
import { CopyButton } from './CopyButton'

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}

function contentText(content: unknown): string {
  if (content === undefined || content === null) return ''
  if (typeof content === 'string') {
    try {
      return JSON.stringify(JSON.parse(content), null, 2)
    } catch {
      return content
    }
  }
  try {
    return JSON.stringify(content, null, 2)
  } catch {
    return String(content)
  }
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex min-w-0 gap-2">
      <span className="shrink-0 text-gray-500">{label}</span>
      <span className="min-w-0 break-all font-mono text-gray-300">{children}</span>
    </div>
  )
}

// First-class evidence records (content hash, redaction profile, retention class, storage URI).
// They persist independently of the finding's embedded evidence and survive worker churn.
export function EvidenceObjectsList({ objects, findingId }: { objects: EvidenceObject[]; findingId: string }) {
  if (objects.length === 0) return null
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-500">
          Durable evidence objects ({objects.length})
        </h3>
        <Link href={`/evidence?finding_id=${encodeURIComponent(findingId)}`} className="text-xs text-blue-400 hover:text-blue-300">
          Browse in Evidence →
        </Link>
      </div>
      {objects.map((eo) => {
        const text = contentText(eo.content)
        return (
          <div key={eo.id} className="space-y-2 rounded-md border border-gray-800 bg-gray-950/60 p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="text-sm font-medium text-gray-200">{eo.object_type}</span>
              <div className="flex items-center gap-2 text-xs">
                {eo.retention_class && (
                  <span className={`rounded px-2 py-0.5 font-medium ${eo.retention_class === 'sensitive' ? 'bg-amber-900/50 text-amber-300' : 'bg-gray-800 text-gray-300'}`}>
                    {eo.retention_class}
                  </span>
                )}
                {typeof eo.size_bytes === 'number' && <span className="text-gray-400">{formatBytes(eo.size_bytes)}</span>}
              </div>
            </div>
            <div className="grid gap-x-4 gap-y-1 text-xs sm:grid-cols-2">
              {eo.scan_id && (
                <div className="flex min-w-0 gap-2">
                  <span className="shrink-0 text-gray-500">evidence-producing scan</span>
                  <Link href={`/scans/${eo.scan_id}`} className="break-all font-mono text-blue-300 hover:text-blue-200">{eo.scan_id}</Link>
                </div>
              )}
              {eo.content_sha256 && <Row label="sha256">{eo.content_sha256}</Row>}
              {eo.storage_uri && <Row label="storage">{eo.storage_uri}</Row>}
              {eo.redaction_profile && <Row label="redaction">{eo.redaction_profile}</Row>}
              <Row label="id">{eo.id}</Row>
            </div>
            {text && (
              <details className="rounded-sm border border-gray-800 bg-gray-950 p-2">
                <summary className="cursor-pointer text-xs font-medium text-gray-300">Object content</summary>
                <div className="mt-2 flex justify-end">
                  <CopyButton text={text} label="Copy evidence object content" />
                </div>
                <pre className="mt-2 max-h-96 overflow-auto whitespace-pre-wrap text-xs text-gray-300 wrap-break-word">{text}</pre>
              </details>
            )}
          </div>
        )
      })}
    </div>
  )
}
