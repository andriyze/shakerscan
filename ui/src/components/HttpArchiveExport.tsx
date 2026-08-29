'use client'

import { useState } from 'react'
import { Download } from 'lucide-react'
import { API_URL } from '@/lib/api'
import { Button, Card, useToast } from '@/components/ui'

type ArchiveFormat = 'transactions' | 'har'

export default function HttpArchiveExport({
  ownerKind,
  ownerId,
  compact = false,
}: {
  ownerKind: 'scan' | 'hunt'
  ownerId: string
  compact?: boolean
}) {
  const toast = useToast()
  const [downloading, setDownloading] = useState<ArchiveFormat | null>(null)

  const download = async (format: ArchiveFormat) => {
    setDownloading(format)
    try {
      const ownerPath = ownerKind === 'scan' ? 'scans' : 'hunts'
      const response = await fetch(
        `${API_URL}/${ownerPath}/${encodeURIComponent(ownerId)}/http-transactions?format=${format}&redaction=redacted&limit=10000`,
      )
      if (!response.ok) {
        const detail = await response.json().catch(() => null)
        throw new Error(detail?.detail || `Export failed (${response.status})`)
      }
      const blob = await response.blob()
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = `shakerscan-${ownerId}.${format === 'har' ? 'har' : 'json'}`
      document.body.appendChild(anchor)
      anchor.click()
      anchor.remove()
      URL.revokeObjectURL(url)
      toast.success(format === 'har' ? 'HAR export downloaded' : 'Request archive downloaded')
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : 'Could not export request archive')
    } finally {
      setDownloading(null)
    }
  }

  const content = (
    <>
      <div className="min-w-0 flex-1">
        <h2 className="text-sm font-semibold text-gray-200">HTTP request archive</h2>
        <p className="mt-1 text-xs text-gray-500">
          Download the requests and responses recorded during this {ownerKind}. Exports are redacted by default and state when capture was partial.
        </p>
      </div>
      <div className="flex shrink-0 flex-wrap gap-2">
        <Button size="sm" variant="secondary" onClick={() => download('transactions')} disabled={downloading !== null}>
          <Download className="h-4 w-4" />
          {downloading === 'transactions' ? 'Preparing…' : 'Requests JSON'}
        </Button>
        <Button size="sm" variant="secondary" onClick={() => download('har')} disabled={downloading !== null}>
          <Download className="h-4 w-4" />
          {downloading === 'har' ? 'Preparing…' : 'HAR 1.2'}
        </Button>
      </div>
    </>
  )

  if (compact) {
    return <div className="flex flex-wrap items-start gap-3 rounded-lg border border-gray-800 bg-gray-950 p-3">{content}</div>
  }
  return <Card className="mb-6 flex flex-wrap items-start gap-4 p-4">{content}</Card>
}
