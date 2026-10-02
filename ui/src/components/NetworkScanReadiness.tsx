import { LoaderCircle } from 'lucide-react'
import { Card } from '@/components/ui'
import { networkReadinessPresentation } from '@/lib/networkReadiness.mjs'

export type NetworkReadiness = {
  status: string
  message?: string | null
  remedy?: string | null
}

export function NetworkScanReadiness({ readiness }: { readiness: NetworkReadiness | null }) {
  const presentation = networkReadinessPresentation(readiness)
  if (!presentation) return null
  return (
    <Card className={`mb-4 p-4 text-sm ${presentation.starting ? 'border-blue-500/20 bg-blue-500/5 text-blue-200' : 'border-amber-500/20 bg-amber-500/5 text-amber-200'}`} role={presentation.role}>
      <div className="flex items-center gap-2">
        {presentation.starting && <LoaderCircle className="h-4 w-4 animate-spin" aria-hidden="true" />}
        <span>{presentation.message}</span>
      </div>
      {presentation.remedy && <details className="mt-3 text-gray-400">
        <summary className="cursor-pointer text-xs">Troubleshooting</summary>
        <p className="mt-2">{presentation.remedy}</p>
      </details>}
    </Card>
  )
}
