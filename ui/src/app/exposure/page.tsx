'use client'

import { Suspense, useEffect, useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { getDomains } from '@/lib/api'
import { useUrlFilters } from '@/lib/useUrlFilters'
import { Button, PageHeader, Select } from '@/components/ui'
import { ServicesView } from './ServicesView'

// Exposure is the service view: per target, each listener, the product and version observed on it,
// and the weaknesses known for that version. The earlier Triage, Map and Attack paths views were
// removed in 2.10 (they restated Targets and Findings); an old ?lens= link lands here.
function ExposureView() {
  const { filters, setFilter } = useUrlFilters()
  const domain = typeof filters.domain === 'string' ? filters.domain : ''
  const [domains, setDomains] = useState<string[]>([])
  const [revision, setRevision] = useState(0)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    getDomains().then((payload) => setDomains(payload.domains || [])).catch(() => {})
  }, [])

  return (
    <div className="space-y-6">
      <PageHeader
        className="mb-0"
        title="Exposure"
        description="Services on your targets: each listener, the product and version observed on it, and the weaknesses known for that version."
        actions={<>
          <Select
            fullWidth={false}
            value={domain}
            onChange={(event) => setFilter('domain', event.target.value || undefined)}
            aria-label="Filter by domain"
          >
            <option value="">All domains</option>
            {domains.map((item) => (
              <option key={item} value={item}>{item}</option>
            ))}
          </Select>
          <Button variant="secondary" onClick={() => setRevision((value) => value + 1)} disabled={busy}>
            <RefreshCw className={`h-4 w-4 ${busy ? 'animate-spin' : ''}`} aria-hidden="true" />
            Refresh
          </Button>
        </>}
      />
      <ServicesView rootDomain={domain || undefined} revision={revision} onBusyChange={setBusy} />
    </div>
  )
}

export default function ExposurePage() {
  // useUrlFilters reads useSearchParams, which the App Router requires to sit under a Suspense boundary.
  return (
    <Suspense fallback={null}>
      <ExposureView />
    </Suspense>
  )
}
