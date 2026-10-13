'use client'

import { Suspense, useEffect, useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { getDomains } from '@/lib/api'
import { useUrlFilters } from '@/lib/useUrlFilters'
import { Button } from '@/components/ui'
import { ServicesView } from './ServicesView'
import styles from './exposure.module.css'

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
    <div className={styles.page}>
      <div className={styles.pageGlow} aria-hidden="true" />
      <div className={`${styles.content} space-y-6`}>
        <div className={`flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between ${styles.rise} ${styles.d1}`}>
          <div>
            <h1 className={`${styles.displayTitle} text-2xl font-bold text-white`}>Exposure</h1>
            <p className="mt-1 text-sm text-gray-400">
              Services on your targets: each listener, the product and version observed on it, and the weaknesses known
              for that version.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <select
              value={domain}
              onChange={(event) => setFilter('domain', event.target.value || undefined)}
              aria-label="Filter by domain"
              className={`px-3 py-2 text-sm text-white ${styles.input}`}
            >
              <option value="">All domains</option>
              {domains.map((item) => (
                <option key={item} value={item}>{item}</option>
              ))}
            </select>
            <Button onClick={() => setRevision((value) => value + 1)} disabled={busy}>
              <RefreshCw className={`h-4 w-4 ${busy ? 'animate-spin' : ''}`} aria-hidden="true" />
              Refresh
            </Button>
          </div>
        </div>
        <div className={`${styles.rise} ${styles.d2}`}>
          <ServicesView rootDomain={domain || undefined} revision={revision} onBusyChange={setBusy} />
        </div>
      </div>
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
