'use client'

import { useEffect, useState, type ReactNode } from 'react'
import { Card, CardSkeleton, PageHeader } from '@/components/ui'
import { getHealth } from '@/lib/api'

const ENABLE_COMMAND = 'shakerscan model-intake enable'

// Model Intake is an optional module (2.10): a new install leaves it off. With it off, the page
// explains what it does and how to install it, and nothing else on the page runs (no Model Intake
// request is made). An engine that predates the setting reports no `enabled` field: treated as on.
export function ModelIntakeModuleGate({ children }: { children: ReactNode }) {
  const [state, setState] = useState<'loading' | 'enabled' | 'disabled'>('loading')
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    let active = true
    getHealth()
      .then((health) => {
        if (active) setState(health?.model_intake_worker?.enabled === false ? 'disabled' : 'enabled')
      })
      .catch(() => { if (active) setState('enabled') })
    return () => { active = false }
  }, [])

  if (state === 'loading') return <CardSkeleton />
  if (state === 'enabled') return <>{children}</>
  return (
    <div className="min-w-0 max-w-full space-y-6">
      <PageHeader title="Model Intake" description="Optional module: not installed on this instance." />
      <Card>
        <div className="space-y-4 text-sm text-gray-300">
          <p>
            Model Intake checks AI models before you deploy them: it fetches a model from a registry such as Hugging Face,
            scans its files for unsafe serialization and known malicious patterns in an isolated sandbox, and records a
            signed admission decision.
          </p>
          <p>
            It ships as two extra images (about 4.8 GB), so a new install leaves it off. To install it, run this on the
            host where ShakerScan runs:
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <code className="rounded-sm border border-gray-700 bg-gray-950 px-3 py-2 font-mono text-gray-100">{ENABLE_COMMAND}</code>
            <button
              type="button"
              onClick={() => {
                void navigator.clipboard?.writeText(ENABLE_COMMAND).then(() => setCopied(true)).catch(() => {})
              }}
              className="rounded-sm border border-gray-700 px-3 py-2 text-xs text-gray-200 hover:bg-gray-800 focus:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500"
            >
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
          <p className="text-xs text-gray-500">
            The images come from the same verified release as the rest of this install. Existing Model Intake records stay
            readable while the module is off; <code className="font-mono">shakerscan model-intake disable</code> turns it off again.
          </p>
        </div>
      </Card>
    </div>
  )
}
