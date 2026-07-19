'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { cn } from '@/lib/cn'

// One nav for the whole AI Investigator cluster so every page shows the same
// bar with the current page highlighted (previously each of the four pages
// hand-rolled a different strip). Operator + Explorer are grouped as the two
// "Engines"; Leads is a supporting tab; "Plan a test" is demoted to a link.
const BASE = '/settings/research-agent'

type TabId = 'operator' | 'explorer' | 'leads' | 'experiment'

function activeTab(pathname: string): TabId {
  if (pathname.startsWith(`${BASE}/explorer`)) return 'explorer'
  if (pathname.startsWith(`${BASE}/leads`)) return 'leads'
  if (pathname.startsWith(`${BASE}/experiment`)) return 'experiment'
  return 'operator' // hub + /runs/*
}

function seg(on: boolean): string {
  return cn(
    'rounded-md px-3 py-1.5 text-sm font-medium transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500',
    on ? 'bg-gray-800 text-white' : 'text-gray-400 hover:text-white',
  )
}

export function InvestigatorTabs() {
  const active = activeTab(usePathname())
  return (
    <nav aria-label="AI Investigator" className="flex flex-wrap items-center gap-x-3 gap-y-2">
      <div className="flex items-center gap-2">
        <span className="text-[10px] font-semibold uppercase tracking-wider text-gray-600">Engines</span>
        <div className="flex rounded-lg border border-gray-800 bg-gray-950 p-1">
          <Link href={BASE} aria-current={active === 'operator' ? 'page' : undefined} className={seg(active === 'operator')}>Operator</Link>
          <Link href={`${BASE}/explorer`} aria-current={active === 'explorer' ? 'page' : undefined} className={seg(active === 'explorer')}>Explorer</Link>
        </div>
      </div>
      <div className="flex rounded-lg border border-gray-800 bg-gray-950 p-1">
        <Link href={`${BASE}/leads`} aria-current={active === 'leads' ? 'page' : undefined} className={seg(active === 'leads')}>Leads</Link>
      </div>
      <Link
        href={`${BASE}/experiment`}
        aria-current={active === 'experiment' ? 'page' : undefined}
        className={cn('text-xs transition-colors', active === 'experiment' ? 'font-medium text-blue-300' : 'text-gray-500 hover:text-gray-300')}
      >
        Plan a test →
      </Link>
    </nav>
  )
}

// The one-line "these are the two engines" cue for the engine pages.
export function EngineHint() {
  return (
    <p className="text-[11px] text-gray-500">
      Operator <span className="text-blue-300">proves</span> · Explorer <span className="text-violet-300">discovers</span>
    </p>
  )
}
