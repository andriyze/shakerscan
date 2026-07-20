'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { cn } from '@/lib/cn'

// One small product navigation for AI investigation. Deep Hunt is the single
// user-facing engine; Leads and Test Builder support it. The legacy guided
// verifier remains an implementation surface, not a peer launcher.
const BASE = '/settings/research-agent'

type TabId = 'deep_hunt' | 'leads' | 'experiment'

function activeTab(pathname: string): TabId {
  if (pathname.startsWith(`${BASE}/leads`)) return 'leads'
  if (pathname.startsWith(`${BASE}/experiment`)) return 'experiment'
  return 'deep_hunt'
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
      <div className="flex rounded-lg border border-gray-800 bg-gray-950 p-1">
        <Link href={BASE} aria-current={active === 'deep_hunt' ? 'page' : undefined} className={seg(active === 'deep_hunt')}>Deep Hunt</Link>
        <Link href={`${BASE}/leads`} aria-current={active === 'leads' ? 'page' : undefined} className={seg(active === 'leads')}>Leads</Link>
        <Link href={`${BASE}/experiment`} aria-current={active === 'experiment' ? 'page' : undefined} className={seg(active === 'experiment')}>Test Builder</Link>
      </div>
    </nav>
  )
}

export function EngineHint() {
  return (
    <p className="text-[11px] text-gray-500">
      AI-driven exploration · bounded exploitation · deterministic verification
    </p>
  )
}
