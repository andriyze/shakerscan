'use client'

import { useEffect, useRef, useState, type ReactNode } from 'react'
import { usePathname } from 'next/navigation'
import Link from '@/components/WorkspaceLink'
import {
  Activity,
  BookOpen,
  Bot,
  Boxes,
  Braces,
  Compass,
  FileArchive,
  KeyRound,
  Menu,
  Network,
  PackageCheck,
  Radar,
  Router,
  Server,
  ServerCog,
  ShieldCheck,
  TriangleAlert,
  X,
} from 'lucide-react'
import { buttonClasses, ToggleVisual } from '@/components/ui'
import { API_URL } from '@/lib/api'
import { productEdition } from '@/lib/pageTitle'
import { SHAKERSCAN_REPOSITORY_URL, SHAKERSCAN_WEBSITE_URL } from '@/lib/repository'
import { usePoll } from '@/lib/usePoll'
import { DEFAULT_EDITION_LABEL, navigationAllowed, workspaceEdition } from '@/lib/workspaceCapabilities'
import {
  deriveBuildIdentity,
  formatBuildIdentity,
  type BuildIdentity,
  type HealthBuildIdentity,
} from '@/lib/buildIdentity'

const navGroups: {
  heading: string | null
  badge?: string
  // Advanced groups/items are hidden unless the sidebar "show all" switch is on.
  advanced?: boolean
  items: { href: string; label: string; icon: ReactNode; advanced?: boolean; fleetOnly?: boolean }[]
}[] = [
  {
    heading: null,
    items: [
      {
        href: '/',
        label: 'Dashboard',
        icon: (
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
          </svg>
        ),
      },
      { href: '/docs', label: 'Docs', icon: <BookOpen className="w-5 h-5" /> },
    ],
  },
  {
    heading: 'Testing',
    items: [
      {
        href: '/targets',
        label: 'Targets',
        icon: (
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
          </svg>
        ),
      },
      {
        href: '/scans',
        label: 'DAST Scans',
        icon: (
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
          </svg>
        ),
      },
      { href: '/credentials', label: 'Credentials', icon: <KeyRound className="w-5 h-5" /> },
      { href: '/request-collections', label: 'Request Collections', icon: <Braces className="w-5 h-5" /> },
      { href: '/devices', label: 'Connected Devices', icon: <Router className="w-5 h-5" /> },
      {
        href: '/findings',
        label: 'Findings',
        icon: (
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
        ),
      },
      {
        href: '/schedules',
        label: 'Schedules',
        icon: (
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        ),
      },
    ],
  },
  {
    heading: 'Attack surface',
    items: [
      { href: '/exposure', label: 'Exposure', icon: <Network className="w-5 h-5" /> },
      { href: '/asm', label: 'Coverage', icon: <Radar className="w-5 h-5" /> },
    ],
  },
  {
    heading: 'AI Investigator',
    badge: 'Agentic',
    items: [
      { href: '/hunt', label: 'Hunts', icon: <Compass className="w-5 h-5" /> },
    ],
  },
  {
    heading: 'Records',
    advanced: true,
    items: [
      { href: '/evidence', label: 'Evidence', icon: <FileArchive className="w-5 h-5" /> },
      { href: '/timeline', label: 'Timeline', icon: <Activity className="w-5 h-5" /> },
    ],
  },
  {
    heading: 'Operations',
    items: [
      { href: '/workers', label: 'Worker Pools', icon: <Server className="w-5 h-5" /> },
      { href: '/fleet', label: 'Fleet', icon: <ServerCog className="w-5 h-5" />, fleetOnly: true },
    ],
  },
  {
    heading: 'AI security',
    items: [
      { href: '/ai-gate', label: 'AI Gate', icon: <Bot className="w-5 h-5" /> },
      { href: '/model-intake', label: 'Model Intake', icon: <PackageCheck className="w-5 h-5" />, advanced: true },
    ],
  },
  {
    heading: 'Governance',
    advanced: true,
    items: [
      { href: '/settings/policy-profiles', label: 'Policy Profiles', icon: <ShieldCheck className="w-5 h-5" /> },
    ],
  },
  {
    heading: 'Developer',
    advanced: true,
    items: [
      { href: '/settings/arsenal', label: 'Command Arsenal', icon: <Boxes className="w-5 h-5" /> },
    ],
  },
]

// Root-layout remounts (including React StrictMode's development probe) share one short-lived
// request. Failed requests are evicted immediately and mounted sidebars refresh after deployments.
const HEALTH_BUILD_IDENTITY_REFRESH_MS = 30_000
let healthBuildIdentityRequest: {
  promise: Promise<HealthBuildIdentity | null>
  expiresAt: number
} | null = null

function loadHealthBuildIdentity(force = false): Promise<HealthBuildIdentity | null> {
  const now = Date.now()
  if (force || !healthBuildIdentityRequest || healthBuildIdentityRequest.expiresAt <= now) {
    const promise = fetch(`${API_URL}/health`, { cache: 'no-store' })
      .then((response) => (response.ok ? response.json() : null))
      .catch(() => null)
    healthBuildIdentityRequest = { promise, expiresAt: now + HEALTH_BUILD_IDENTITY_REFRESH_MS }
    promise.then((health) => {
      if (!health && healthBuildIdentityRequest?.promise === promise) {
        healthBuildIdentityRequest = null
      }
    })
  }
  return healthBuildIdentityRequest.promise
}

// The ShakerScan S mark, the same drawing as public/favicon.svg: a blue S on its own dark tile,
// so it reads on any background. Its colours are the mark's own, not theme colours.
function BrandMark({ className = 'h-[22px] w-[22px]' }: { className?: string }) {
  return (
    <svg className={`${className} shrink-0`} fill="none" viewBox="0 0 32 32" aria-hidden="true" focusable="false">
      <rect width="32" height="32" rx="7" fill="#07090e" />
      <path d="M23 8H13L9 12L13 16H19L23 20L19 24H9" stroke="#3b82f6" strokeWidth={4} strokeLinecap="square" strokeLinejoin="round" />
    </svg>
  )
}

// "ShakerScan" in one weight, then the edition a managed deployment names as a quiet label
// after a hairline ("ShakerScan | Enterprise").
function BrandLockup({ edition, compact = false }: { edition?: string; compact?: boolean }) {
  return (
    <>
      <BrandMark className={compact ? 'h-5 w-5' : undefined} />
      <span className="text-base font-semibold leading-none tracking-[-0.012em]">ShakerScan</span>
      {edition ? (
        <span className="border-l border-gray-700 pl-2.5 text-[13px] font-medium leading-[14px] text-gray-400">
          {edition}
        </span>
      ) : null}
    </>
  )
}

function NavContent({
  pathname,
  showAll,
  onToggleShowAll,
  buildIdentity,
  fleetEnabled,
  editionLabel,
}: {
  editionLabel: string
  pathname: string
  showAll: boolean
  onToggleShowAll: (value: boolean) => void
  buildIdentity: BuildIdentity
  fleetEnabled: boolean
}) {
  const buildLabel = formatBuildIdentity(buildIdentity)
  const edition = productEdition(editionLabel)
  // Default view hides advanced groups/items; the footer switch reveals them.
  const visibleGroups = navGroups
    .filter((group) => showAll || !group.advanced)
    .map((group) => ({
      ...group,
      items: group.items.filter((item) => (
        (showAll || !item.advanced)
        && (!item.fleetOnly || fleetEnabled)
        && navigationAllowed(item.href)
      )),
    }))
    .filter((group) => group.items.length > 0)
  // Only the Settings landing lights the gear. The /settings/* sub-routes
  // (research-agent, arsenal) belong to their own nav groups.
  const settingsActive = pathname === '/settings'

  const isActive = (href: string) => {
    if (href === '/') {
      return pathname === '/'
    }
    if (href === '/hunt') {
      return pathname === href || pathname.startsWith('/hunt/')
    }
    return pathname.startsWith(href)
  }

  return (
    <>
      <div className="mb-8">
        {/* The link's name keeps the lockup's visible words ("ShakerScan Enterprise") in it. */}
        <Link
          href="/"
          aria-label={edition ? `ShakerScan ${edition} dashboard` : 'ShakerScan dashboard'}
          className="flex items-center gap-2.5 rounded-sm py-0.5 text-white focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500"
        >
          <BrandLockup edition={edition} />
        </Link>
        {/* The lockup already names an Enterprise edition; any other label stays on its own line. */}
        {!edition && <p className="text-xs text-gray-500 mt-2">{editionLabel}</p>}
        {(buildIdentity.ui || buildIdentity.api || buildIdentity.workers) && (
          <p
            className={`${edition ? 'mt-2' : 'mt-1'} flex items-center gap-1 text-[11px] ${buildIdentity.skew ? 'text-amber-300' : 'text-gray-400'}`}
            title={buildIdentity.skew ? 'Component build mismatch detected' : 'Component build identities'}
            role={buildIdentity.skew ? 'status' : undefined}
            aria-live={buildIdentity.skew ? 'polite' : undefined}
          >
            {buildIdentity.skew && <TriangleAlert className="h-3 w-3 shrink-0" aria-hidden="true" />}
            <span>{buildIdentity.skew ? `Build mismatch: ${buildLabel}` : buildLabel}</span>
          </p>
        )}
      </div>

      <nav className="flex-1">
        {visibleGroups.map((group, groupIndex) => (
          <div key={group.heading ?? 'overview'} className={`space-y-1 ${groupIndex === 0 ? '' : 'mt-4'}`}>
            {group.heading ? (
              <div className="flex items-center gap-1.5 px-3 pb-0.5 text-[10px] font-semibold uppercase tracking-wider text-gray-600">
                <span>{group.heading}</span>
                {group.badge ? (
                  <span className="inline-flex items-center rounded-full border border-violet-400/30 px-1.5 text-[10px] font-medium normal-case leading-4 tracking-normal text-violet-300">
                    {group.badge}
                  </span>
                ) : null}
              </div>
            ) : null}
            {group.items.map((item) => {
              const active = isActive(item.href)
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  // Every page fetches its own data on the client, so prefetching the route
                  // shell for all fourteen links on each navigation only adds a 307+200
                  // pair per link that the page's real API calls then queue behind.
                  prefetch={false}
                  aria-current={active ? 'page' : undefined}
                  className={`flex items-center gap-3 px-3 py-2 text-sm rounded-lg transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500 ${
                    active
                      ? 'bg-blue-600/20 text-blue-400 border-l-2 border-blue-500 ml-[-2px] pl-[14px]'
                      : 'hover:bg-gray-800 text-gray-300'
                  }`}
                >
                  {item.icon}
                  {item.label}
                </Link>
              )
            })}
          </div>
        ))}
      </nav>

      <div className="pt-4 mt-4 border-t border-gray-800">
        <Link
          href="/scan/new"
          className={`${buttonClasses('primary', 'md')} w-full`}
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          New Scan
        </Link>
      </div>

      <div className="pt-3 mt-4 border-t border-gray-800">
        <div className="flex items-center gap-1.5 px-1 text-[12.5px]">
          <a
            href={SHAKERSCAN_WEBSITE_URL}
            target="_blank"
            rel="noopener noreferrer"
            title={SHAKERSCAN_WEBSITE_URL}
            className="inline-flex items-center gap-1.5 rounded-sm text-gray-400 transition-colors hover:text-white focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500"
          >
            <BrandMark className="h-3.5 w-3.5" />
            shakerscan.com
          </a>
          <span className="text-gray-700" aria-hidden="true">·</span>
          <a
            href={SHAKERSCAN_REPOSITORY_URL}
            target="_blank"
            rel="noopener noreferrer"
            aria-label="ShakerScan on GitHub"
            title="Source code on GitHub"
            className="inline-flex items-center gap-1.5 rounded-sm text-gray-400 transition-colors hover:text-white focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500"
          >
            <svg className="h-3.5 w-3.5" fill="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.17 6.839 9.49.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.604-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.464-1.11-1.464-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.831.092-.646.35-1.086.636-1.336-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.578 9.578 0 0112 6.836c.85.004 1.705.114 2.504.336 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.578.688.48C19.138 20.167 22 16.418 22 12c0-5.523-4.477-10-10-10z" />
            </svg>
            GitHub
          </a>
        </div>
        <div className="mt-2 flex items-center justify-between pl-1">
          <button
            type="button"
            role="switch"
            aria-checked={showAll}
            onClick={() => onToggleShowAll(!showAll)}
            title="Show advanced sections (Records, Governance, Developer, Model Intake)"
            className="inline-flex items-center gap-2 rounded-md py-1 pr-1 text-[12.5px] text-gray-400 transition-colors hover:text-white focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500"
          >
            <ToggleVisual checked={showAll} />
            All sections
          </button>
          <Link
            href="/settings"
            aria-label="Settings"
            title="Settings"
            aria-current={settingsActive ? 'page' : undefined}
            className={`p-2 rounded-md transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500 ${
              settingsActive
                ? 'bg-blue-600/20 text-blue-400'
                : 'text-gray-400 hover:text-white hover:bg-gray-800'
            }`}
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M11.983 5.5a1.5 1.5 0 013.034 0l.184 1.145a1.5 1.5 0 001.126 1.192l1.132.286a1.5 1.5 0 01.76 2.49l-.773.862a1.5 1.5 0 000 1.998l.773.862a1.5 1.5 0 01-.76 2.49l-1.132.286a1.5 1.5 0 00-1.126 1.192l-.184 1.145a1.5 1.5 0 01-3.034 0l-.184-1.145a1.5 1.5 0 00-1.126-1.192l-1.132-.286a1.5 1.5 0 01-.76-2.49l.773-.862a1.5 1.5 0 000-1.998l-.773-.862a1.5 1.5 0 01.76-2.49l1.132-.286a1.5 1.5 0 001.126-1.192l.184-1.145z"
              />
              <circle cx="13.5" cy="12" r="2.5" strokeWidth={2} />
            </svg>
          </Link>
        </div>
      </div>
    </>
  )
}

export default function Sidebar() {
  const [editionLabel, setEditionLabel] = useState(DEFAULT_EDITION_LABEL)
  useEffect(() => {
    const label = workspaceEdition()
    if (label) setEditionLabel(label)
  }, [])
  const pathname = usePathname()
  const [mobileOpen, setMobileOpen] = useState(false)
  const [showAll, setShowAll] = useState(false)
  const bakedVersion = process.env.NEXT_PUBLIC_APP_VERSION
  const bakedExpectedApiFingerprint = process.env.NEXT_PUBLIC_EXPECTED_API_BUILD_FINGERPRINT
  const [buildIdentity, setBuildIdentity] = useState<BuildIdentity>({ ui: bakedVersion, skew: false })
  const [fleetEnabled, setFleetEnabled] = useState(false)
  const openerRef = useRef<HTMLButtonElement>(null)
  const drawerRef = useRef<HTMLElement>(null)
  const healthLoaded = useRef(false)

  // Fetch in the parent so opening the mobile drawer does not duplicate runtime requests.
  // Periodic refresh recovers from startup races and reflects a mid-session deploy.
  // The first read may reuse the cached health answer; later ticks force a fresh one.
  usePoll(async (signal) => {
    const health = await loadHealthBuildIdentity(healthLoaded.current)
    healthLoaded.current = true
    if (signal.aborted) return
    setBuildIdentity(deriveBuildIdentity(bakedVersion, health, bakedExpectedApiFingerprint))
    setFleetEnabled(health?.fleet?.enabled === true)
  }, { intervalMs: HEALTH_BUILD_IDENTITY_REFRESH_MS, deps: [bakedExpectedApiFingerprint, bakedVersion] })

  // Persist the "show all sections" preference across reloads (default off).
  useEffect(() => {
    try {
      setShowAll(window.localStorage.getItem('shakerscan.sidebar.show_all') === 'true')
    } catch {
      /* localStorage unavailable */
    }
  }, [])
  const handleToggleShowAll = (value: boolean) => {
    setShowAll(value)
    try {
      window.localStorage.setItem('shakerscan.sidebar.show_all', String(value))
    } catch {
      /* localStorage unavailable */
    }
  }

  // Close the mobile drawer whenever navigation happens.
  useEffect(() => {
    setMobileOpen(false)
  }, [pathname])

  // Accessible modal-drawer behavior: move focus in on open, trap Tab within the
  // drawer, close on Escape, and restore focus to the opener on close.
  useEffect(() => {
    if (!mobileOpen) return
    const opener = openerRef.current
    const focusables = () =>
      Array.from(
        drawerRef.current?.querySelectorAll<HTMLElement>(
          'a[href], button:not([disabled]), input, select, textarea, [tabindex]:not([tabindex="-1"])',
        ) ?? [],
      ).filter((el) => el.offsetParent !== null)
    focusables()[0]?.focus()
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setMobileOpen(false)
        return
      }
      if (event.key !== 'Tab') return
      const items = focusables()
      if (items.length === 0) return
      const first = items[0]
      const last = items[items.length - 1]
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault()
        first.focus()
      }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('keydown', onKeyDown)
      opener?.focus()
    }
  }, [mobileOpen])

  return (
    <>
      {/* Mobile: slim top bar instead of a viewport-eating sidebar. */}
      <div className="sticky top-0 z-40 flex items-center justify-between border-b border-gray-800 bg-gray-900 px-4 py-3 md:hidden">
        <Link href="/" className="flex items-center gap-2.5 text-white">
          <BrandLockup edition={productEdition(editionLabel)} compact />
        </Link>
        <button
          ref={openerRef}
          type="button"
          onClick={() => setMobileOpen(true)}
          aria-label="Open navigation"
          aria-expanded={mobileOpen}
          className="rounded-lg p-2 text-gray-300 hover:bg-gray-800 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500"
        >
          <Menu className="h-5 w-5" aria-hidden="true" />
        </button>
      </div>

      {mobileOpen && (
        <div className="fixed inset-0 z-50 md:hidden" role="dialog" aria-modal="true" aria-label="Navigation">
          {/* Backdrop is a mouse affordance only — hidden from the a11y tree and the tab
              order so it doesn't duplicate the labeled Close button; keyboard users use
              Escape or that button. */}
          <button
            type="button"
            aria-hidden="true"
            tabIndex={-1}
            className="absolute inset-0 bg-black/60"
            onClick={() => setMobileOpen(false)}
          />
          <aside
            ref={drawerRef}
            className="absolute left-0 top-0 flex h-full w-72 max-w-[85vw] flex-col overflow-y-auto border-r border-gray-800 bg-gray-900 p-4"
          >
            <div className="mb-2 flex justify-end">
              <button
                type="button"
                onClick={() => setMobileOpen(false)}
                aria-label="Close navigation"
                className="rounded-lg p-2 text-gray-300 hover:bg-gray-800 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500"
              >
                <X className="h-5 w-5" aria-hidden="true" />
              </button>
            </div>
            <NavContent editionLabel={editionLabel} pathname={pathname} showAll={showAll} onToggleShowAll={handleToggleShowAll} buildIdentity={buildIdentity} fleetEnabled={fleetEnabled} />
          </aside>
        </div>
      )}

      {/* Desktop: persistent sidebar. */}
      <aside className="sticky top-0 hidden h-screen w-64 shrink-0 flex-col overflow-y-auto overscroll-contain border-r border-gray-800 bg-gray-900 p-4 md:flex">
        <NavContent editionLabel={editionLabel} pathname={pathname} showAll={showAll} onToggleShowAll={handleToggleShowAll} buildIdentity={buildIdentity} fleetEnabled={fleetEnabled} />
      </aside>
    </>
  )
}
