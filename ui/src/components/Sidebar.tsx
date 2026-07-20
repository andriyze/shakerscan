'use client'

import { useEffect, useRef, useState, type ReactNode } from 'react'
import { usePathname } from 'next/navigation'
import Link from 'next/link'
import { Activity, Bot, Boxes, Compass, Crosshair, FileArchive, Lightbulb, Menu, Network, PackageCheck, Radar, ShieldAlert, ShieldCheck, Wand2, X } from 'lucide-react'
import { buttonClasses } from '@/components/ui'

const navGroups: {
  heading: string | null
  badge?: string
  items: { href: string; label: string; icon: ReactNode }[]
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
      {
        href: '/interactive',
        label: 'Interactive Testing',
        icon: <Crosshair className="w-5 h-5" />,
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
    badge: 'Alpha',
    items: [
      { href: '/settings/research-agent', label: 'Deep Hunt', icon: <Compass className="w-5 h-5" /> },
      { href: '/settings/research-agent/leads', label: 'Leads', icon: <Lightbulb className="w-5 h-5" /> },
    ],
  },
  {
    heading: 'Records',
    items: [
      { href: '/evidence', label: 'Evidence', icon: <FileArchive className="w-5 h-5" /> },
      { href: '/timeline', label: 'Timeline', icon: <Activity className="w-5 h-5" /> },
    ],
  },
  {
    heading: 'AI security',
    items: [
      { href: '/ai-gate', label: 'AI Gate', icon: <Bot className="w-5 h-5" /> },
      { href: '/model-intake', label: 'Model Intake', icon: <PackageCheck className="w-5 h-5" /> },
    ],
  },
  {
    heading: 'Governance',
    items: [
      { href: '/settings/policy-profiles', label: 'Policy Profiles', icon: <ShieldCheck className="w-5 h-5" /> },
      { href: '/exceptions', label: 'Exceptions Queue', icon: <ShieldAlert className="w-5 h-5" /> },
    ],
  },
  {
    heading: 'Developer',
    items: [
      { href: '/settings/arsenal', label: 'Command Arsenal', icon: <Boxes className="w-5 h-5" /> },
      { href: '/settings/ai-ops-router', label: 'AI Ops Router', icon: <Wand2 className="w-5 h-5" /> },
    ],
  },
]

function BrandMark({ className = 'w-6 h-6' }: { className?: string }) {
  return (
    <svg className={`${className} text-blue-500`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
    </svg>
  )
}

function NavContent({ pathname }: { pathname: string }) {
  const appVersion = process.env.NEXT_PUBLIC_APP_VERSION
  // Only the Settings landing lights the gear. The /settings/* sub-routes
  // (research-agent, arsenal, ai-ops-router) belong to their own nav groups.
  const settingsActive = pathname === '/settings'

  const isActive = (href: string) => {
    if (href === '/') {
      return pathname === '/'
    }
    if (href === '/settings/research-agent') {
      // Deep Hunt is the canonical investigator launcher; keep it lit across its
      // cluster pages that have no sidebar entry of their own (run detail and
      // Test Builder). Leads highlights its own item.
      return (
        pathname === href ||
        pathname.startsWith('/settings/research-agent/runs') ||
        pathname.startsWith('/settings/research-agent/experiment')
      )
    }
    return pathname.startsWith(href)
  }

  return (
    <>
      <div className="mb-8">
        <h1 className="text-xl font-bold text-white flex items-center gap-2">
          <BrandMark />
          ShakerScan
        </h1>
        <p className="text-xs text-gray-500 mt-1">Open Source Edition</p>
        {appVersion && (
          <p className="text-[10px] text-gray-600 mt-1">Build {appVersion}</p>
        )}
      </div>

      <nav className="flex-1">
        {navGroups.map((group, groupIndex) => (
          <div key={group.heading ?? 'overview'} className={`space-y-1 ${groupIndex === 0 ? '' : 'mt-4'}`}>
            {group.heading ? (
              <div className="flex items-center gap-1.5 px-3 pb-0.5 text-[10px] font-semibold uppercase tracking-wider text-gray-600">
                <span>{group.heading}</span>
                {group.badge ? (
                  <span className="rounded-full border border-blue-500/30 bg-blue-500/10 px-1.5 py-px text-[8px] font-bold tracking-wider text-blue-400">
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
                  aria-current={active ? 'page' : undefined}
                  className={`flex items-center gap-3 px-3 py-2 text-sm rounded-lg transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                    active
                      ? 'bg-blue-600/20 text-blue-400 border-l-2 border-blue-500 -ml-[2px] pl-[14px]'
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

      <div className="pt-4 mt-4 border-t border-gray-800">
        <div className="flex items-center justify-between">
          <a
            href="https://github.com/andriyze/shakerscan"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="ShakerScan on GitHub"
            className="flex items-center gap-2 px-3 py-2 text-sm text-gray-400 hover:text-white transition-colors rounded-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
          >
            <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
              <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.17 6.839 9.49.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.604-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.464-1.11-1.464-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.831.092-.646.35-1.086.636-1.336-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.578 9.578 0 0112 6.836c.85.004 1.705.114 2.504.336 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.578.688.48C19.138 20.167 22 16.418 22 12c0-5.523-4.477-10-10-10z" />
            </svg>
            GitHub
          </a>
          <Link
            href="/settings"
            aria-label="Settings"
            title="Settings"
            aria-current={settingsActive ? 'page' : undefined}
            className={`p-2 rounded-md transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
              settingsActive
                ? 'bg-blue-600/20 text-blue-400'
                : 'text-gray-400 hover:text-white hover:bg-gray-800'
            }`}
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
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
  const pathname = usePathname()
  const [mobileOpen, setMobileOpen] = useState(false)
  const openerRef = useRef<HTMLButtonElement>(null)
  const drawerRef = useRef<HTMLElement>(null)

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
        <Link href="/" className="flex items-center gap-2 text-base font-bold text-white">
          <BrandMark className="w-5 h-5" />
          ShakerScan
        </Link>
        <button
          ref={openerRef}
          type="button"
          onClick={() => setMobileOpen(true)}
          aria-label="Open navigation"
          aria-expanded={mobileOpen}
          className="rounded-lg p-2 text-gray-300 hover:bg-gray-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
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
                className="rounded-lg p-2 text-gray-300 hover:bg-gray-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
              >
                <X className="h-5 w-5" aria-hidden="true" />
              </button>
            </div>
            <NavContent pathname={pathname} />
          </aside>
        </div>
      )}

      {/* Desktop: persistent sidebar. */}
      <aside className="sticky top-0 hidden h-screen w-64 shrink-0 flex-col overflow-y-auto overscroll-contain border-r border-gray-800 bg-gray-900 p-4 md:flex">
        <NavContent pathname={pathname} />
      </aside>
    </>
  )
}
