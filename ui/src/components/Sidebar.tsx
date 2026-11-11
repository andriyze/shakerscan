'use client'

import { useEffect, useId, useRef, useState, type ReactNode } from 'react'
import { usePathname } from 'next/navigation'
import Link from '@/components/WorkspaceLink'
import {
  Activity,
  BookOpen,
  Bot,
  Boxes,
  Braces,
  ChevronDown,
  ChevronRight,
  ChevronsUpDown,
  Compass,
  FileArchive,
  Globe,
  KeyRound,
  Menu,
  Network,
  PackageCheck,
  Radar,
  Router,
  Server,
  ServerCog,
  Settings,
  ShieldCheck,
  TriangleAlert,
  X,
} from 'lucide-react'
import { buttonClasses } from '@/components/ui'
import { ExtensionIcon } from '@/components/extensions/ExtensionIcon'
import { API_URL } from '@/lib/api'
import { productEdition } from '@/lib/pageTitle'
import { SHAKERSCAN_REPOSITORY_URL, SHAKERSCAN_WEBSITE_URL } from '@/lib/repository'
import { usePoll } from '@/lib/usePoll'
import { DEFAULT_EDITION_LABEL, navigationAllowed, workspaceEdition, workspaceExtensions } from '@/lib/workspaceCapabilities'
import { placeNavigation, sameOriginPath, type ExtensionAccount } from '@/lib/uiExtensions.mjs'
import { useCan, usePageAllowed } from '@/lib/useSessionCapabilities'
import { useWorkspaceIsManaged } from '@/components/hunt/TerminalHuntStart'
import {
  deriveBuildIdentity,
  formatBuildIdentity,
  type BuildIdentity,
  type HealthBuildIdentity,
} from '@/lib/buildIdentity'

const navGroups: {
  heading: string | null
  badge?: string
  // Advanced groups/items are hidden unless the sidebar "show all" switch is on. A managed
  // workspace has no switch: its gateway's navigation list decides, so every page it allows shows.
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

const focusRing = 'focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500'
// One row of the menu: a page link, the "More" row and Settings share it.
const menuRow = `flex items-center gap-3 px-3 py-2 text-sm rounded-lg transition-colors ${focusRing}`
const menuRowActive = 'bg-blue-600/20 text-blue-400 border-l-2 border-blue-500 ml-[-2px] pl-[14px]'
const menuRowIdle = 'hover:bg-gray-800 text-gray-300'
const accountLink = `block rounded-md px-2.5 py-1.5 text-[13.5px] text-gray-300 transition-colors hover:bg-gray-800 hover:text-white ${focusRing}`

// The quiet line that says what is running: "Open Source 2.12.3". An Enterprise edition is
// already named in the lockup, so there it is "Version 2.12.3". A build mismatch is spelled out
// under the logo instead, and this line then carries no version.
function aboutLine(editionLabel: string, edition: string | undefined, identity: BuildIdentity): string {
  const name = edition ? '' : editionLabel.replace(/\s+Edition$/i, '')
  if (identity.skew) return name
  const build = formatBuildIdentity(identity)
  if (!name) return build
  return build.startsWith('Version ') ? `${name} ${build.slice('Version '.length)}` : [name, build].filter(Boolean).join(' · ')
}

// Who is signed in, where a managed deployment says so (ui-extensions/v1): one row that opens
// the deployment's own links, Sign out and the running version above it. The links are
// ordinary navigations on this origin, never requests the UI makes. The row is drawn inside the
// sidebar's foot (see NavContent), which stays in view when the menu is taller than the window
// (only the menu scrolls), so the person's name never needs a scroll to be found.
function AccountMenu({ account, about }: { account: ExtensionAccount; about: string }) {
  const [open, setOpen] = useState(false)
  const root = useRef<HTMLElement>(null)
  const trigger = useRef<HTMLButtonElement>(null)
  const id = useId()
  const origin = window.location.origin
  const links = account.links
    .map((link) => ({ label: link.label, href: sameOriginPath(link.href, origin) }))
    .filter((link): link is { label: string; href: string } => link.href !== null)
  const signOut = account.sign_out ? sameOriginPath(account.sign_out, origin) : null
  // A role that only repeats the name ("Administrator / Administrator") is left out.
  const detail = account.detail && account.detail.trim().toLowerCase() !== account.name.trim().toLowerCase()
    ? account.detail
    : null

  useEffect(() => {
    if (!open) return
    const onPointer = (event: PointerEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(false)
    }
    // Capture phase: Escape closes this panel first, not the phone drawer around it.
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return
      event.stopPropagation()
      setOpen(false)
      trigger.current?.focus()
    }
    document.addEventListener('pointerdown', onPointer)
    document.addEventListener('keydown', onKey, true)
    return () => {
      document.removeEventListener('pointerdown', onPointer)
      document.removeEventListener('keydown', onKey, true)
    }
  }, [open])

  const who = (
    <>
      <span aria-hidden="true" className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-gray-800 text-xs font-semibold uppercase text-gray-200">
        {Array.from(account.name)[0]}
      </span>
      <span className="min-w-0 flex-1">
        <span className="block truncate text-sm font-medium leading-5 text-gray-200" title={account.name}>{account.name}</span>
        {detail && <span className="block truncate text-xs leading-4 text-gray-400">{detail}</span>}
      </span>
    </>
  )
  // With nothing to open, the row only names the person.
  if (links.length === 0 && !signOut && !about) {
    return <section aria-label="Account" className="flex items-center gap-2.5 px-1.5 py-3.5">{who}</section>
  }
  return (
    <section ref={root} aria-label="Account" className="relative py-2">
      <button
        ref={trigger}
        type="button"
        aria-expanded={open}
        aria-controls={id}
        onClick={() => setOpen(!open)}
        className={`flex w-full items-center gap-2.5 rounded-lg px-1.5 py-1.5 text-left transition-colors hover:bg-gray-800 ${focusRing} ${open ? 'bg-gray-800' : ''}`}
      >
        {who}
        <ChevronsUpDown className="h-4 w-4 shrink-0 text-gray-500" aria-hidden="true" />
      </button>
      {/* After the row in the document, above it on screen: Tab goes from the row into the panel. */}
      <div
        id={id}
        hidden={!open}
        className="absolute inset-x-0 bottom-full z-10 mb-1 rounded-xl border border-gray-700 bg-gray-900 p-1.5 shadow-2xl shadow-black/60"
      >
        {links.map((link) => <a key={`${link.label} ${link.href}`} href={link.href} className={accountLink}>{link.label}</a>)}
        {signOut && <a href={signOut} className={accountLink}>Sign out</a>}
        {about && (
          <p className={`px-2.5 pb-0.5 text-[11.5px] tabular-nums text-gray-400 ${links.length > 0 || signOut ? 'mt-1.5 border-t border-gray-800 pt-2' : 'pt-0.5'}`}>
            {about}
          </p>
        )}
      </div>
    </section>
  )
}

function NavContent({
  pathname,
  showAll,
  preferenceLoaded,
  onToggleShowAll,
  buildIdentity,
  fleetEnabled,
  editionLabel,
  managed,
}: {
  editionLabel: string
  managed: boolean
  pathname: string
  showAll: boolean
  preferenceLoaded: boolean
  onToggleShowAll: (value: boolean) => void
  buildIdentity: BuildIdentity
  fleetEnabled: boolean
}) {
  const buildLabel = formatBuildIdentity(buildIdentity)
  const edition = productEdition(editionLabel)
  const pageAllowed = usePageAllowed()
  const canStartScan = useCan('scans.start')
  // A managed deployment may add entries and sections of its own (ui-extensions/v1). A hosted
  // page is a route of this UI and is filtered like one; any other entry is the deployment's
  // own same-origin page, offered as declared.
  const extensions = workspaceExtensions()
  const origin = typeof window === 'undefined' ? '' : window.location.origin
  const groups = placeNavigation(navGroups, extensions).map((group) => ({
    ...group,
    items: group.items.filter((item) => {
      if ('extension' in item) {
        return item.hosted ? navigationAllowed(item.href) && pageAllowed(item.href) : sameOriginPath(item.href, origin) !== null
      }
      return (!item.fleetOnly || fleetEnabled) && navigationAllowed(item.href) && pageAllowed(item.href)
    }),
  }))
  type NavItem = (typeof groups)[number]['items'][number]
  // A managed workspace shows every page its navigation list allows, each in its own section.
  // Standalone, the advanced pages wait behind the "More" row that ends the menu.
  const inMore = (group: (typeof groups)[number], item: NavItem) =>
    !managed && (group.advanced === true || (!('extension' in item) && item.advanced === true))
  const visibleGroups = groups
    .map((group) => ({ ...group, items: group.items.filter((item) => !inMore(group, item)) }))
    .filter((group) => group.items.length > 0)
  const moreItems = managed ? [] : groups.flatMap((group) => group.items.filter((item) => inMore(group, item)))
  const moreId = useId()
  const moreRef = useRef<HTMLDivElement>(null)
  const moreRowRef = useRef<HTMLDivElement>(null)
  // The closed row stays at the foot of the menu; a page scrolled into view must clear it.
  const pinnedMore = moreItems.length > 0 && !showAll
  // Set by a press that opens the row: the menu then shows what the press added.
  const moreOpenedByHand = useRef(false)
  const toggleMore = () => {
    moreOpenedByHand.current = !showAll
    onToggleShowAll(!showAll)
  }
  // Where a deployment names who is signed in, the sidebar's foot is that person's row.
  const account = extensions.account
  const about = aboutLine(editionLabel, edition, buildIdentity)
  const settingsAllowed = navigationAllowed('/settings') && pageAllowed('/settings')
  const newScan = canStartScan && pageAllowed('/scan/new') ? (
    <Link
      href="/scan/new"
      className={`${buttonClasses('primary', 'md')} w-full`}
    >
      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
      </svg>
      New Scan
    </Link>
  ) : null
  // Only the Settings landing lights the Settings row. The /settings/* sub-routes
  // (research-agent, arsenal) belong to their own nav groups.
  const settingsActive = pathname === '/settings'

  // In a window shorter than the menu only the list of pages scrolls; the brand and New Scan
  // above it and the foot below it stay in view. Keep the current page, which may sit below the
  // fold of that list, in view when the page opens and whenever the room left for the list
  // changes. A press on "More" is the exception: the pages it adds sit below the fold of a full
  // menu, so the menu scrolls to them, as far as the row itself stays in view.
  const menuRef = useRef<HTMLElement>(null)
  useEffect(() => {
    const menu = menuRef.current
    if (!menu) return
    const showCurrent = () => {
      const current = menu.querySelector<HTMLElement>('[aria-current="page"]')
      if (!current) return
      const frame = menu.getBoundingClientRect()
      const box = current.getBoundingClientRect()
      const pinned = showAll ? 0 : moreRowRef.current?.getBoundingClientRect().height ?? 0
      if (box.top < frame.top) menu.scrollTop -= frame.top - box.top + 8
      else if (box.bottom > frame.bottom - pinned) menu.scrollTop += box.bottom - (frame.bottom - pinned) + 8
    }
    const opened = moreOpenedByHand.current ? moreRef.current : null
    moreOpenedByHand.current = false
    if (opened && moreRowRef.current) {
      const frame = menu.getBoundingClientRect()
      const below = opened.getBoundingClientRect().bottom - frame.bottom + 8
      const room = moreRowRef.current.getBoundingClientRect().top - frame.top - 8
      if (below > 0) menu.scrollTop += Math.max(0, Math.min(below, room))
    } else {
      showCurrent()
    }
    if (typeof ResizeObserver === 'undefined') return
    // An observer reports once when it starts; that report is no change of room.
    let started = false
    const observer = new ResizeObserver(() => {
      if (started) showCurrent()
      started = true
    })
    observer.observe(menu)
    return () => observer.disconnect()
  }, [pathname, showAll, managed])

  const isActive = (href: string) => {
    if (href === '/') {
      return pathname === '/'
    }
    if (href === '/hunt') {
      return pathname === href || pathname.startsWith('/hunt/')
    }
    return pathname.startsWith(href)
  }

  const renderItem = (item: NavItem) => {
    const declared = 'extension' in item
    const active = declared ? pathname === item.href : isActive(item.href)
    const className = `${menuRow} ${active ? menuRowActive : menuRowIdle}`
    // A deployment's own page is not a route of this UI: a plain navigation.
    if (declared && !item.hosted) {
      return (
        <a key={`${item.label} ${item.href}`} href={sameOriginPath(item.href, origin) ?? undefined} className={className}>
          <ExtensionIcon name={item.icon} />
          {item.label}
        </a>
      )
    }
    return (
      <Link
        key={item.href}
        href={item.href}
        // Every page fetches its own data on the client, so prefetching the route
        // shell for all fourteen links on each navigation only adds a 307+200
        // pair per link that the page's real API calls then queue behind.
        prefetch={false}
        aria-current={active ? 'page' : undefined}
        className={className}
      >
        {declared ? <ExtensionIcon name={item.icon} /> : item.icon}
        {item.label}
      </Link>
    )
  }

  return (
    <>
      <div className="mb-4 shrink-0">
        {/* The link's name keeps the lockup's visible words ("ShakerScan Enterprise") in it. */}
        <Link
          href="/"
          aria-label={edition ? `ShakerScan ${edition} dashboard` : 'ShakerScan dashboard'}
          className={`flex items-center gap-2.5 rounded-sm py-0.5 text-white ${focusRing}`}
        >
          <BrandLockup edition={edition} />
        </Link>
        {/* The corner is the logo and the primary action. Only a build mismatch adds a line. */}
        {buildIdentity.skew && buildLabel && (
          <p
            className="mt-2 flex items-center gap-1 text-[11px] text-amber-300"
            title="Component build mismatch detected"
            role="status"
            aria-live="polite"
          >
            <TriangleAlert className="h-3 w-3 shrink-0" aria-hidden="true" />
            <span>{`Build mismatch: ${buildLabel}`}</span>
          </p>
        )}
        {newScan && <div className="mt-4">{newScan}</div>}
      </div>

      {/* The margins and padding keep focus rings and the active marker inside the scrolling box. */}
      <nav ref={menuRef} className={`-mx-4 -my-1 min-h-24 flex-1 overflow-y-auto overscroll-contain px-4 py-1 ${pinnedMore ? 'scroll-pb-11' : ''}`}>
        {visibleGroups.map((group, groupIndex) => (
          <div key={`${groupIndex} ${group.heading ?? 'overview'}`} className={`space-y-1 ${groupIndex === 0 ? '' : 'mt-4'}`}>
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
            {group.items.map(renderItem)}
          </div>
        ))}
        {moreItems.length > 0 && (
          <>
            {/* Closed, the row holds the foot of a menu taller than its window, so it is never
                below the fold; open, it heads the pages it added and scrolls with them. */}
            <div
              ref={moreRowRef}
              className={showAll ? 'mt-4' : 'sticky bottom-0 z-[1] -mb-1 mt-4 bg-gray-900 pb-1 before:pointer-events-none before:absolute before:inset-x-0 before:-top-4 before:h-4 before:bg-linear-to-t before:from-gray-900 before:to-transparent'}
            >
            <button
              type="button"
              aria-expanded={showAll}
              aria-controls={moreId}
              // The server-rendered row has no handler until the page hydrates, and the saved
              // preference has not been read yet: a click then would be lost or overwritten.
              disabled={!preferenceLoaded}
              onClick={toggleMore}
              className={`${menuRow} w-full text-left text-gray-400 hover:bg-gray-800 hover:text-gray-200`}
            >
              {showAll
                ? <ChevronDown className="h-5 w-5 shrink-0" aria-hidden="true" />
                : <ChevronRight className="h-5 w-5 shrink-0" aria-hidden="true" />}
              More
              {!showAll && (
                <span className="ml-auto text-xs text-gray-500">
                  {moreItems.length} {moreItems.length === 1 ? 'page' : 'pages'}
                </span>
              )}
            </button>
            </div>
            <div id={moreId} ref={moreRef} hidden={!showAll} className="mt-1 space-y-1">
              {showAll && moreItems.map(renderItem)}
            </div>
          </>
        )}
      </nav>

      {(settingsAllowed || !account) && (
        <div className="mt-4 shrink-0 space-y-2 border-t border-gray-800 pt-3">
          {settingsAllowed && (
            <Link
              href="/settings"
              prefetch={false}
              aria-current={settingsActive ? 'page' : undefined}
              className={`${menuRow} ${settingsActive ? menuRowActive : menuRowIdle}`}
            >
              <Settings className="h-5 w-5" aria-hidden="true" />
              Settings
            </Link>
          )}
          {/* What is running and, in a standalone install, the two ways out: the website and the
              source code. A managed deployment links to neither. */}
          {!account && (about || !managed) && (
            <div className="flex min-h-6 items-center justify-between gap-2 px-3 text-[11.5px] tabular-nums text-gray-400">
              <span className="truncate" title={about}>{about}</span>
              {!managed && (
                <span className="flex shrink-0 items-center gap-2">
                  <a
                    href={SHAKERSCAN_WEBSITE_URL}
                    target="_blank"
                    rel="noopener noreferrer"
                    aria-label="shakerscan.com"
                    title="shakerscan.com"
                    className={`rounded-sm p-1 text-gray-400 transition-colors hover:text-white ${focusRing}`}
                  >
                    <Globe className="h-4 w-4" aria-hidden="true" />
                  </a>
                  <a
                    href={SHAKERSCAN_REPOSITORY_URL}
                    target="_blank"
                    rel="noopener noreferrer"
                    aria-label="ShakerScan on GitHub"
                    title="Source code on GitHub"
                    className={`-mr-1 rounded-sm p-1 text-gray-400 transition-colors hover:text-white ${focusRing}`}
                  >
                    <svg className="h-4 w-4" fill="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                      <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.17 6.839 9.49.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.604-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.464-1.11-1.464-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.831.092-.646.35-1.086.636-1.336-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.578 9.578 0 0112 6.836c.85.004 1.705.114 2.504.336 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.578.688.48C19.138 20.167 22 16.418 22 12c0-5.523-4.477-10-10-10z" />
                    </svg>
                  </a>
                </span>
              )}
            </div>
          )}
        </div>
      )}

      {/* The negative offset and margins take the foot over the sidebar's own padding, flush
          with its edges. */}
      {account && (
        <div className="sticky -bottom-4 -mx-4 -mb-4 mt-4 shrink-0 border-t border-gray-800 bg-gray-900 px-2.5">
          <AccountMenu account={account} about={about} />
        </div>
      )}
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
  const [preferenceLoaded, setPreferenceLoaded] = useState(false)
  const managed = useWorkspaceIsManaged()
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

  // Whether the "More" row is open is kept across reloads (closed by default).
  useEffect(() => {
    try {
      setShowAll(window.localStorage.getItem('shakerscan.sidebar.show_all') === 'true')
    } catch {
      /* localStorage unavailable */
    }
    setPreferenceLoaded(true)
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
            <NavContent editionLabel={editionLabel} managed={managed} pathname={pathname} showAll={showAll} preferenceLoaded={preferenceLoaded} onToggleShowAll={handleToggleShowAll} buildIdentity={buildIdentity} fleetEnabled={fleetEnabled} />
          </aside>
        </div>
      )}

      {/* Desktop: persistent sidebar. */}
      <aside className="sticky top-0 hidden h-screen w-64 shrink-0 flex-col overflow-y-auto overscroll-contain border-r border-gray-800 bg-gray-900 p-4 md:flex">
        <NavContent editionLabel={editionLabel} managed={managed} pathname={pathname} showAll={showAll} preferenceLoaded={preferenceLoaded} onToggleShowAll={handleToggleShowAll} buildIdentity={buildIdentity} fleetEnabled={fleetEnabled} />
      </aside>
    </>
  )
}
