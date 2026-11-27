'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { cn } from '@/lib/cn'

export interface SectionTab {
  key: string
  label: string
  /** A short count or state shown after the label. */
  badge?: string | number
  /** Tone of the badge; defaults to neutral. */
  badgeTone?: 'neutral' | 'danger' | 'warning' | 'success'
}

const BADGE_TONES: Record<NonNullable<SectionTab['badgeTone']>, string> = {
  neutral: 'bg-gray-800 text-gray-300',
  danger: 'bg-red-500/15 text-red-300',
  warning: 'bg-amber-500/15 text-amber-200',
  success: 'bg-emerald-500/15 text-emerald-300',
}

/**
 * The selected section of a long page, kept in the URL (`?<param>=<key>`) so a link or reload
 * lands on the same section. Updates use history.replaceState: switching sections is not a
 * navigation, so it neither refetches the page nor adds history entries.
 */
export function useSectionTab(keys: string[], fallback: string, param = 'tab'): [string, (key: string) => void] {
  const [active, setActive] = useState(fallback)
  const keyList = keys.join('|')
  useEffect(() => {
    const requested = new URLSearchParams(window.location.search).get(param)
    if (requested && keyList.split('|').includes(requested)) setActive(requested)
  }, [keyList, param])
  const select = useCallback((key: string) => {
    setActive(key)
    const url = new URL(window.location.href)
    if (key === fallback) url.searchParams.delete(param)
    else url.searchParams.set(param, key)
    window.history.replaceState(window.history.state, '', `${url.pathname}${url.search}${url.hash}`)
  }, [fallback, param])
  return [active, select]
}

/** WAI-ARIA tabs: arrow keys, Home and End move between tabs; panels are SectionTabPanel. */
export function SectionTabs({
  id,
  tabs,
  active,
  onChange,
  ariaLabel,
  className = '',
}: {
  id: string
  tabs: SectionTab[]
  active: string
  onChange: (key: string) => void
  ariaLabel: string
  className?: string
}) {
  const refs = useRef<Array<HTMLButtonElement | null>>([])
  const focusTab = (index: number) => {
    const next = (index + tabs.length) % tabs.length
    refs.current[next]?.focus()
    onChange(tabs[next].key)
  }
  return (
    <div
      role="tablist"
      aria-label={ariaLabel}
      className={cn('no-print -mx-1 flex gap-1 overflow-x-auto border-b border-gray-800 px-1', className)}
    >
      {tabs.map((tab, index) => {
        const selected = tab.key === active
        return (
          <button
            key={tab.key}
            ref={(element) => { refs.current[index] = element }}
            type="button"
            role="tab"
            id={`${id}-tab-${tab.key}`}
            aria-selected={selected}
            aria-controls={`${id}-panel-${tab.key}`}
            tabIndex={selected ? 0 : -1}
            onClick={() => onChange(tab.key)}
            onKeyDown={(event) => {
              if (event.key === 'ArrowRight') { event.preventDefault(); focusTab(index + 1) }
              else if (event.key === 'ArrowLeft') { event.preventDefault(); focusTab(index - 1) }
              else if (event.key === 'Home') { event.preventDefault(); focusTab(0) }
              else if (event.key === 'End') { event.preventDefault(); focusTab(tabs.length - 1) }
            }}
            className={cn(
              '-mb-px inline-flex shrink-0 items-center gap-2 border-b-2 px-3 py-2.5 text-sm font-medium transition-colors',
              'focus:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500 rounded-t-sm',
              selected ? 'border-blue-500 text-white' : 'border-transparent text-gray-400 hover:border-gray-600 hover:text-gray-200',
            )}
          >
            {tab.label}
            {tab.badge !== undefined && tab.badge !== '' && (
              <span className={cn('rounded-full px-1.5 py-0.5 text-[11px] font-semibold tabular-nums', BADGE_TONES[tab.badgeTone || 'neutral'])}>
                {tab.badge}
              </span>
            )}
          </button>
        )
      })}
    </div>
  )
}

/** Inactive panels stay rendered but hidden, and all of them print: Export PDF prints the whole report. */
export function SectionTabPanel({
  id,
  tab,
  active,
  children,
  className = '',
}: {
  id: string
  tab: string
  active: string
  children: React.ReactNode
  className?: string
}) {
  const selected = tab === active
  return (
    <section
      role="tabpanel"
      id={`${id}-panel-${tab}`}
      aria-labelledby={`${id}-tab-${tab}`}
      // A class, not the hidden attribute: Tailwind's base layer hides [hidden] with !important,
      // which a print utility cannot override.
      className={cn('pt-5 print:block print:pt-2', !selected && 'hidden', className)}
    >
      {children}
    </section>
  )
}
