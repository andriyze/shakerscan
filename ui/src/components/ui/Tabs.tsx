'use client'

import Link from '@/components/WorkspaceLink'
import { cn } from '@/lib/cn'

export interface TabItem {
  key: string
  label: string
  /** When present, the tab renders as a Link (route/query-driven nav). */
  href?: string
  badge?: string | number
  disabled?: boolean
}

const ITEM_BASE =
  'inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-sm font-medium transition-colors ' +
  'focus:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500 disabled:cursor-not-allowed disabled:opacity-50'

function activeClasses(active: boolean): string {
  return active
    ? 'bg-gray-800 text-white shadow-xs ring-1 ring-inset ring-gray-700'
    : 'text-gray-400 hover:bg-gray-800/60 hover:text-gray-200'
}

function Badge({ value }: { value: string | number }) {
  return (
    <span className="text-xs font-normal tabular-nums text-gray-500">{value}</span>
  )
}

/**
 * Segmented control for filter/section switching. Renders Links (with
 * aria-current) when items carry an href, or buttons (with aria-pressed +
 * onChange) otherwise — replacing the 7+ hand-rolled pill/tab strips that each
 * wired accessibility differently, or not at all.
 */
export function Tabs({
  items,
  active,
  onChange,
  ariaLabel,
  className = '',
}: {
  items: TabItem[]
  active: string
  onChange?: (key: string) => void
  ariaLabel: string
  className?: string
}) {
  return (
    <div
      role="group"
      aria-label={ariaLabel}
      className={cn('inline-flex flex-wrap items-center gap-0.5 rounded-lg border border-gray-800 bg-gray-950 p-0.5', className)}
    >
      {items.map((item) => {
        const isActive = item.key === active
        const inner = (
          <>
            {item.label}
            {item.badge !== undefined && <Badge value={item.badge} />}
          </>
        )
        if (item.disabled) {
          // Render as an inert span so a disabled item never navigates, whether
          // or not it carries an href.
          return (
            <span
              key={item.key}
              aria-disabled="true"
              className={cn(ITEM_BASE, 'cursor-not-allowed opacity-50', activeClasses(isActive))}
            >
              {inner}
            </span>
          )
        }
        if (item.href) {
          return (
            <Link
              key={item.key}
              href={item.href}
              aria-current={isActive ? 'page' : undefined}
              className={cn(ITEM_BASE, activeClasses(isActive))}
            >
              {inner}
            </Link>
          )
        }
        return (
          <button
            key={item.key}
            type="button"
            aria-pressed={isActive}
            disabled={item.disabled}
            onClick={() => onChange?.(item.key)}
            className={cn(ITEM_BASE, activeClasses(isActive))}
          >
            {inner}
          </button>
        )
      })}
    </div>
  )
}
