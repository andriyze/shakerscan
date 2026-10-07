import Link from '@/components/WorkspaceLink'
import { cn } from '@/lib/cn'

export type StatTone = 'default' | 'danger' | 'warning' | 'success' | 'muted'

const VALUE_TONES: Record<StatTone, string> = {
  default: 'text-white',
  danger: 'text-red-400',
  warning: 'text-amber-300',
  success: 'text-emerald-400',
  muted: 'text-gray-500',
}

const COLUMN_CLASSES: Record<number, string> = {
  2: 'sm:grid-cols-2',
  3: 'sm:grid-cols-3',
  4: 'sm:grid-cols-2 lg:grid-cols-4',
  5: 'sm:grid-cols-3 lg:grid-cols-5',
  6: 'sm:grid-cols-3 lg:grid-cols-6',
}

/**
 * One bordered strip of key numbers, split by hairlines. Replaces the per-page KPI tiles (icon
 * squares, glows, colored borders) so every page reports its headline numbers the same way.
 */
export function StatGroup({
  children,
  columns = 4,
  className = '',
  ariaLabel,
}: {
  children: React.ReactNode
  columns?: 2 | 3 | 4 | 5 | 6
  className?: string
  ariaLabel?: string
}) {
  return (
    <div
      role={ariaLabel ? 'group' : undefined}
      aria-label={ariaLabel}
      // gap-px over a border-colored background draws hairlines between cells, including
      // across wrapped rows, without per-cell border bookkeeping.
      className={cn(
        'grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-gray-800 bg-gray-800',
        COLUMN_CLASSES[columns],
        className,
      )}
    >
      {children}
    </div>
  )
}

/**
 * A labelled number inside a StatGroup. With `onClick` it becomes a filter toggle (aria-pressed);
 * with `href` it links to the list behind the number.
 */
export function Stat({
  label,
  value,
  caption,
  tone = 'default',
  onClick,
  active,
  href,
  title,
}: {
  label: React.ReactNode
  value: React.ReactNode
  caption?: React.ReactNode
  tone?: StatTone
  onClick?: () => void
  active?: boolean
  href?: string
  title?: string
}) {
  const body = (
    <>
      <span className="block truncate text-xs font-medium text-gray-400">{label}</span>
      <span className={cn('mt-1 block text-2xl font-semibold leading-8 tracking-tight tabular-nums', VALUE_TONES[tone])}>
        {value}
      </span>
      {caption && <span className="mt-0.5 block truncate text-xs text-gray-500">{caption}</span>}
    </>
  )
  const base = 'block min-w-0 bg-gray-900 px-4 py-3 text-left'
  const interactive =
    'transition-colors hover:bg-gray-800/60 focus:outline-hidden focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-blue-500'
  // The active filter is marked by an inset rule along the bottom edge, like a selected tab.
  const activeClass = active ? 'bg-gray-800/50 shadow-[inset_0_-2px_0_0_var(--color-blue-500)]' : ''
  if (onClick) {
    return (
      <button type="button" onClick={onClick} aria-pressed={active} title={title} className={cn(base, interactive, activeClass)}>
        {body}
      </button>
    )
  }
  if (href) {
    return (
      <Link href={href} title={title} className={cn(base, interactive)}>
        {body}
      </Link>
    )
  }
  return (
    <div className={base} title={title}>
      {body}
    </div>
  )
}
