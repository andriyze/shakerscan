'use client'

import { cn } from '@/lib/cn'

const FOCUS_RING =
  'focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 focus-visible:ring-offset-gray-950'

// Presentational track + thumb, shared by the standalone Toggle and the
// full-row ToggleField so a real interactive control can wrap it (you can't
// nest a <button> inside a <button>).
export function ToggleVisual({ checked }: { checked: boolean }) {
  return (
    <span
      aria-hidden="true"
      className={cn(
        'relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors',
        checked ? 'bg-blue-600' : 'bg-gray-700'
      )}
    >
      <span
        className={cn(
          'inline-block h-4 w-4 transform rounded-full bg-white transition-transform',
          checked ? 'translate-x-4' : 'translate-x-0.5'
        )}
      />
    </span>
  )
}

// Standalone switch, replacing the four divergent toggle implementations
// (peer-checkbox, ad-hoc role=switch, bare checkboxes, on/off pill buttons).
export function Toggle({
  checked,
  onChange,
  disabled,
  label,
  className = '',
}: {
  checked: boolean
  onChange: (checked: boolean) => void
  disabled?: boolean
  /** Accessible name when the switch has no adjacent visible label. */
  label?: string
  className?: string
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={cn('rounded-full disabled:cursor-not-allowed disabled:opacity-50', FOCUS_RING, className)}
    >
      <ToggleVisual checked={checked} />
    </button>
  )
}

// Labeled row: the WHOLE row is the switch, so the entire card is the hit
// target (not just the 36×20 track). Correct role/aria live on the row button.
export function ToggleField({
  label,
  description,
  checked,
  onChange,
  disabled,
  children,
  className = '',
}: {
  label: string
  description?: string
  checked: boolean
  onChange: (checked: boolean) => void
  disabled?: boolean
  children?: React.ReactNode
  className?: string
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={cn(
        'flex w-full items-start justify-between gap-3 rounded-lg border border-gray-800 bg-gray-950/40 px-3 py-2.5 text-left transition-colors hover:border-gray-700 disabled:cursor-not-allowed disabled:opacity-50',
        FOCUS_RING,
        className
      )}
    >
      <span className="min-w-0">
        <span className="block text-sm font-medium text-gray-100">{label}</span>
        {description && <span className="mt-0.5 block text-xs leading-5 text-gray-500">{description}</span>}
        {children}
      </span>
      <ToggleVisual checked={checked} />
    </button>
  )
}
