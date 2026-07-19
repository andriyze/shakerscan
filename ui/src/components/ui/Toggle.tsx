'use client'

import { cn } from '@/lib/cn'

// One accessible switch for the whole app, replacing the four divergent toggle
// implementations that were in use (peer-checkbox, ad-hoc role=switch,
// bare checkboxes, and on/off pill buttons).
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
      className={cn(
        'relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors',
        'focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 focus-visible:ring-offset-gray-950',
        'disabled:cursor-not-allowed disabled:opacity-50',
        checked ? 'bg-blue-600' : 'bg-gray-700',
        className
      )}
    >
      <span
        aria-hidden="true"
        className={cn(
          'inline-block h-4 w-4 transform rounded-full bg-white transition-transform',
          checked ? 'translate-x-4' : 'translate-x-0.5'
        )}
      />
    </button>
  )
}

// Common labeled row: title + description on the left, switch on the right.
export function ToggleField({
  label,
  description,
  checked,
  onChange,
  disabled,
}: {
  label: string
  description?: string
  checked: boolean
  onChange: (checked: boolean) => void
  disabled?: boolean
}) {
  return (
    <div className="flex items-start justify-between gap-3 rounded-lg border border-gray-800 bg-gray-950/40 px-3 py-2.5">
      <div className="min-w-0">
        <p className="text-sm font-medium text-gray-100">{label}</p>
        {description && <p className="mt-0.5 text-xs leading-5 text-gray-500">{description}</p>}
      </div>
      <Toggle checked={checked} onChange={onChange} disabled={disabled} label={label} />
    </div>
  )
}
