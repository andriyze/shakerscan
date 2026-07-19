'use client'

import { forwardRef } from 'react'
import { cn } from '@/lib/cn'

// Shared field styling — single source of truth for text inputs, selects, and
// textareas so every form control shares one background, border, and focus
// ring. Replaces the ~7 hand-copied `bg-gray-800 border border-gray-700 …`
// strings scattered across the app (which also disagreed on bg-gray-800 vs
// bg-gray-950). Focus shows a real ring, not just a 1px border color change.
export const FIELD_BASE =
  'rounded-lg border bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 ' +
  'transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500/60 focus:border-blue-500 ' +
  'disabled:cursor-not-allowed disabled:opacity-50'

// Width-agnostic (no w-full) so inline filters can size to content. Bare
// <Input>/<Select>/<Textarea> default to full width; raw consumers add w-full.
export function fieldClasses(error?: boolean): string {
  return cn(FIELD_BASE, error ? 'border-red-500/70' : 'border-gray-700')
}

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  error?: boolean
  /** Fill the parent width (default). Set false for inline filter controls. */
  fullWidth?: boolean
}

export const Input = forwardRef<HTMLInputElement, InputProps>(function Input(
  { error, fullWidth = true, className = '', ...props },
  ref
) {
  return (
    <input
      ref={ref}
      aria-invalid={error || undefined}
      className={cn(fieldClasses(error), fullWidth && 'w-full', className)}
      {...props}
    />
  )
})
