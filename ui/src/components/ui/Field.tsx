'use client'

import { cloneElement, isValidElement, useId, type ReactElement } from 'react'
import { cn } from '@/lib/cn'

// Wraps a single form control with a properly associated <label>, optional
// hint, required marker, and error/description text. The label's htmlFor and
// the control's id/aria-describedby/aria-invalid are wired automatically via
// cloneElement, so callers can't accidentally ship a detached label (a
// recurring a11y bug in the hand-rolled forms this replaces).
export function Field({
  label,
  hint,
  error,
  required,
  htmlFor,
  className = '',
  children,
}: {
  label: string
  hint?: string
  error?: string | null
  required?: boolean
  /** Override the generated id (e.g. when the control sets its own id). */
  htmlFor?: string
  className?: string
  children: ReactElement<{ id?: string; 'aria-describedby'?: string; 'aria-invalid'?: boolean }>
}) {
  const generatedId = useId()
  const controlId = htmlFor ?? children.props.id ?? generatedId
  const describedById = hint || error ? `${controlId}-desc` : undefined

  const control = isValidElement(children)
    ? cloneElement(children, {
        id: controlId,
        'aria-describedby': cn(children.props['aria-describedby'], describedById) || undefined,
        'aria-invalid': error ? true : children.props['aria-invalid'],
      })
    : children

  return (
    <div className={cn('space-y-1', className)}>
      <label htmlFor={controlId} className="flex items-center gap-1 text-xs font-medium text-gray-400">
        {label}
        {required && <span className="text-red-400" aria-hidden="true">*</span>}
      </label>
      {control}
      {(hint || error) && (
        <p id={describedById} className={cn('text-[11px] leading-4', error ? 'text-red-400' : 'text-gray-500')}>
          {error || hint}
        </p>
      )}
    </div>
  )
}
