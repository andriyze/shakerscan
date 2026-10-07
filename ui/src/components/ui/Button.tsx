'use client'

import { forwardRef } from 'react'
import { Spinner } from './Spinner'

export type ButtonVariant = 'primary' | 'secondary' | 'danger' | 'ghost'
export type ButtonSize = 'sm' | 'md'

// One primary action per view; everything else is secondary or ghost (see ui/DESIGN.md).
// Heights match the form controls (sm 32px, md 36px) so toolbars line up.
const BASE_CLASSES =
  'inline-flex items-center justify-center gap-1.5 font-medium rounded-lg transition-colors ' +
  'focus:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500/70 focus-visible:ring-offset-2 ' +
  'focus-visible:ring-offset-gray-950 disabled:opacity-50 disabled:cursor-not-allowed'

const VARIANT_CLASSES: Record<ButtonVariant, string> = {
  primary: 'bg-blue-600 text-white shadow-xs hover:bg-blue-500',
  secondary: 'border border-gray-700 bg-gray-900 text-gray-200 shadow-xs hover:border-gray-600 hover:bg-gray-800 hover:text-white',
  danger: 'bg-red-600 text-white shadow-xs hover:bg-red-500',
  ghost: 'text-gray-400 hover:bg-gray-800 hover:text-gray-100',
}

const SIZE_CLASSES: Record<ButtonSize, string> = {
  sm: 'min-h-8 px-2.5 py-1 text-xs',
  md: 'min-h-9 px-3.5 py-1.5 text-sm',
}

export function buttonClasses(variant: ButtonVariant = 'primary', size: ButtonSize = 'md'): string {
  return `${BASE_CLASSES} ${VARIANT_CLASSES[variant]} ${SIZE_CLASSES[size]}`
}

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  size?: ButtonSize
  /** Shows a spinner and disables the button while an action is in flight. */
  loading?: boolean
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = 'primary', size = 'md', className = '', type = 'button', loading = false, disabled, children, ...props },
  ref
) {
  return (
    <button
      ref={ref}
      type={type}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      className={`${buttonClasses(variant, size)} ${className}`}
      {...props}
    >
      {loading && <Spinner className={size === 'sm' ? 'h-3.5 w-3.5' : 'h-4 w-4'} />}
      {children}
    </button>
  )
})
