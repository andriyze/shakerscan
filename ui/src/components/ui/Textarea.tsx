'use client'

import { forwardRef } from 'react'
import { cn } from '@/lib/cn'
import { fieldClasses } from './Input'

export interface TextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  error?: boolean
  /** Monospace + preserved whitespace, for JSON / payload editing. */
  mono?: boolean
}

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaProps>(function Textarea(
  { error, mono, className = '', rows = 4, ...props },
  ref
) {
  return (
    <textarea
      ref={ref}
      rows={rows}
      aria-invalid={error || undefined}
      className={cn(fieldClasses(error), mono && 'font-mono text-xs leading-relaxed', className)}
      {...props}
    />
  )
})
