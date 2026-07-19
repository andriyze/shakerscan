'use client'

import { forwardRef } from 'react'
import { ChevronDown } from 'lucide-react'
import { cn } from '@/lib/cn'
import { fieldClasses } from './Input'

export interface SelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {
  error?: boolean
}

// Native <select> styled to match Input, with a consistent chevron so it reads
// as the same control family across pages instead of the OS default arrow.
export const Select = forwardRef<HTMLSelectElement, SelectProps>(function Select(
  { error, className = '', children, ...props },
  ref
) {
  return (
    <span className="relative block">
      <select
        ref={ref}
        aria-invalid={error || undefined}
        className={cn(fieldClasses(error), 'appearance-none pr-9', className)}
        {...props}
      >
        {children}
      </select>
      <ChevronDown
        className="pointer-events-none absolute right-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500"
        aria-hidden="true"
      />
    </span>
  )
})
