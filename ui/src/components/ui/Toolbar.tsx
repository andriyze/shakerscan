'use client'

import { forwardRef } from 'react'
import { Search, X } from 'lucide-react'
import { cn } from '@/lib/cn'
import { fieldClasses } from './Input'

/**
 * The row of search and filter controls above a list. It sits directly on the page — not in its
 * own card — so the list stays the only bordered surface.
 */
export function Toolbar({ className = '', children }: { className?: string; children: React.ReactNode }) {
  return <div className={cn('mb-3 flex flex-wrap items-center gap-2', className)}>{children}</div>
}

export interface SearchInputProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'onChange' | 'value'> {
  value: string
  onValueChange: (value: string) => void
  /** Shows a `/` hint while empty; the page owns the keyboard shortcut itself. */
  shortcutHint?: string
  wrapperClassName?: string
}

/** Search field with a leading icon and a clear button. */
export const SearchInput = forwardRef<HTMLInputElement, SearchInputProps>(function SearchInput(
  { value, onValueChange, shortcutHint, wrapperClassName = '', className = '', ...props },
  ref,
) {
  return (
    <div className={cn('relative min-w-0', wrapperClassName)}>
      <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" aria-hidden="true" />
      <input
        ref={ref}
        type="search"
        value={value}
        onChange={(event) => onValueChange(event.target.value)}
        className={cn(fieldClasses(), 'w-full pl-8.5 pr-9 [&::-webkit-search-cancel-button]:appearance-none', className)}
        {...props}
      />
      {value ? (
        <button
          type="button"
          aria-label="Clear search"
          onClick={() => onValueChange('')}
          className="absolute right-2 top-1/2 -translate-y-1/2 rounded-sm p-0.5 text-gray-500 hover:text-gray-200 focus:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500"
        >
          <X className="h-4 w-4" aria-hidden="true" />
        </button>
      ) : shortcutHint ? (
        <kbd className="pointer-events-none absolute right-2.5 top-1/2 hidden -translate-y-1/2 rounded-sm border border-gray-700 px-1.5 font-sans text-[11px] leading-4 text-gray-500 sm:block">
          {shortcutHint}
        </kbd>
      ) : null}
    </div>
  )
})
