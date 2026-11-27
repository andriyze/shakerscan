import { cn } from '@/lib/cn'

// One spinner for the whole app. Replaces the several bespoke
// `animate-spin border-b-2 border-blue-500` / `border-b-2 border-white`
// variants that had drifted apart across pages.
export function Spinner({ className = '' }: { className?: string }) {
  return (
    <span
      role="status"
      aria-label="Loading"
      className={cn('inline-block animate-spin rounded-full border-2 border-current border-t-transparent', className)}
    />
  )
}
