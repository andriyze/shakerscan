import Link from 'next/link'
import { ArrowLeft } from 'lucide-react'
import { cn } from '@/lib/cn'

// The single page-title block, replacing ~24 hand-rolled headers that had
// drifted into four title scales, three back-link conventions (including a
// back-arrow SVG inlined four times in one file), and inconsistent action
// placement. One title scale (text-2xl), one back affordance (lucide ArrowLeft).
export function PageHeader({
  title,
  description,
  icon,
  actions,
  backHref,
  backLabel = 'Back',
  eyebrow,
  className = '',
}: {
  title: React.ReactNode
  description?: React.ReactNode
  icon?: React.ReactNode
  actions?: React.ReactNode
  backHref?: string
  backLabel?: string
  eyebrow?: string
  className?: string
}) {
  return (
    <div className={cn('mb-6', className)}>
      {backHref && (
        <Link
          href={backHref}
          className="mb-2 inline-flex items-center gap-1.5 text-sm text-gray-400 transition-colors hover:text-gray-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded"
        >
          <ArrowLeft className="h-4 w-4" aria-hidden="true" />
          {backLabel}
        </Link>
      )}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex min-w-0 items-start gap-3">
          {icon && <span className="mt-0.5 shrink-0 text-blue-400">{icon}</span>}
          <div className="min-w-0">
            {eyebrow && (
              <p className="text-[11px] font-semibold uppercase tracking-wider text-gray-500">{eyebrow}</p>
            )}
            <h1 className="text-2xl font-bold text-white">{title}</h1>
            {description && <p className="mt-1 max-w-3xl text-sm text-gray-400">{description}</p>}
          </div>
        </div>
        {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
      </div>
    </div>
  )
}
