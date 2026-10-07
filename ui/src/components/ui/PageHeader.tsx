import Link from '@/components/WorkspaceLink'
import { ChevronLeft } from 'lucide-react'
import { cn } from '@/lib/cn'
import { boundedDisplayText } from '@/lib/targetChoices'

// The single page-title block for every page: one title scale, one back affordance, actions on
// the right. Titles carry no icon — the sidebar already says where you are — so every page opens
// on the same baseline (see ui/DESIGN.md).
export function PageHeader({
  title,
  description,
  actions,
  backHref,
  backLabel = 'Back',
  eyebrow,
  meta,
  className = '',
}: {
  title: React.ReactNode
  description?: React.ReactNode
  actions?: React.ReactNode
  backHref?: string
  backLabel?: string
  eyebrow?: string
  /** Small inline facts under the title (status, timestamps); rendered after the description. */
  meta?: React.ReactNode
  className?: string
}) {
  const renderedTitle = typeof title === 'string' ? boundedDisplayText(title, 200) : title
  return (
    <div className={cn('mb-6', className)}>
      {backHref && (
        <Link
          href={backHref}
          className="mb-2 -ml-0.5 inline-flex items-center gap-0.5 rounded-sm text-xs font-medium text-gray-400 transition-colors hover:text-gray-100 focus:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500"
        >
          <ChevronLeft className="h-3.5 w-3.5" aria-hidden="true" />
          {backLabel}
        </Link>
      )}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          {eyebrow && <p className="mb-0.5 text-xs font-medium text-gray-500">{eyebrow}</p>}
          <h1 className="readout wrap-break-word text-xl font-semibold text-white">{renderedTitle}</h1>
          {description && <p className="mt-1 max-w-3xl text-sm text-gray-400">{description}</p>}
          {meta && <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-gray-400">{meta}</div>}
        </div>
        {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
      </div>
    </div>
  )
}
