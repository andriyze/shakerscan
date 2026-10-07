export function Card({
  className = '',
  children,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={`bg-gray-900 rounded-lg border border-gray-800 ${className}`} {...props}>
      {children}
    </div>
  )
}

export function SectionCard({
  title,
  description,
  actions,
  className = '',
  id,
  children,
}: {
  title: string
  /** One short line under the title; leave it out when the title says enough. */
  description?: React.ReactNode
  actions?: React.ReactNode
  className?: string
  /** Anchor id for in-page table-of-contents navigation. */
  id?: string
  children: React.ReactNode
}) {
  return (
    <Card id={id} className={`p-4 ${id ? 'scroll-mt-6' : ''} ${className}`}>
      <div className="mb-3 flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold text-gray-100">{title}</h2>
          {description && <p className="mt-0.5 text-xs text-gray-400">{description}</p>}
        </div>
        {actions}
      </div>
      {children}
    </Card>
  )
}
