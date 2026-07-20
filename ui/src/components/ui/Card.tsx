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
  actions,
  className = '',
  id,
  children,
}: {
  title: string
  actions?: React.ReactNode
  className?: string
  /** Anchor id for in-page table-of-contents navigation. */
  id?: string
  children: React.ReactNode
}) {
  return (
    <Card id={id} className={`p-4 ${id ? 'scroll-mt-6' : ''} ${className}`}>
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-sm font-medium text-gray-400">{title}</h2>
        {actions}
      </div>
      {children}
    </Card>
  )
}
