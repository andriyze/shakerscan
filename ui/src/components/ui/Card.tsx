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
  children,
}: {
  title: string
  actions?: React.ReactNode
  className?: string
  children: React.ReactNode
}) {
  return (
    <Card className={`p-4 ${className}`}>
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-sm font-medium text-gray-400">{title}</h2>
        {actions}
      </div>
      {children}
    </Card>
  )
}
