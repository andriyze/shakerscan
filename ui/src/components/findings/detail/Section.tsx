// One section style for the finding page: a readable heading, optional actions, and content.
export function Section({
  id,
  title,
  actions,
  className = '',
  children,
}: {
  id?: string
  title: string
  actions?: React.ReactNode
  className?: string
  children: React.ReactNode
}) {
  const headingId = id ? `${id}-heading` : undefined
  return (
    <section
      id={id}
      aria-labelledby={headingId}
      className={`min-w-0 scroll-mt-6 rounded-lg border border-gray-800 bg-gray-900 p-4 sm:p-5 ${className}`}
    >
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h2 id={headingId} className="text-sm font-semibold text-gray-100">{title}</h2>
        {actions}
      </div>
      {children}
    </section>
  )
}

// A label/value pair in a facts list.
export function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex min-w-0 items-baseline justify-between gap-3 py-1.5 text-sm">
      <dt className="shrink-0 text-gray-500">{label}</dt>
      <dd className="min-w-0 text-right text-gray-200 wrap-break-word">{children}</dd>
    </div>
  )
}
