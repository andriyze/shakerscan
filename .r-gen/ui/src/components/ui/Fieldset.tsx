import { cn } from '@/lib/cn'

// A nested, titled group of controls with an optional description — the
// sub-section pattern that AISettingsPanel previously defined as a PRIVATE
// component also named "SectionCard", colliding with the shared top-level
// SectionCard (same name, different API and look). Giving it its own name
// removes that trap. Use SectionCard for top-level cards; Fieldset for groups
// of related controls inside a panel.
export function Fieldset({
  title,
  description,
  actions,
  className = '',
  children,
}: {
  title: string
  description?: string
  actions?: React.ReactNode
  className?: string
  children: React.ReactNode
}) {
  return (
    <section className={cn('space-y-3 rounded-lg border border-gray-800 bg-gray-950/50 p-3', className)}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-300">{title}</h3>
          {description && <p className="mt-1 text-xs leading-5 text-gray-500">{description}</p>}
        </div>
        {actions}
      </div>
      {children}
    </section>
  )
}
