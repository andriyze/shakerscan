import Link from 'next/link'
import { Button, buttonClasses } from './Button'
import { Card } from './Card'

export interface EmptyStateAction {
  label: string
  href?: string
  onClick?: () => void
}

export function EmptyState({
  message,
  hint,
  action,
}: {
  message: string
  hint?: string
  action?: EmptyStateAction
}) {
  return (
    <Card className="p-8 text-center">
      <p className="text-gray-500">{message}</p>
      {hint && <p className="mt-1 text-sm text-gray-600">{hint}</p>}
      {action &&
        (action.href ? (
          <Link href={action.href} className={`mt-4 ${buttonClasses('primary', 'sm')}`}>
            {action.label}
          </Link>
        ) : (
          <Button size="sm" className="mt-4" onClick={action.onClick}>
            {action.label}
          </Button>
        ))}
    </Card>
  )
}
