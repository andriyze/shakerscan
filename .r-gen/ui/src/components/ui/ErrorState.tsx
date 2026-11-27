'use client'

import { Button } from './Button'

export function ErrorState({
  message = 'Failed to load data. Is the API running?',
  onRetry,
}: {
  message?: string
  onRetry?: () => void
}) {
  return (
    <div
      role="alert"
      className="flex items-center justify-between gap-4 rounded-lg border border-red-500/20 bg-red-500/10 p-4"
    >
      <p className="text-sm text-red-400">{message}</p>
      {onRetry && (
        <Button variant="secondary" size="sm" onClick={onRetry}>
          Retry
        </Button>
      )}
    </div>
  )
}
