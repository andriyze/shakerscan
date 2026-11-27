'use client'

import { EmptyState, PageHeader } from '@/components/ui'

// An address that matches no route. It names no title of its own, so the tab keeps the product
// name from the root layout.
export default function NotFound() {
  return (
    <div>
      <PageHeader title="Page not found" />
      <EmptyState
        message="There is no page at this address."
        hint="The link may be out of date, or the address may have a typo."
        action={{ label: 'Back to the dashboard', href: '/' }}
      />
    </div>
  )
}
