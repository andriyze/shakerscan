import { EmptyState } from './EmptyState'
import { PageHeader } from './PageHeader'

/**
 * A detail page whose record does not exist (the API answered 404): say so and lead back to the
 * list. A read that failed for another reason keeps the page's error state with Retry.
 */
export function RecordNotFound({
  title,
  message,
  listHref,
  listLabel,
}: {
  title: string
  message: string
  listHref: string
  listLabel: string
}) {
  return (
    <div data-testid="record-not-found">
      <PageHeader title={title} />
      <EmptyState
        message={message}
        hint="It may have been deleted, or the link may be out of date."
        action={{ label: listLabel, href: listHref }}
      />
    </div>
  )
}
