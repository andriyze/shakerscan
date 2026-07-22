'use client'

// Route-level safety net: if the Command Arsenal page throws outside a panel
// boundary, degrade to a retryable message instead of the bare app error page.
export default function ArsenalError({ reset }: { error: Error; reset: () => void }) {
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-bold text-white">Command Arsenal</h1>
        <p className="mt-1 text-gray-400">Read-only command schemas and integrated tool status</p>
      </div>
      <div className="rounded-lg border border-amber-500/20 bg-amber-500/[0.06] p-4 text-sm text-amber-200">
        <p className="font-medium">This page hit an unexpected error while loading.</p>
        <p className="mt-1 text-amber-200/80">
          One of the arsenal data sources returned something the page didn’t expect. Retry, or refresh the browser.
        </p>
        <button
          type="button"
          onClick={reset}
          className="mt-3 rounded-lg border border-amber-400/30 px-3 py-1.5 text-xs font-medium hover:bg-amber-500/10 focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-500"
        >
          Retry
        </button>
      </div>
    </div>
  )
}
