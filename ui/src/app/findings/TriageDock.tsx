'use client'

import { useEffect, useRef, useState } from 'react'
import { ChevronDown } from 'lucide-react'
import { Button } from '@/components/ui'
import { cn } from '@/lib/cn'
import type { FindingStatus } from '@/lib/constants'
import { TRIAGE_VERDICTS } from './triage'

const VERDICT_BASE =
  'inline-flex items-center rounded-lg px-3 py-1.5 text-xs font-semibold ring-1 ring-inset transition-colors ' +
  'focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 disabled:cursor-not-allowed disabled:opacity-50'

/**
 * Bottom dock that exists only while findings are selected. Triage verdicts are the primary
 * actions; record deletion (when the page passes `onDelete`) sits in the More menu as a text
 * item, never as a colored button on the page.
 *
 * Fixed, not sticky: the document scrolls (the sidebar is `sticky h-screen`), so a sticky
 * element inside `main` would never pin to the viewport. The page adds bottom padding while
 * the dock is shown so the last row stays reachable.
 */
export function TriageDock({
  count,
  busy,
  hideStatus,
  onTriage,
  onClear,
  onDelete,
}: {
  count: number
  busy: boolean
  /** The active status filter: setting it again would be a no-op, so that verdict is omitted. */
  hideStatus?: string
  onTriage: (status: FindingStatus) => void
  onClear: () => void
  /** Absent when the workspace does not allow record deletion; the menu is then not rendered. */
  onDelete?: () => void
}) {
  const [menuOpen, setMenuOpen] = useState(false)
  const menuRef = useRef<HTMLDivElement>(null)
  const menuButtonRef = useRef<HTMLButtonElement>(null)
  const firstItemRef = useRef<HTMLButtonElement>(null)
  const verdicts = TRIAGE_VERDICTS.filter((verdict) => verdict.status !== hideStatus)

  useEffect(() => {
    if (!menuOpen) return
    firstItemRef.current?.focus()
    function onPointerDown(event: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) setMenuOpen(false)
    }
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setMenuOpen(false)
        menuButtonRef.current?.focus()
      }
    }
    document.addEventListener('mousedown', onPointerDown)
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('mousedown', onPointerDown)
      document.removeEventListener('keydown', onKeyDown)
    }
  }, [menuOpen])

  return (
    <div
      role="region"
      aria-label="Selection actions"
      className="fixed inset-x-3 bottom-3 z-40 md:left-[calc(16rem+1.5rem)] md:right-6 motion-safe:animate-[dock-rise_150ms_ease-out]"
    >
      <div className="flex flex-wrap items-center gap-2 rounded-xl border border-gray-700 bg-gray-900/95 px-3 py-2 shadow-2xl shadow-black/60 backdrop-blur">
        <p className="text-sm text-gray-200" aria-live="polite">
          <span className="font-semibold tabular-nums">{count}</span> selected
        </p>
        <Button variant="ghost" size="sm" onClick={onClear} disabled={busy}>
          Clear
        </Button>
        {/* Phones: count, Clear, More on one row and the verdicts as a two-column grid below.
            Wider: everything on one row with the verdicts pushed right and More last. */}
        <div
          role="group"
          aria-label="Set status for selected findings"
          className="order-last grid w-full grid-cols-2 gap-1.5 sm:order-none sm:ml-auto sm:flex sm:w-auto sm:flex-wrap sm:items-center"
        >
          {verdicts.map((verdict) => (
            <button
              key={verdict.status}
              type="button"
              disabled={busy}
              onClick={() => onTriage(verdict.status)}
              className={cn(VERDICT_BASE, 'justify-center', verdict.classes)}
            >
              {verdict.label}
            </button>
          ))}
        </div>
        {onDelete && (
          <div className="relative ml-auto sm:ml-0" ref={menuRef}>
            <Button
              ref={menuButtonRef}
              variant="ghost"
              size="sm"
              aria-haspopup="menu"
              aria-expanded={menuOpen}
              aria-controls="triage-dock-menu"
              aria-label="More actions"
              disabled={busy}
              onClick={() => setMenuOpen((open) => !open)}
            >
              More
              <ChevronDown className="h-3.5 w-3.5" aria-hidden="true" />
            </Button>
            {menuOpen && (
              <div
                id="triage-dock-menu"
                role="menu"
                aria-label="More actions"
                className="absolute bottom-full right-0 mb-1 w-72 rounded-lg border border-gray-700 bg-gray-800 py-1 shadow-xl"
              >
                <button
                  ref={firstItemRef}
                  role="menuitem"
                  type="button"
                  aria-label="Delete selected findings"
                  aria-describedby="triage-dock-delete-hint"
                  onClick={() => {
                    // Close and hand focus back before opening the dialog, so its focus restore
                    // lands on a control that still exists after the dock unmounts.
                    setMenuOpen(false)
                    menuButtonRef.current?.focus()
                    onDelete()
                  }}
                  className="w-full px-3 py-2 text-left transition-colors hover:bg-gray-700 focus:outline-none focus-visible:bg-gray-700"
                >
                  <span className="block text-sm font-medium text-red-300">Delete selected findings</span>
                  <span id="triage-dock-delete-hint" className="mt-0.5 block text-xs text-gray-400">
                    Permanent. Shows a preview first, then needs approval.
                  </span>
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
