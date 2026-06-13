'use client'

import { useEffect, useRef, type RefObject } from 'react'

// Count of open modals currently holding the background inert, so stacked
// modals (e.g. a drawer plus a confirm dialog) don't release it early.
let inertHolds = 0

function acquireBackgroundInert() {
  inertHolds += 1
  document.querySelector('main')?.setAttribute('inert', '')
}

function releaseBackgroundInert() {
  inertHolds = Math.max(0, inertHolds - 1)
  if (inertHolds === 0) document.querySelector('main')?.removeAttribute('inert')
}

/**
 * Shared modal accessibility behaviour: traps Tab focus inside `panelRef`,
 * closes on Escape, restores focus to the previously focused element on
 * close, and makes the page background (`main`) inert so screen readers and
 * sequential focus can't reach the content behind the modal.
 *
 * The modal must be rendered in a portal OUTSIDE `main` (e.g. document.body),
 * otherwise the inert background disables the modal itself.
 */
export function useModalA11y(
  open: boolean,
  panelRef: RefObject<HTMLElement | null>,
  onClose: () => void,
  initialFocusRef?: RefObject<HTMLElement | null>
) {
  // Track the latest onClose without re-running the effect (callers usually
  // pass inline lambdas); re-running mid-open would restore focus too early.
  const onCloseRef = useRef(onClose)
  useEffect(() => {
    onCloseRef.current = onClose
  })
  const initialFocus = useRef(initialFocusRef)
  useEffect(() => {
    initialFocus.current = initialFocusRef
  })

  useEffect(() => {
    if (!open) return
    const previouslyFocused = document.activeElement as HTMLElement | null
    ;(initialFocus.current?.current ?? panelRef.current)?.focus()
    acquireBackgroundInert()

    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onCloseRef.current()
        return
      }
      if (e.key !== 'Tab' || !panelRef.current) return
      const focusables = panelRef.current.querySelectorAll<HTMLElement>(
        'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
      )
      if (focusables.length === 0) return
      const first = focusables[0]
      const last = focusables[focusables.length - 1]
      const active = document.activeElement as HTMLElement | null
      const inside = panelRef.current.contains(active)
      if (e.shiftKey) {
        if (!inside || active === first) {
          e.preventDefault()
          last.focus()
        }
      } else if (!inside || active === last) {
        e.preventDefault()
        first.focus()
      }
    }
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('keydown', onKey)
      releaseBackgroundInert()
      previouslyFocused?.focus?.()
    }
  }, [open, panelRef])
}
