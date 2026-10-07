'use client'

import { useCallback, useEffect, useId, useLayoutEffect, useRef, useState, type ReactNode } from 'react'
import { MoreHorizontal } from 'lucide-react'
import Link from '@/components/WorkspaceLink'

/**
 * The overflow ("…") menu for a row or a group. Secondary and destructive actions live here so a
 * list row shows at most one visible button. The panel stays mounted while hidden, so entries
 * that own a dialog (instructions, deletion) keep it open after the menu closes. Fixed
 * positioning keeps the panel clear of card edges and scroll containers.
 */
export function ActionMenu({ label, children }: { label: string; children: ReactNode }) {
  const [open, setOpen] = useState(false)
  const [position, setPosition] = useState<{ top: number; left: number; maxHeight?: number }>({ top: 0, left: 0 })
  const trigger = useRef<HTMLButtonElement>(null)
  const panel = useRef<HTMLDivElement>(null)
  const id = useId()

  const close = useCallback((restoreFocus = false) => {
    setOpen(false)
    if (restoreFocus) trigger.current?.focus()
  }, [])

  /**
   * Anchor the panel to its button using its measured height: below when it fits, above when
   * that fits, else on the roomier side with its own scroll. Every entry stays reachable and the
   * button is never covered. Returns false once the button has left the viewport.
   */
  const place = useCallback(() => {
    const rect = trigger.current?.getBoundingClientRect()
    if (!rect || rect.bottom < 0 || rect.top > window.innerHeight) return false
    const width = panel.current?.offsetWidth || 248
    const height = panel.current?.scrollHeight || 0
    const gap = 6, margin = 8, viewport = window.innerHeight
    const left = Math.max(margin, Math.min(rect.right - width, window.innerWidth - width - margin))
    const below = viewport - margin - (rect.bottom + gap)
    const above = rect.top - gap - margin
    if (height <= below) setPosition({ top: rect.bottom + gap, left })
    else if (height <= above) setPosition({ top: rect.top - gap - height, left })
    else if (below >= above) setPosition({ top: rect.bottom + gap, left, maxHeight: below })
    else setPosition({ top: margin, left, maxHeight: above })
    return true
  }, [])

  function toggle() {
    if (open) close()
    else setOpen(true)
  }

  // Measure once the panel is displayed, before paint.
  useLayoutEffect(() => { if (open) place() }, [open, place])

  useEffect(() => {
    if (!open) return
    const onPointer = (event: PointerEvent) => {
      const target = event.target as Node
      if (!panel.current?.contains(target) && !trigger.current?.contains(target)) close()
    }
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') close(true)
      if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        const items = [...(panel.current?.querySelectorAll<HTMLElement>('[role="menuitem"]:not([disabled])') || [])]
        if (!items.length) return
        event.preventDefault()
        const index = items.indexOf(document.activeElement as HTMLElement)
        const next = event.key === 'ArrowDown' ? (index + 1) % items.length : (index - 1 + items.length) % items.length
        items[next].focus()
      }
    }
    // Follow the button while the page scrolls; close once it is out of view.
    const onScroll = () => { if (!place()) close() }
    document.addEventListener('pointerdown', onPointer)
    document.addEventListener('keydown', onKey)
    window.addEventListener('scroll', onScroll, true)
    window.addEventListener('resize', onScroll)
    requestAnimationFrame(() => panel.current?.querySelector<HTMLElement>('[role="menuitem"]')?.focus())
    return () => {
      document.removeEventListener('pointerdown', onPointer)
      document.removeEventListener('keydown', onKey)
      window.removeEventListener('scroll', onScroll, true)
      window.removeEventListener('resize', onScroll)
    }
  }, [open, close, place])

  return <>
    <button ref={trigger} type="button" aria-label={label} aria-haspopup="menu" aria-expanded={open} aria-controls={id}
      onClick={toggle}
      className="inline-flex h-8 w-8 items-center justify-center rounded-lg text-gray-400 transition-colors hover:bg-gray-800 hover:text-gray-100 aria-expanded:bg-gray-800 aria-expanded:text-gray-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/60">
      <MoreHorizontal className="h-4 w-4" aria-hidden="true" />
    </button>
    <div ref={panel} id={id} role="menu" aria-label={label} hidden={!open}
      // Capture phase: entries that stop propagation (the deletion control) still close the menu.
      onClickCapture={event => { if ((event.target as HTMLElement).closest('[role="menuitem"], button, a')) close() }}
      style={{ position: 'fixed', top: position.top, left: position.left, maxHeight: position.maxHeight }}
      className="z-50 w-62 overflow-y-auto overscroll-contain rounded-lg border border-gray-700 bg-gray-900 p-1 shadow-xl shadow-black/40">
      {children}
    </div>
  </>
}

export function MenuItem({ icon, children, description, onSelect, href, disabled, tone = 'default' }: {
  icon: ReactNode; children: ReactNode; description?: string; onSelect?: () => void; href?: string; disabled?: boolean
  tone?: 'default' | 'danger'
}) {
  const className = `flex w-full items-start gap-2.5 rounded-md px-2.5 py-1.5 text-left text-sm transition-colors focus:outline-none disabled:cursor-not-allowed disabled:opacity-40 ${
    tone === 'danger' ? 'text-red-300 hover:bg-red-500/10 focus:bg-red-500/10' : 'text-gray-200 hover:bg-gray-800 focus:bg-gray-800'}`
  const content = <>
    <span className="mt-0.5 text-gray-400 [&>svg]:h-4 [&>svg]:w-4" aria-hidden="true">{icon}</span>
    <span className="min-w-0"><span className="block">{children}</span>{description && <span className="mt-0.5 block text-xs leading-4 text-gray-500">{description}</span>}</span>
  </>
  // WorkspaceLink hides entries for routes this workspace does not offer.
  if (href && !disabled) return <Link role="menuitem" href={href} className={className}>{content}</Link>
  return <button type="button" role="menuitem" disabled={disabled} onClick={onSelect} className={className}>{content}</button>
}

export function MenuSeparator() {
  return <div role="separator" className="-mx-1 my-1 h-px bg-gray-800" />
}
