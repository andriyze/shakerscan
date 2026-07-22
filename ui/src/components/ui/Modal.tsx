'use client'

import { useRef } from 'react'
import { createPortal } from 'react-dom'
import { X } from 'lucide-react'
import { cn } from '@/lib/cn'
import { useModalA11y } from './useModalA11y'

const SIZES = {
  sm: 'max-w-md',
  md: 'max-w-lg',
  lg: 'max-w-2xl',
  xl: 'max-w-4xl',
} as const

// Generic modal shell for non-confirm dialogs (create/edit forms, detail
// panels). Reuses useModalA11y for focus-trap + Escape + focus-restore +
// background inert, and portals to <body> — the behaviour every hand-rolled
// `fixed inset-0` modal was missing.
export function Modal({
  open,
  title,
  onClose,
  size = 'md',
  footer,
  children,
}: {
  open: boolean
  title: string
  onClose: () => void
  size?: keyof typeof SIZES
  footer?: React.ReactNode
  children: React.ReactNode
}) {
  const panelRef = useRef<HTMLDivElement>(null)
  const titleId = `modal-title-${title.replace(/\s+/g, '-').toLowerCase()}`

  useModalA11y(open, panelRef, onClose)

  if (!open || typeof document === 'undefined') return null

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" onClick={onClose}>
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        // Focusable so useModalA11y can move focus here on open (a plain div is
        // not, which would leave focus in the now-inert page until first Tab).
        tabIndex={-1}
        className={cn('flex max-h-[90vh] w-full flex-col rounded-lg border border-gray-800 bg-gray-900 shadow-xl focus:outline-none', SIZES[size])}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-4 border-b border-gray-800 p-4">
          <h2 id={titleId} className="text-lg font-semibold text-white">{title}</h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="rounded p-1 text-gray-500 transition-colors hover:bg-gray-800 hover:text-gray-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
          >
            <X className="h-5 w-5" aria-hidden="true" />
          </button>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto p-4">{children}</div>
        {footer && <div className="flex justify-end gap-3 border-t border-gray-800 p-4">{footer}</div>}
      </div>
    </div>,
    document.body
  )
}
