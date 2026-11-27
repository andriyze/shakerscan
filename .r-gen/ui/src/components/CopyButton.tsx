'use client'

import React, { useCallback, useEffect, useRef, useState } from 'react'
import { Check, Copy, X } from 'lucide-react'
import { copyText } from '@/lib/copyText'

/** Outcome of the latest copy: `copied` flashes, `fallback` holds text the browser refused to copy. */
export function useCopy(resetMs = 2000) {
  const [copiedKey, setCopiedKey] = useState<string | null>(null)
  const [fallback, setFallback] = useState<{ key: string; text: string } | null>(null)
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => () => { if (timer.current) clearTimeout(timer.current) }, [])

  const copy = useCallback(async (text: string, key = 'default'): Promise<boolean> => {
    const result = await copyText(text)
    if (timer.current) clearTimeout(timer.current)
    if (result.ok) {
      setFallback(null)
      setCopiedKey(key)
      timer.current = setTimeout(() => setCopiedKey(null), resetMs)
      return true
    }
    setCopiedKey(null)
    setFallback({ key, text: result.text })
    return false
  }, [resetMs])

  const dismiss = useCallback(() => setFallback(null), [])
  return { copy, copiedKey, fallback, dismiss }
}

/**
 * Shown when the browser refused every copy method: the text in a read-only
 * field, already selected, so Ctrl/Cmd+C copies it.
 */
export function CopyFallback({
  text,
  label,
  onClose,
  floating = false,
}: {
  text: string
  label?: string
  onClose: () => void
  floating?: boolean
}) {
  const fieldRef = useRef<HTMLInputElement & HTMLTextAreaElement>(null)
  const multiline = text.includes('\n') || text.length > 200

  useEffect(() => {
    const field = fieldRef.current
    if (!field) return
    field.focus({ preventScroll: true })
    field.select()
  }, [text])

  const position = floating
    ? 'absolute right-0 top-full z-50 mt-1 w-[min(28rem,80vw)]'
    : 'mt-2 w-full'
  const fieldClass = 'w-full rounded-sm border border-gray-600 bg-gray-950 px-2 py-1 font-mono text-xs text-gray-100 focus:border-blue-500 focus:outline-hidden'
  const fieldLabel = `${label || 'Text'} (select and copy)`

  return (
    <div
      role="group"
      aria-label="Copy manually"
      data-testid="copy-fallback"
      className={`${position} rounded-md border border-amber-700/70 bg-gray-900 p-2 text-left shadow-lg`}
      onClick={(event) => event.stopPropagation()}
      onKeyDown={(event) => { if (event.key === 'Escape') { event.stopPropagation(); onClose() } }}
    >
      <div className="mb-1 flex items-center justify-between gap-2 text-[11px] text-amber-200">
        <span>The browser blocked copying. Press Ctrl+C (Cmd+C on a Mac) to copy the selected text.</span>
        <button
          type="button"
          onClick={onClose}
          className="shrink-0 rounded-sm p-0.5 text-gray-400 hover:bg-gray-800 hover:text-white focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500"
          aria-label="Close"
        >
          <X className="h-3 w-3" aria-hidden="true" />
        </button>
      </div>
      {multiline ? (
        <textarea ref={fieldRef} readOnly value={text} rows={Math.min(8, text.split('\n').length + 1)} aria-label={fieldLabel} className={fieldClass} onFocus={(event) => event.currentTarget.select()} />
      ) : (
        <input ref={fieldRef} readOnly value={text} aria-label={fieldLabel} className={fieldClass} onFocus={(event) => event.currentTarget.select()} />
      )}
    </div>
  )
}

export interface CopyButtonProps {
  /** The text, or a function read at click time (e.g. a link built from window.location). */
  text: string | (() => string)
  label?: string
  /** Visible text next to the icon; the button is icon-only without it. */
  children?: React.ReactNode
  /** Keep the click from reaching a surrounding clickable card or summary. */
  stopPropagation?: boolean
  size?: 'sm' | 'md'
  className?: string
  testId?: string
}

/** The one copy button the UI uses: copies in secure and insecure contexts, never fails silently. */
export function CopyButton({ text, label, children, stopPropagation = false, size = 'sm', className, testId }: CopyButtonProps) {
  const { copy, copiedKey, fallback, dismiss } = useCopy()
  const copied = copiedKey !== null
  const name = label || 'Copy'
  const icon = size === 'md' ? 'h-4 w-4' : 'h-3.5 w-3.5'
  const buttonClass = className || (children
    ? 'inline-flex items-center gap-1.5 rounded-lg border border-gray-700 px-3 py-1.5 text-xs font-medium text-gray-200 transition-colors hover:bg-gray-800 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500'
    : `rounded-sm ${size === 'md' ? 'p-1.5' : 'p-1'} transition-colors hover:bg-gray-800 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500`)

  const handleClick = (event: React.MouseEvent) => {
    if (stopPropagation) event.stopPropagation()
    void copy(typeof text === 'function' ? text() : text)
  }

  return (
    <span className="relative inline-flex shrink-0 items-center" onClick={stopPropagation ? (event) => event.stopPropagation() : undefined}>
      <button
        type="button"
        onClick={handleClick}
        className={buttonClass}
        title={name}
        aria-label={children ? undefined : name}
        data-testid={testId}
        data-copy-state={copied ? 'copied' : fallback ? 'fallback' : 'idle'}
      >
        {copied
          ? <Check className={`${icon} text-green-400`} aria-hidden="true" />
          : <Copy className={`${icon} ${fallback ? 'text-amber-300' : 'text-gray-400'}`} aria-hidden="true" />}
        {children && <span>{copied ? 'Copied' : children}</span>}
      </button>
      <span role="status" className="sr-only">{copied ? 'Copied' : ''}</span>
      {fallback && <CopyFallback text={fallback.text} label={name} onClose={dismiss} floating />}
    </span>
  )
}

export default CopyButton
