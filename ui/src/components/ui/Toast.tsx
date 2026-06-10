'use client'

import { createContext, useCallback, useContext, useMemo, useRef, useState } from 'react'
import Link from 'next/link'
import { CheckCircle2, Info, X, XCircle } from 'lucide-react'

export interface ToastLink {
  href: string
  label: string
}

type ToastVariant = 'success' | 'error' | 'info'

interface ToastItem {
  id: number
  variant: ToastVariant
  message: string
  link?: ToastLink
}

export interface ToastApi {
  success: (message: string, opts?: { link?: ToastLink }) => void
  error: (message: string, opts?: { link?: ToastLink }) => void
  info: (message: string, opts?: { link?: ToastLink }) => void
}

const ToastContext = createContext<ToastApi | null>(null)

const VARIANT_BORDERS: Record<ToastVariant, string> = {
  success: 'border-green-500/30',
  error: 'border-red-500/30',
  info: 'border-blue-500/30',
}

const VARIANT_ICON_COLORS: Record<ToastVariant, string> = {
  success: 'text-green-400',
  error: 'text-red-400',
  info: 'text-blue-400',
}

const VARIANT_ICONS: Record<ToastVariant, typeof Info> = {
  success: CheckCircle2,
  error: XCircle,
  info: Info,
}

const MAX_VISIBLE_TOASTS = 5

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([])
  const nextId = useRef(1)

  const dismiss = useCallback((id: number) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  const push = useCallback(
    (variant: ToastVariant, message: string, opts?: { link?: ToastLink }) => {
      const id = nextId.current++
      setToasts(prev => [...prev.slice(-(MAX_VISIBLE_TOASTS - 1)), { id, variant, message, link: opts?.link }])
      window.setTimeout(() => dismiss(id), variant === 'error' ? 8000 : 5000)
    },
    [dismiss]
  )

  const api = useMemo<ToastApi>(
    () => ({
      success: (message, opts) => push('success', message, opts),
      error: (message, opts) => push('error', message, opts),
      info: (message, opts) => push('info', message, opts),
    }),
    [push]
  )

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div
        className="fixed bottom-4 right-4 z-[100] flex w-80 max-w-[calc(100vw-2rem)] flex-col gap-2"
        role="region"
        aria-label="Notifications"
      >
        {toasts.map(t => {
          const Icon = VARIANT_ICONS[t.variant]
          return (
            <div
              key={t.id}
              role={t.variant === 'error' ? 'alert' : 'status'}
              className={`flex items-start gap-2 rounded-lg border bg-gray-900 p-3 shadow-lg ${VARIANT_BORDERS[t.variant]}`}
            >
              <Icon
                className={`mt-0.5 h-4 w-4 shrink-0 ${VARIANT_ICON_COLORS[t.variant]}`}
                aria-hidden="true"
              />
              <div className="min-w-0 flex-1 text-sm text-gray-200">
                <p className="break-words">{t.message}</p>
                {t.link && (
                  <Link
                    href={t.link.href}
                    onClick={() => dismiss(t.id)}
                    className="mt-1 inline-block text-xs font-medium text-blue-400 hover:text-blue-300"
                  >
                    {t.link.label}
                  </Link>
                )}
              </div>
              <button
                type="button"
                onClick={() => dismiss(t.id)}
                aria-label="Dismiss notification"
                className="rounded text-gray-500 hover:text-gray-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
              >
                <X className="h-4 w-4" aria-hidden="true" />
              </button>
            </div>
          )
        })}
      </div>
    </ToastContext.Provider>
  )
}

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext)
  if (!ctx) {
    throw new Error('useToast must be used within a ToastProvider')
  }
  return ctx
}
