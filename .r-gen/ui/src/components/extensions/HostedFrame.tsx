'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { useRouter } from 'next/navigation'
import { Button } from '@/components/ui'
import { navigationAllowed, workspaceIsManaged } from '@/lib/workspaceCapabilities'

// How long a deployment page may take to load before the frame says it is unavailable.
const LOAD_TIMEOUT_MS = 20_000

type FrameState = 'loading' | 'ready' | 'unavailable'

// The framed document: 'blank' before the first real load, null when this page may not read it
// (it left the origin, was refused as a frame, or failed to load).
function framedDocument(frame: HTMLIFrameElement): Document | 'blank' | null {
  try {
    const doc = frame.contentDocument
    if (!doc || !doc.body || !doc.documentElement) return null
    if (doc.location.href === 'about:blank') return 'blank'
    return doc.location.origin === window.location.origin ? doc : null
  } catch {
    return null
  }
}

/**
 * A deployment page shown inside this UI (ui-extensions/v1, docs/ui-extensions.md): a same-origin
 * frame as tall as its content, so the UI's own page keeps the only scrollbar.
 *
 * `variant` is where it is drawn. A hosted `page` that cannot be shown says so and offers to try
 * again. A `panel` draws nothing and reports it through `onUnavailable`, so its place can close to
 * a single quiet line.
 */
export function HostedFrame({ src, title, variant, onUnavailable }: {
  src: string
  title: string
  variant: 'page' | 'panel'
  onUnavailable?: () => void
}) {
  const router = useRouter()
  const frameRef = useRef<HTMLIFrameElement>(null)
  const detachRef = useRef<() => void>(() => undefined)
  const unavailableRef = useRef(onUnavailable)
  unavailableRef.current = onUnavailable
  const [state, setFrameState] = useState<FrameState>('loading')
  const stateRef = useRef<FrameState>('loading')
  const setState = useCallback((next: FrameState) => {
    stateRef.current = next
    setFrameState(next)
  }, [])
  const [height, setHeight] = useState(0)
  const [attempt, setAttempt] = useState(0)

  const fail = useCallback(() => {
    detachRef.current()
    setState('unavailable')
    unavailableRef.current?.()
  }, [setState])

  // Runs for every document the frame loads, so a navigation inside the frame is measured too.
  const onLoad = useCallback(() => {
    detachRef.current()
    const frame = frameRef.current
    const doc = frame ? framedDocument(frame) : null
    if (doc === 'blank') return
    // The frame's own ResizeObserver: it watches elements of the frame's document.
    const view = frame?.contentWindow as (Window & typeof globalThis) | null | undefined
    if (!frame || !doc || !view) return fail()

    const measure = () => {
      // The root element's own box: the content's height, however tall the frame is now.
      const next = Math.ceil(doc.documentElement.getBoundingClientRect().height)
      setHeight((current) => (current === next ? current : next))
    }
    const observer = new view.ResizeObserver(measure)
    observer.observe(doc.documentElement)
    observer.observe(doc.body)

    // A link the framed page marks target="_top" to a page of this UI goes through the UI's
    // router (no reload). Every other link behaves as the framed page wrote it.
    const onClick = (event: MouseEvent) => {
      if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return
      // The target belongs to the frame's realm: no instanceof against this window's classes.
      const target = event.target as { closest?: (selector: string) => HTMLAnchorElement | null } | null
      const anchor = target?.closest?.('a[target="_top"][href]')
      if (!anchor) return
      let url: URL
      try { url = new URL(anchor.href, window.location.origin) } catch { return }
      if (url.origin !== window.location.origin) return
      if (!workspaceIsManaged() || !navigationAllowed(url.pathname)) return
      event.preventDefault()
      router.push(`${url.pathname}${url.search}${url.hash}`)
    }
    doc.addEventListener('click', onClick)

    detachRef.current = () => {
      observer.disconnect()
      doc.removeEventListener('click', onClick)
      detachRef.current = () => undefined
    }
    measure()
    setState('ready')
  }, [fail, router, setState])

  // Each address, and each "Try again", starts over; a page that never loads is unavailable.
  useEffect(() => {
    setState('loading')
    setHeight(0)
    const timer = window.setTimeout(() => {
      if (stateRef.current === 'loading') fail()
    }, LOAD_TIMEOUT_MS)
    return () => {
      window.clearTimeout(timer)
      detachRef.current()
    }
  }, [src, attempt, fail, setState])

  if (state === 'unavailable') {
    if (variant === 'panel') return null
    return (
      <div role="alert" className="rounded-lg border border-gray-800 bg-gray-900 p-5 text-sm text-gray-300">
        <p>{title} could not be shown.</p>
        <Button variant="secondary" size="sm" className="mt-3" onClick={() => setAttempt((count) => count + 1)}>
          Try again
        </Button>
      </div>
    )
  }

  return (
    <>
      {state === 'loading' && <p role="status" className="text-sm text-gray-500">Loading…</p>}
      <iframe
        key={`${src} ${attempt}`}
        ref={frameRef}
        src={src}
        title={title}
        onLoad={onLoad}
        // As tall as its content: never a scrollbar of its own.
        scrolling="no"
        className="block w-full border-0 bg-transparent"
        style={{
          height: state === 'ready' ? height : 0,
          visibility: state === 'ready' ? 'visible' : 'hidden',
          colorScheme: 'dark',
        }}
      />
    </>
  )
}
