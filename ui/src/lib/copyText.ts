// Copy text to the clipboard in every context the UI is served from.
//
// `navigator.clipboard` only exists in a secure context (HTTPS or localhost). A
// self-hosted install reached over plain HTTP on a LAN address has no async
// clipboard at all, so calling it directly threw and the copy button did
// nothing. This helper tries the async clipboard when it is usable, falls back
// to a temporary off-screen textarea plus `document.execCommand('copy')`, and
// when both fail returns a failure the caller must show as a selectable field:
// a copy must never fail silently.

export type CopyMethod = 'clipboard' | 'execCommand'

export type CopyResult =
  | { ok: true; method: CopyMethod }
  | { ok: false; text: string; reason: string }

interface ClipboardLike {
  writeText(text: string): Promise<void>
}

/** The browser surface the helper uses; tests pass a fake one. */
export interface CopyEnvironment {
  window?: {
    isSecureContext?: boolean
    scrollX?: number
    scrollY?: number
    scrollTo?: (x: number, y: number) => void
    getSelection?: () => SelectionLike | null
  }
  navigator?: { clipboard?: ClipboardLike }
  document?: DocumentLike
}

interface SelectionLike {
  rangeCount: number
  getRangeAt(index: number): unknown
  removeAllRanges(): void
  addRange(range: unknown): void
}

interface ElementLike {
  focus?: (options?: { preventScroll?: boolean }) => void
}

interface TextAreaLike extends ElementLike {
  value: string
  style: Record<string, string> | CSSStyleDeclaration
  setAttribute(name: string, value: string): void
  select(): void
  setSelectionRange?: (start: number, end: number) => void
  remove?: () => void
}

interface DocumentLike {
  activeElement?: unknown
  body?: { appendChild(node: unknown): unknown; removeChild?(node: unknown): unknown } | null
  createElement(tag: 'textarea'): TextAreaLike
  execCommand?: (command: string) => boolean
}

function browserEnvironment(): CopyEnvironment {
  return {
    window: typeof window === 'undefined' ? undefined : (window as unknown as CopyEnvironment['window']),
    navigator: typeof navigator === 'undefined' ? undefined : (navigator as unknown as CopyEnvironment['navigator']),
    document: typeof document === 'undefined' ? undefined : (document as unknown as DocumentLike),
  }
}

function errorText(error: unknown): string {
  if (error instanceof Error && error.message) return error.message
  return String(error || 'unknown error')
}

/** True when the async Clipboard API can be called in this context. */
export function asyncClipboardUsable(env: CopyEnvironment = browserEnvironment()): boolean {
  return Boolean(
    env.window?.isSecureContext
    && env.navigator?.clipboard
    && typeof env.navigator.clipboard.writeText === 'function',
  )
}

/**
 * Copy through a temporary off-screen textarea and `execCommand('copy')`.
 * Restores the previously focused element, the page selection and the scroll
 * position so the copy does not move the user's place on the page.
 */
export function legacyCopy(text: string, env: CopyEnvironment = browserEnvironment()): boolean {
  const doc = env.document
  const win = env.window
  if (!doc || !doc.body || typeof doc.execCommand !== 'function') return false

  const previousFocus = doc.activeElement as ElementLike | null | undefined
  const scrollX = win?.scrollX ?? 0
  const scrollY = win?.scrollY ?? 0
  const selection = win?.getSelection?.() ?? null
  const savedRanges: unknown[] = []
  if (selection) {
    for (let i = 0; i < selection.rangeCount; i += 1) savedRanges.push(selection.getRangeAt(i))
  }

  const area = doc.createElement('textarea')
  area.value = text
  area.setAttribute('readonly', '')
  area.setAttribute('aria-hidden', 'true')
  area.setAttribute('tabindex', '-1')
  Object.assign(area.style, {
    position: 'fixed',
    top: '0',
    left: '-9999px',
    width: '1px',
    height: '1px',
    opacity: '0',
    pointerEvents: 'none',
  })
  doc.body.appendChild(area)

  let copied = false
  try {
    area.focus?.({ preventScroll: true })
    area.select()
    area.setSelectionRange?.(0, text.length)
    copied = doc.execCommand('copy') === true
  } catch {
    copied = false
  } finally {
    if (typeof area.remove === 'function') area.remove()
    else doc.body.removeChild?.(area)
    try {
      previousFocus?.focus?.({ preventScroll: true })
    } catch {
      // The element may have left the page; nothing to restore.
    }
    if (selection) {
      try {
        selection.removeAllRanges()
        for (const range of savedRanges) selection.addRange(range)
      } catch {
        // A selection that cannot be restored is not worth failing the copy for.
      }
    }
    if (win?.scrollTo && (win.scrollX !== scrollX || win.scrollY !== scrollY)) {
      win.scrollTo(scrollX, scrollY)
    }
  }
  return copied
}

/**
 * Copy `text`. Never throws. On `{ ok: false }` the caller must show `text` in
 * a visible, pre-selected read-only field so the user can copy it by hand.
 */
export async function copyText(text: string, env: CopyEnvironment = browserEnvironment()): Promise<CopyResult> {
  let asyncFailure = 'clipboard unavailable in this context'
  if (asyncClipboardUsable(env)) {
    try {
      await env.navigator!.clipboard!.writeText(text)
      return { ok: true, method: 'clipboard' }
    } catch (error) {
      asyncFailure = errorText(error)
    }
  }
  if (legacyCopy(text, env)) return { ok: true, method: 'execCommand' }
  return { ok: false, text, reason: `${asyncFailure}; fallback copy refused` }
}

/** Absolute link to a finding page on the origin the user is browsing. */
export function findingLink(findingId: string, origin?: string): string {
  const base = origin ?? (typeof window === 'undefined' ? '' : window.location.origin)
  return `${base}/findings/${encodeURIComponent(findingId)}`
}
