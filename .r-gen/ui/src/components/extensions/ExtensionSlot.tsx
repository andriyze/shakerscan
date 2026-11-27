'use client'

import { useCallback, useEffect, useState } from 'react'
import { Section } from '@/components/findings/detail/Section'
import { sameOriginPath, slotPanelSrc, type ExtensionFrame, type SlotName } from '@/lib/uiExtensions.mjs'
import { workspaceExtensions } from '@/lib/workspaceCapabilities'
import { HostedFrame } from './HostedFrame'

/**
 * A named place in one of the UI's own pages where a managed deployment may show panels
 * (ui-extensions/v1, docs/ui-extensions.md). `values` fills the placeholders the place offers.
 * Nothing is drawn where no panel is declared, which is every standalone UI.
 */
export function ExtensionSlot({ name, values }: { name: SlotName; values: Record<string, string | undefined> }) {
  // Client-only, like every read of the managed policy: the server render has none.
  const [mounted, setMounted] = useState(false)
  useEffect(() => setMounted(true), [])
  if (!mounted) return null
  const panels = workspaceExtensions().slots[name] ?? []
  return <>{panels.map((panel) => <SlotPanel key={panel.id} panel={panel} values={values} />)}</>
}

function SlotPanel({ panel, values }: { panel: ExtensionFrame; values: Record<string, string | undefined> }) {
  const [unavailable, setUnavailable] = useState(false)
  const onUnavailable = useCallback(() => setUnavailable(true), [])
  const filled = slotPanelSrc(panel.src, values)
  const src = filled ? sameOriginPath(filled, window.location.origin) : null
  if (!src) return null
  // A panel that cannot be shown takes one quiet line, not a card: the page's own content
  // stays where it is.
  if (unavailable) return <p className="px-1 text-xs text-gray-500">{panel.title} is not available right now.</p>
  return (
    <Section id={`extension-${panel.id}`} title={panel.title}>
      <HostedFrame key={src} src={src} title={panel.title} variant="panel" onUnavailable={onUnavailable} />
    </Section>
  )
}
