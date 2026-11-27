'use client'

import { useEffect, useState, type ReactNode } from 'react'
import { usePathname } from 'next/navigation'
import { featureEnabled, navigationAllowed } from '@/lib/workspaceCapabilities'

export function WorkspaceFeature({ name, children }: { name: string; children: ReactNode }) {
  return featureEnabled(name) ? children : null
}

export default function WorkspaceBoundary({ children, managed }: { children: ReactNode; managed: boolean }) {
  // Standalone deployments have no client-injected policy to await, so they render the shell
  // immediately on the server and the first client paint — no mount-gate flash and no window
  // for a probe (test or user) to see an empty shell. Managed deployments still wait one mount
  // cycle for the runtime-config script to publish window.__SHAKERSCAN_CAPABILITIES__.
  const [ready, setReady] = useState(!managed)
  const path = usePathname()
  useEffect(() => setReady(true), [])
  if (managed && !ready) return <p role="status">Loading workspace…</p>
  if (managed && window.__SHAKERSCAN_CAPABILITIES__?.schema !== 'shakerscan.workspace-capabilities/v1')
    return <p role="alert">Workspace configuration is unavailable. Reload or contact your administrator.</p>
  if (!navigationAllowed(path))
    return <p role="alert">This feature is not available in this workspace.</p>
  return children
}
