'use client'

import { useEffect, useState } from 'react'
import { workspaceIsManaged } from '@/lib/workspaceCapabilities'

// A managed (Enterprise) workspace starts Hunts from the operator's terminal only. Client-only,
// like the edition label, so the server render and hydration agree.
export function useWorkspaceIsManaged(): boolean {
  const [managed, setManaged] = useState(false)
  useEffect(() => { setManaged(workspaceIsManaged()) }, [])
  return managed
}

export const TERMINAL_HUNT_START_LABEL = 'Start Hunts from your terminal:'
export const TERMINAL_HUNT_START_COMMAND = 'shakerscan agent'

// What a managed workspace shows where the open-source edition offers a browser Hunt start.
export function TerminalHuntStart({ className = '' }: { className?: string }) {
  return (
    <span data-testid="terminal-hunt-start" className={`text-sm text-gray-400 ${className}`}>
      {TERMINAL_HUNT_START_LABEL}{' '}
      <code className="rounded-sm bg-gray-800 px-1.5 py-0.5 font-mono text-xs text-gray-200">{TERMINAL_HUNT_START_COMMAND}</code>
    </span>
  )
}
