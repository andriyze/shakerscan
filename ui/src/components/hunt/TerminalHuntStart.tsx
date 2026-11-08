'use client'

import { useEffect, useState } from 'react'
import { workspaceIsManaged } from '@/lib/workspaceCapabilities'
import { CopyButton } from '@/components/CopyButton'

// A managed (Enterprise) workspace starts Hunts from the operator's terminal only. Client-only,
// like the edition label, so the server render and hydration agree.
export function useWorkspaceIsManaged(): boolean {
  const [managed, setManaged] = useState(false)
  useEffect(() => { setManaged(workspaceIsManaged()) }, [])
  return managed
}

export const TERMINAL_HUNT_START_LABEL = 'Start Hunts from your terminal:'
export const TERMINAL_HUNT_START_COMMAND = 'shakerscan agent'

const ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

// The command with the page's context: the target the operator is on and, from a saved action,
// that action, so the agent starts where the browser link would have (`shakerscan agent --target
// ID --saved-action ID`). Ids only: anything else is left out rather than printed into a command.
export function terminalHuntStartCommand(targetId?: string | null, actionId?: string | null): string {
  const target = targetId && ID.test(targetId) ? targetId.toLowerCase() : ''
  if (!target) return TERMINAL_HUNT_START_COMMAND
  const action = actionId && ID.test(actionId) ? ` --saved-action ${actionId.toLowerCase()}` : ''
  return `${TERMINAL_HUNT_START_COMMAND} --target ${target}${action}`
}

// What a managed workspace shows where the open-source edition offers a browser Hunt start.
export function TerminalHuntStart({ className = '', targetId, actionId }: {
  className?: string, targetId?: string | null, actionId?: string | null,
}) {
  const command = terminalHuntStartCommand(targetId, actionId)
  return (
    <span data-testid="terminal-hunt-start" className={`inline-flex flex-wrap items-center gap-1 text-sm text-gray-400 ${className}`}>
      {TERMINAL_HUNT_START_LABEL}{' '}
      <code className="break-all rounded-sm bg-gray-800 px-1.5 py-0.5 font-mono text-xs text-gray-200">{command}</code>
      <CopyButton text={command} label="Copy the Hunt command" />
    </span>
  )
}
