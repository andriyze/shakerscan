'use client'

import { useEffect, useMemo, useState } from 'react'
import { Boxes, CheckCircle2, RefreshCw, ShieldCheck, TerminalSquare, XCircle } from 'lucide-react'
import {
  getArsenalCommands,
  getArsenalTools,
  type ArsenalCommand,
  type ArsenalCommandsResponse,
  type ArsenalTool,
  type ArsenalToolsResponse,
} from '@/lib/api'
import { Badge, Button, Card, EmptyState, ErrorState, Skeleton } from '@/components/ui'

function statusClass(status: string): string {
  switch (status) {
    case 'runnable':
    case 'read_only':
    case 'proof_backed':
      return 'bg-green-500/15 text-green-300'
    case 'gated':
    case 'installed':
    case 'dry_run':
      return 'bg-blue-500/15 text-blue-300'
    case 'wired':
    case 'experimental':
      return 'bg-amber-500/15 text-amber-300'
    case 'catalog_only':
    case 'waived':
      return 'bg-gray-800 text-gray-300'
    case 'disabled':
    case 'out_of_scope':
      return 'bg-red-500/15 text-red-300'
    default:
      return 'bg-gray-800 text-gray-300'
  }
}

function riskClass(risk: string): string {
  switch (risk) {
    case 'read_only':
      return 'bg-green-500/15 text-green-300'
    case 'passive':
      return 'bg-cyan-500/15 text-cyan-300'
    case 'active':
      return 'bg-blue-500/15 text-blue-300'
    case 'credential':
    case 'intrusive':
      return 'bg-amber-500/15 text-amber-300'
    case 'dangerous':
      return 'bg-red-500/15 text-red-300'
    default:
      return 'bg-gray-800 text-gray-300'
  }
}

function countBy<T extends { status: string }>(items: T[]): Record<string, number> {
  return items.reduce<Record<string, number>>((acc, item) => {
    acc[item.status] = (acc[item.status] || 0) + 1
    return acc
  }, {})
}

function Stat({
  label,
  value,
  tone = 'text-white',
}: {
  label: string
  value: string | number
  tone?: string
}) {
  return (
    <div className="rounded-md border border-gray-800 bg-gray-950 p-3">
      <div className={`text-lg font-semibold ${tone}`}>{value}</div>
      <div className="mt-1 text-xs text-gray-500">{label}</div>
    </div>
  )
}

function CommandRow({ command }: { command: ArsenalCommand }) {
  return (
    <div className="rounded-md border border-gray-800 bg-gray-950 p-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-sm text-white">{command.name}</span>
            <Badge className={statusClass(command.status)}>{command.status}</Badge>
            <Badge className={riskClass(command.risk_tier)}>{command.risk_tier}</Badge>
          </div>
          <p className="mt-2 text-sm text-gray-400">{command.description}</p>
        </div>
        <div className="shrink-0 rounded bg-gray-900 px-2 py-1 font-mono text-xs text-gray-300">
          {command.method} {command.path}
        </div>
      </div>
      <div className="mt-3 flex flex-wrap gap-2 text-xs text-gray-500">
        {command.scope_fields.length > 0 && <span>scope: {command.scope_fields.join(', ')}</span>}
        {command.required_confirmations.length > 0 && <span>confirm: {command.required_confirmations.join(', ')}</span>}
        {command.evidence_contract.length > 0 && <span>evidence: {command.evidence_contract.slice(0, 3).join(', ')}</span>}
      </div>
    </div>
  )
}

function ToolRow({ tool }: { tool: ArsenalTool }) {
  const Icon = tool.status === 'runnable' || tool.status === 'installed' ? CheckCircle2 : tool.status === 'wired' || tool.status === 'gated' ? ShieldCheck : XCircle
  return (
    <div className="rounded-md border border-gray-800 bg-gray-950 p-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Icon className="h-4 w-4 text-gray-400" aria-hidden="true" />
            <span className="font-mono text-sm text-white">{tool.tool_name}</span>
            <Badge className={statusClass(tool.status)}>{tool.status}</Badge>
            <Badge className={riskClass(tool.risk_tier)}>{tool.risk_tier}</Badge>
          </div>
          <p className="mt-2 text-sm text-gray-400">{tool.description}</p>
        </div>
        <div className="shrink-0 text-right text-xs text-gray-500">
          <div>{tool.family}</div>
          {tool.version && (
            <div className="mt-1 max-w-44 truncate font-mono text-gray-300">
              version: {tool.version}
            </div>
          )}
        </div>
      </div>
      <div className="mt-3 grid gap-2 text-xs text-gray-500 md:grid-cols-2">
        <div className="min-w-0 truncate">parser: <span className="text-gray-300">{tool.evidence_parser || 'none'}</span></div>
        <div className="min-w-0 truncate">proof: <span className="text-gray-300">{tool.proof_contract || 'none'}</span></div>
        <div className="min-w-0 truncate">binary: <span className="font-mono text-gray-300">{tool.binary_path || 'not detected'}</span></div>
        <div className="min-w-0 truncate">expected: <span className="text-gray-300">{tool.expected_status}</span></div>
      </div>
      {tool.version_probe_error && (
        <p role="alert" className="mt-2 text-xs text-amber-300">{tool.version_probe_error}</p>
      )}
    </div>
  )
}

export default function ArsenalSettingsPage() {
  const [commands, setCommands] = useState<ArsenalCommandsResponse | null>(null)
  const [tools, setTools] = useState<ArsenalToolsResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [probing, setProbing] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function load(probeVersions = false) {
    setError(null)
    if (probeVersions) setProbing(true)
    else setLoading(true)
    try {
      const [commandData, toolData] = await Promise.all([
        getArsenalCommands(),
        getArsenalTools({ probeVersions }),
      ])
      setCommands(commandData)
      setTools(toolData)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load Command Arsenal status')
    } finally {
      setLoading(false)
      setProbing(false)
    }
  }

  useEffect(() => {
    void load(false)
  }, [])

  const commandCounts = useMemo(() => countBy(commands?.commands || []), [commands])
  const gatedCommands = useMemo(
    () => (commands?.commands || []).filter((command) => command.status === 'gated'),
    [commands]
  )
  const readOnlyCommands = useMemo(
    () => (commands?.commands || []).filter((command) => command.status === 'read_only'),
    [commands]
  )
  const visibleTools = tools?.tools || []

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white">Command Arsenal</h1>
          <p className="mt-1 max-w-3xl text-gray-400">
            Read-only command schemas and integrated tool status. State-changing commands stay gated through the existing API paths.
          </p>
        </div>
        <Button
          type="button"
          variant="secondary"
          onClick={() => void load(true)}
          disabled={loading || probing}
        >
          <RefreshCw className={`h-4 w-4 ${probing ? 'animate-spin' : ''}`} />
          Probe versions
        </Button>
      </div>

      {error && <ErrorState message={error} onRetry={() => void load(false)} />}

      {loading ? (
        <div className="grid gap-3 md:grid-cols-4">
          <Skeleton className="h-20" />
          <Skeleton className="h-20" />
          <Skeleton className="h-20" />
          <Skeleton className="h-20" />
        </div>
      ) : (
        <div className="grid gap-3 md:grid-cols-4">
          <Stat label="schema" value={commands?.schema_version || '-'} tone="text-blue-300" />
          <Stat label="commands" value={commands?.commands.length || 0} />
          <Stat label="read-only" value={commandCounts.read_only || 0} tone="text-green-300" />
          <Stat label="gated" value={commandCounts.gated || 0} tone="text-blue-300" />
        </div>
      )}

      <Card className="p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <TerminalSquare className="h-4 w-4 text-blue-300" aria-hidden="true" />
            <h2 className="font-medium text-white">Command Schemas</h2>
          </div>
          {commands && <Badge className="bg-gray-800 text-gray-300">execution disabled</Badge>}
        </div>
        {loading ? (
          <div className="space-y-3">
            <Skeleton className="h-24" />
            <Skeleton className="h-24" />
          </div>
        ) : !commands?.commands.length ? (
          <EmptyState message="No commands are registered." />
        ) : (
          <div className="grid gap-3 xl:grid-cols-2">
            {[...readOnlyCommands, ...gatedCommands].map((command) => (
              <CommandRow key={command.name} command={command} />
            ))}
          </div>
        )}
      </Card>

      <Card className="p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Boxes className="h-4 w-4 text-cyan-300" aria-hidden="true" />
            <h2 className="font-medium text-white">Integrated Tool Status</h2>
          </div>
          {tools && (
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(tools.summary).map(([status, count]) => (
                <Badge key={status} className={statusClass(status)}>{status}: {count}</Badge>
              ))}
            </div>
          )}
        </div>
        {loading ? (
          <div className="space-y-3">
            <Skeleton className="h-24" />
            <Skeleton className="h-24" />
          </div>
        ) : visibleTools.length === 0 ? (
          <EmptyState message="No tools are registered." />
        ) : (
          <div className="grid gap-3 xl:grid-cols-2">
            {visibleTools.map((tool) => (
              <ToolRow key={tool.tool_name} tool={tool} />
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}
