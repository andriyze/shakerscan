'use client'

import { useEffect, useMemo, useState } from 'react'
import { Boxes, CheckCircle2, RefreshCw, ShieldCheck, TerminalSquare, XCircle } from 'lucide-react'
import {
  getArsenalCommands,
  getArsenalContracts,
  getArsenalTools,
  previewScopeReceipt,
  type ArsenalCommand,
  type ArsenalCommandsResponse,
  type ArsenalContractDefinition,
  type ArsenalContractsResponse,
  type ArsenalTool,
  type ArsenalToolsResponse,
  type ScopeReceiptPreview,
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

function ContractRow({
  name,
  contract,
}: {
  name: string
  contract: ArsenalContractDefinition
}) {
  const required = contract.required || []
  const invariants = contract.invariants || []
  const forbidden = contract.forbidden_fields || []
  const fieldNames = Object.keys(contract.fields || {})

  return (
    <div className="rounded-md border border-gray-800 bg-gray-950 p-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-sm text-white">{name}</span>
            <Badge className={statusClass(contract.status)}>{contract.status}</Badge>
          </div>
          <p className="mt-2 text-sm text-gray-400">{contract.description}</p>
        </div>
        <div className="shrink-0 rounded bg-gray-900 px-2 py-1 text-xs text-gray-400">
          {fieldNames.length} fields
        </div>
      </div>
      <div className="mt-3 grid gap-2 text-xs text-gray-500 md:grid-cols-2">
        <div className="min-w-0">
          <span className="text-gray-400">required: </span>
          <span className="text-gray-300">{required.length ? required.slice(0, 6).join(', ') : 'none'}</span>
        </div>
        <div className="min-w-0">
          <span className="text-gray-400">fields: </span>
          <span className="text-gray-300">{fieldNames.slice(0, 6).join(', ')}</span>
        </div>
      </div>
      {invariants.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {invariants.slice(0, 3).map((invariant) => (
            <Badge key={invariant} className="bg-blue-500/15 text-blue-300">
              {invariant}
            </Badge>
          ))}
        </div>
      )}
      {forbidden.length > 0 && (
        <p className="mt-2 text-xs text-red-300">
          forbidden: {forbidden.join(', ')}
        </p>
      )}
    </div>
  )
}

export default function ArsenalSettingsPage() {
  const [commands, setCommands] = useState<ArsenalCommandsResponse | null>(null)
  const [contracts, setContracts] = useState<ArsenalContractsResponse | null>(null)
  const [tools, setTools] = useState<ArsenalToolsResponse | null>(null)
  const [scopeUrl, setScopeUrl] = useState('https://app.example.com/')
  const [scopeHosts, setScopeHosts] = useState('app.example.com')
  const [scopeRoots, setScopeRoots] = useState('example.com')
  const [scopeEnvironment, setScopeEnvironment] = useState('production')
  const [scopeRedirects, setScopeRedirects] = useState('')
  const [scopePreview, setScopePreview] = useState<ScopeReceiptPreview | null>(null)
  const [scopeLoading, setScopeLoading] = useState(false)
  const [scopeError, setScopeError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [probing, setProbing] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function load(probeVersions = false) {
    setError(null)
    if (probeVersions) setProbing(true)
    else setLoading(true)
    try {
      const [commandData, contractData, toolData] = await Promise.all([
        getArsenalCommands(),
        getArsenalContracts(),
        getArsenalTools({ probeVersions }),
      ])
      setCommands(commandData)
      setContracts(contractData)
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
  const contractEntries = useMemo(
    () => contracts?.contract_names.map((name) => [name, contracts.contracts[name]] as const).filter((entry) => Boolean(entry[1])) || [],
    [contracts]
  )
  const visibleTools = tools?.tools || []

  function splitLines(value: string): string[] {
    return value
      .split(/[\n,]/)
      .map((item) => item.trim())
      .filter(Boolean)
  }

  async function previewScope() {
    setScopeLoading(true)
    setScopeError(null)
    try {
      const response = await previewScopeReceipt({
        url: scopeUrl,
        allowed_hosts: splitLines(scopeHosts),
        allowed_root_domains: splitLines(scopeRoots),
        environment: scopeEnvironment,
        redirect_urls: splitLines(scopeRedirects),
      })
      setScopePreview(response.scope_receipt)
    } catch (err) {
      setScopeError(err instanceof Error ? err.message : 'Failed to preview scope receipt')
    } finally {
      setScopeLoading(false)
    }
  }

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
          <Stat label="contracts" value={contracts?.contract_names.length || 0} tone="text-cyan-300" />
        </div>
      )}

      <Card className="p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-green-300" aria-hidden="true" />
            <h2 className="font-medium text-white">Mission Contracts</h2>
          </div>
          {contracts && <Badge className="bg-gray-800 text-gray-300">execution disabled</Badge>}
        </div>
        {contracts && (
          <div className="mb-3 rounded-md border border-gray-800 bg-gray-950 p-3 text-xs text-gray-400">
            Secret policy: <span className="text-gray-200">{contracts.secret_policy.default}</span>
            <span className="mx-2 text-gray-700">|</span>
            never inline: <span className="text-gray-300">{contracts.secret_policy.never_inline.slice(0, 6).join(', ')}</span>
          </div>
        )}
        {loading ? (
          <div className="space-y-3">
            <Skeleton className="h-24" />
            <Skeleton className="h-24" />
          </div>
        ) : contractEntries.length === 0 ? (
          <EmptyState message="No mission contracts are registered." />
        ) : (
          <div className="grid gap-3 xl:grid-cols-2">
            {contractEntries.map(([name, contract]) => (
              <ContractRow key={name} name={name} contract={contract} />
            ))}
          </div>
        )}
      </Card>

      <Card className="p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-blue-300" aria-hidden="true" />
            <h2 className="font-medium text-white">Scope Receipt Preview</h2>
          </div>
          <Badge className="bg-gray-800 text-gray-300">no execution</Badge>
        </div>
        <div className="grid gap-3 lg:grid-cols-2">
          <label className="block">
            <span className="text-xs text-gray-400">URL</span>
            <input
              value={scopeUrl}
              onChange={(event) => setScopeUrl(event.target.value)}
              className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
            />
          </label>
          <label className="block">
            <span className="text-xs text-gray-400">Environment</span>
            <select
              value={scopeEnvironment}
              onChange={(event) => setScopeEnvironment(event.target.value)}
              className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
            >
              <option value="production">production</option>
              <option value="staging">staging</option>
              <option value="preview">preview</option>
              <option value="lab">lab</option>
              <option value="development">development</option>
            </select>
          </label>
          <label className="block">
            <span className="text-xs text-gray-400">Allowed hosts</span>
            <textarea
              value={scopeHosts}
              onChange={(event) => setScopeHosts(event.target.value)}
              rows={3}
              className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
            />
          </label>
          <label className="block">
            <span className="text-xs text-gray-400">Allowed root domains</span>
            <textarea
              value={scopeRoots}
              onChange={(event) => setScopeRoots(event.target.value)}
              rows={3}
              className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
            />
          </label>
          <label className="block lg:col-span-2">
            <span className="text-xs text-gray-400">Redirect destinations to validate</span>
            <textarea
              value={scopeRedirects}
              onChange={(event) => setScopeRedirects(event.target.value)}
              rows={2}
              className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
            />
          </label>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <Button type="button" variant="secondary" onClick={() => void previewScope()} disabled={scopeLoading}>
            {scopeLoading ? 'Validating...' : 'Preview receipt'}
          </Button>
          {scopeError && <span role="alert" className="text-sm text-red-300">{scopeError}</span>}
        </div>
        {scopePreview && (
          <div className="mt-4 rounded-md border border-gray-800 bg-gray-950 p-3">
            <div className="flex flex-wrap items-center gap-2">
              <Badge className={scopePreview.verdict === 'allowed' ? statusClass('read_only') : scopePreview.verdict === 'blocked' ? statusClass('out_of_scope') : statusClass('dry_run')}>
                {scopePreview.verdict}
              </Badge>
              <span className="font-mono text-xs text-gray-400">{scopePreview.receipt_id}</span>
              <span className="text-xs text-gray-500">persisted receipt preview</span>
            </div>
            <div className="mt-3 grid gap-2 text-xs text-gray-500 md:grid-cols-2">
              <div>host: <span className="text-gray-300">{String(scopePreview.normalized_scope.host || 'none')}</span></div>
              <div>blocked: <span className="text-gray-300">{scopePreview.blocked_by.length ? scopePreview.blocked_by.join(', ') : 'none'}</span></div>
              <div>warnings: <span className="text-gray-300">{scopePreview.warnings.length ? scopePreview.warnings.join(', ') : 'none'}</span></div>
              <div>redirects: <span className="text-gray-300">{scopePreview.redirect_destinations.length}</span></div>
            </div>
            <div className="mt-3 flex flex-wrap gap-1.5">
              {scopePreview.checks.slice(0, 8).map((check) => (
                <Badge key={`${check.name}-${check.status}`} className={check.status === 'passed' ? statusClass('read_only') : check.status === 'blocked' ? statusClass('out_of_scope') : statusClass('dry_run')}>
                  {check.name}: {check.status}
                </Badge>
              ))}
            </div>
          </div>
        )}
      </Card>

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
