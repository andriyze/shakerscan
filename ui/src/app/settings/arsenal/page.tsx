'use client'

import { useEffect, useMemo, useState } from 'react'
import { Boxes, CheckCircle2, RefreshCw, ShieldCheck, TerminalSquare, XCircle } from 'lucide-react'
import {
  createAgentContextPack,
  createAgentDecisionTrace,
  createOperationPlan,
  createApprovalReceipt,
  getAgentContextPacks,
  getAgentDecisionTraces,
  getArsenalCommands,
  getArsenalContracts,
  getOperationPlans,
  getArsenalTools,
  previewScopeReceipt,
  type AgentContextPack,
  type AgentContextPackResponse,
  type AgentDecisionTrace,
  type AgentDecisionTraceResponse,
  type ApprovalReceipt,
  type ArsenalCommand,
  type ArsenalCommandsResponse,
  type ArsenalContractDefinition,
  type ArsenalContractsResponse,
  type OperationPlan,
  type OperationPlanResponse,
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
  const [approvalRiskTier, setApprovalRiskTier] = useState('active')
  const [approvalActor, setApprovalActor] = useState('operator')
  const [denialReason, setDenialReason] = useState('')
  const [approvalReceipt, setApprovalReceipt] = useState<ApprovalReceipt | null>(null)
  const [approvalLoading, setApprovalLoading] = useState(false)
  const [approvalError, setApprovalError] = useState<string | null>(null)
  const [planObjective, setPlanObjective] = useState('Review target coverage and record the next safe action')
  const [planCommand, setPlanCommand] = useState('asm.gaps')
  const [planRiskTier, setPlanRiskTier] = useState('read_only')
  const [planContextHash, setPlanContextHash] = useState('0'.repeat(64))
  const [planResult, setPlanResult] = useState<OperationPlanResponse | null>(null)
  const [recentPlans, setRecentPlans] = useState<OperationPlan[]>([])
  const [planLoading, setPlanLoading] = useState(false)
  const [planError, setPlanError] = useState<string | null>(null)
  const [contextResult, setContextResult] = useState<AgentContextPackResponse | null>(null)
  const [traceResult, setTraceResult] = useState<AgentDecisionTraceResponse | null>(null)
  const [recentContextPacks, setRecentContextPacks] = useState<AgentContextPack[]>([])
  const [recentDecisionTraces, setRecentDecisionTraces] = useState<AgentDecisionTrace[]>([])
  const [contextTraceLoading, setContextTraceLoading] = useState(false)
  const [contextTraceError, setContextTraceError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [probing, setProbing] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function load(probeVersions = false) {
    setError(null)
    if (probeVersions) setProbing(true)
    else setLoading(true)
    try {
      const [commandData, contractData, toolData, planData, contextData, traceData] = await Promise.all([
        getArsenalCommands(),
        getArsenalContracts(),
        getArsenalTools({ probeVersions }),
        getOperationPlans(5),
        getAgentContextPacks(5),
        getAgentDecisionTraces(5),
      ])
      setCommands(commandData)
      setContracts(contractData)
      setTools(toolData)
      setRecentPlans(planData.operation_plans)
      setRecentContextPacks(contextData.context_packs)
      setRecentDecisionTraces(traceData.decision_traces)
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
  const selectedPlanCommand = useMemo(
    () => (commands?.commands || []).find((command) => command.name === planCommand),
    [commands, planCommand]
  )

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
      setApprovalReceipt(null)
      setApprovalError(null)
    } catch (err) {
      setScopeError(err instanceof Error ? err.message : 'Failed to preview scope receipt')
    } finally {
      setScopeLoading(false)
    }
  }

  async function recordApproval(action: 'approve' | 'deny') {
    if (!scopePreview) return
    setApprovalLoading(true)
    setApprovalError(null)
    try {
      const confirmations = ['confirm_authorized']
      if (scopePreview.verdict === 'needs_approval') confirmations.push('confirm_scope_reviewed')
      const response = await createApprovalReceipt({
        scope_receipt_id: scopePreview.receipt_id,
        risk_tier: approvalRiskTier,
        confirmations,
        approved_by: action === 'approve' ? approvalActor.trim() || 'operator' : undefined,
        denial_reason: action === 'deny' ? denialReason.trim() || 'Denied during receipt preview' : undefined,
      })
      setApprovalReceipt(response.approval_receipt)
    } catch (err) {
      setApprovalError(err instanceof Error ? err.message : 'Failed to create approval receipt')
    } finally {
      setApprovalLoading(false)
    }
  }

  async function createPlan() {
    setPlanLoading(true)
    setPlanError(null)
    try {
      const command = selectedPlanCommand
      const gated = command?.status === 'gated'
      const confirmations = gated ? ['confirm_authorized'] : []
      const response = await createOperationPlan({
        objective: planObjective,
        planner: { kind: 'ui', name: 'settings-arsenal', version: commands?.schema_version || 'unknown' },
        context_hash: planContextHash,
        target_scope: {
          url: scopeUrl,
          allowed_hosts: splitLines(scopeHosts),
          allowed_root_domains: splitLines(scopeRoots),
          environment: scopeEnvironment,
        },
        risk_tier: planRiskTier,
        confirmations,
        actions: [{
          command: planCommand,
          risk_tier: command?.risk_tier || planRiskTier,
          parameters: {},
          scope_receipt_id: scopePreview?.receipt_id,
          approval_receipt_id: approvalReceipt?.approved_by ? approvalReceipt.id : undefined,
          reason: 'operator dry-run preview',
        }],
        stop_conditions: ['scope_blocked', 'budget_exhausted', 'operator_cancelled'],
        success_criteria: ['plan_validated', 'no_execution_performed'],
        scope_receipt_id: scopePreview?.receipt_id,
        approval_receipt_id: approvalReceipt?.approved_by ? approvalReceipt.id : undefined,
        created_by: approvalActor.trim() || 'operator',
      })
      setPlanResult(response)
      setRecentPlans((plans) => [response.operation_plan, ...plans].slice(0, 5))
    } catch (err) {
      setPlanError(err instanceof Error ? err.message : 'Failed to validate operation plan')
    } finally {
      setPlanLoading(false)
    }
  }

  async function recordContextAndTrace() {
    setContextTraceLoading(true)
    setContextTraceError(null)
    try {
      const allowedCommands = commands?.commands
        .filter((command) => command.status === 'read_only' || command.status === 'dry_run')
        .slice(0, 12)
        .map((command) => command.name) || ['target.list', 'asm.gaps', 'operation_plan.preview']
      const contextResponse = await createAgentContextPack({
        context_hash: planContextHash,
        target_summary: {
          url: scopeUrl,
          environment: scopeEnvironment,
          allowed_hosts: splitLines(scopeHosts),
          allowed_root_domains: splitLines(scopeRoots),
        },
        current_surface: {
          source: 'settings-arsenal',
          commands_loaded: commands?.commands.length || 0,
          tools_loaded: tools?.tools.length || 0,
        },
        current_gaps: [
          { kind: 'operator_review', reason: planObjective },
        ],
        findings_summary: [],
        hypotheses_summary: [],
        allowed_commands: allowedCommands,
        disallowed_commands: (commands?.commands || [])
          .filter((command) => command.status === 'gated' || command.status === 'catalog_only' || command.status === 'out_of_scope')
          .slice(0, 8)
          .map((command) => ({ command: command.name, reason: `${command.status}:${command.risk_tier}` })),
        known_preconditions: {
          scope_receipt: scopePreview?.receipt_id || 'missing',
          approval_receipt: approvalReceipt?.approved_by ? approvalReceipt.id : 'missing',
          execution_enabled: false,
        },
        created_by: approvalActor.trim() || 'operator',
      })
      const traceResponse = await createAgentDecisionTrace({
        context_pack_id: contextResponse.context_pack.id,
        operation_plan_id: planResult?.operation_plan.id,
        planner: { kind: 'ui', name: 'settings-arsenal', version: commands?.schema_version || 'unknown' },
        context_hash: contextResponse.context_pack.context_hash,
        command_schema_version: commands?.schema_version || 'unknown',
        steps: [
          {
            kind: 'proposed_action',
            command: planCommand,
            status: 'planned',
            reason: 'operator dry-run planning trace',
            refs: planResult?.operation_plan.id ? [planResult.operation_plan.id] : [contextResponse.context_pack.id],
          },
          {
            kind: 'summary',
            status: 'recorded',
            reason: 'No command execution was requested or enabled.',
            refs: [contextResponse.context_pack.id],
          },
        ],
        final_rationale: 'Recorded bounded context and dry-run decision trace for operator review.',
        created_by: approvalActor.trim() || 'operator',
      })
      setContextResult(contextResponse)
      setTraceResult(traceResponse)
      setRecentContextPacks((packs) => [contextResponse.context_pack, ...packs].slice(0, 5))
      setRecentDecisionTraces((traces) => [traceResponse.decision_trace, ...traces].slice(0, 5))
    } catch (err) {
      setContextTraceError(err instanceof Error ? err.message : 'Failed to record context and trace')
    } finally {
      setContextTraceLoading(false)
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
            <ShieldCheck className="h-4 w-4 text-cyan-300" aria-hidden="true" />
            <h2 className="font-medium text-white">Operation Plan Preview</h2>
          </div>
          <Badge className="bg-gray-800 text-gray-300">dry-run only</Badge>
        </div>
        <div className="grid gap-3 lg:grid-cols-2">
          <label className="block">
            <span className="text-xs text-gray-400">Objective</span>
            <input
              value={planObjective}
              onChange={(event) => setPlanObjective(event.target.value)}
              className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
            />
          </label>
          <label className="block">
            <span className="text-xs text-gray-400">Command</span>
            <select
              value={planCommand}
              onChange={(event) => setPlanCommand(event.target.value)}
              className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
            >
              {(commands?.commands || []).map((command) => (
                <option key={command.name} value={command.name}>
                  {command.name}
                </option>
              ))}
            </select>
          </label>
          <label className="block">
            <span className="text-xs text-gray-400">Risk tier</span>
            <select
              value={planRiskTier}
              onChange={(event) => setPlanRiskTier(event.target.value)}
              className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
            >
              <option value="read_only">read_only</option>
              <option value="passive">passive</option>
              <option value="active">active</option>
              <option value="intrusive">intrusive</option>
              <option value="credential">credential</option>
              <option value="dangerous">dangerous</option>
            </select>
          </label>
          <label className="block">
            <span className="text-xs text-gray-400">Context hash</span>
            <input
              value={planContextHash}
              onChange={(event) => setPlanContextHash(event.target.value)}
              className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 font-mono text-xs text-white focus:border-blue-500 focus:outline-none"
            />
          </label>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <Button type="button" variant="secondary" onClick={() => void createPlan()} disabled={planLoading || !commands?.commands.length}>
            {planLoading ? 'Validating...' : 'Persist dry-run plan'}
          </Button>
          {selectedPlanCommand && (
            <span className="text-xs text-gray-500">
              {selectedPlanCommand.status} / {selectedPlanCommand.risk_tier}
              {selectedPlanCommand.status === 'gated' && !approvalReceipt?.approved_by ? ' / approval receipt required' : ''}
            </span>
          )}
          {planError && <span role="alert" className="text-sm text-red-300">{planError}</span>}
        </div>
        {planResult && (
          <div className="mt-4 rounded-md border border-gray-800 bg-gray-950 p-3">
            <div className="flex flex-wrap items-center gap-2">
              <Badge className={planResult.validated ? statusClass('read_only') : statusClass('out_of_scope')}>
                {planResult.operation_plan.status}
              </Badge>
              <span className="font-mono text-xs text-gray-400">{planResult.operation_plan.id}</span>
              <span className="text-xs text-gray-500">execution disabled</span>
            </div>
            <div className="mt-3 grid gap-2 text-xs text-gray-500 md:grid-cols-2">
              <div>errors: <span className="text-gray-300">{planResult.operation_plan.validation_errors.length ? planResult.operation_plan.validation_errors.join(', ') : 'none'}</span></div>
              <div>warnings: <span className="text-gray-300">{planResult.operation_plan.validation_warnings.length ? planResult.operation_plan.validation_warnings.join(', ') : 'none'}</span></div>
              <div>scope receipt: <span className="font-mono text-gray-300">{planResult.operation_plan.scope_receipt_id || 'none'}</span></div>
              <div>approval receipt: <span className="font-mono text-gray-300">{planResult.operation_plan.approval_receipt_id || 'none'}</span></div>
            </div>
          </div>
        )}
        {recentPlans.length > 0 && (
          <div className="mt-4 grid gap-2">
            {recentPlans.slice(0, 5).map((plan) => (
              <div key={plan.id} className="rounded-md border border-gray-800 bg-gray-950 px-3 py-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="min-w-0 truncate text-sm text-gray-200">{plan.objective}</span>
                  <div className="flex shrink-0 items-center gap-2">
                    <Badge className={plan.status === 'blocked' ? statusClass('out_of_scope') : statusClass('read_only')}>{plan.status}</Badge>
                    <span className="font-mono text-xs text-gray-500">{plan.id}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      <Card className="p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <TerminalSquare className="h-4 w-4 text-blue-300" aria-hidden="true" />
            <h2 className="font-medium text-white">Context Packs and Decision Traces</h2>
          </div>
          <Badge className="bg-gray-800 text-gray-300">dry-run records</Badge>
        </div>
        <div className="rounded-md border border-gray-800 bg-gray-950 p-3 text-sm text-gray-400">
          <div className="grid gap-2 md:grid-cols-3">
            <div>
              <span className="text-xs text-gray-500">context hash</span>
              <div className="truncate font-mono text-xs text-gray-300">{planContextHash}</div>
            </div>
            <div>
              <span className="text-xs text-gray-500">planner</span>
              <div className="text-gray-300">settings-arsenal</div>
            </div>
            <div>
              <span className="text-xs text-gray-500">execution</span>
              <div className="text-gray-300">disabled</div>
            </div>
          </div>
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <Button
              type="button"
              variant="secondary"
              onClick={() => void recordContextAndTrace()}
              disabled={contextTraceLoading || !commands?.commands.length}
            >
              {contextTraceLoading ? 'Recording...' : 'Record context + trace'}
            </Button>
            {contextTraceError && <span role="alert" className="text-sm text-red-300">{contextTraceError}</span>}
          </div>
        </div>
        {(contextResult || traceResult) && (
          <div className="mt-4 grid gap-3 lg:grid-cols-2">
            {contextResult && (
              <div className="rounded-md border border-gray-800 bg-gray-950 p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge className={contextResult.validated ? statusClass('read_only') : statusClass('out_of_scope')}>
                    {contextResult.context_pack.status}
                  </Badge>
                  <span className="font-mono text-xs text-gray-400">{contextResult.context_pack.id}</span>
                  <span className="text-xs text-gray-500">context pack</span>
                </div>
                <div className="mt-2 text-xs text-gray-500">
                  errors: <span className="text-gray-300">{contextResult.context_pack.validation_errors.length ? contextResult.context_pack.validation_errors.join(', ') : 'none'}</span>
                </div>
                <div className="mt-1 text-xs text-gray-500">
                  allowed commands: <span className="text-gray-300">{contextResult.context_pack.allowed_commands.slice(0, 6).join(', ') || 'none'}</span>
                </div>
              </div>
            )}
            {traceResult && (
              <div className="rounded-md border border-gray-800 bg-gray-950 p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge className={traceResult.validated ? statusClass('read_only') : statusClass('out_of_scope')}>
                    {traceResult.decision_trace.status}
                  </Badge>
                  <span className="font-mono text-xs text-gray-400">{traceResult.decision_trace.id}</span>
                  <span className="text-xs text-gray-500">decision trace</span>
                </div>
                <div className="mt-2 text-xs text-gray-500">
                  errors: <span className="text-gray-300">{traceResult.decision_trace.validation_errors.length ? traceResult.decision_trace.validation_errors.join(', ') : 'none'}</span>
                </div>
                <div className="mt-1 text-xs text-gray-500">
                  steps: <span className="text-gray-300">{traceResult.decision_trace.steps.length}</span>
                </div>
              </div>
            )}
          </div>
        )}
        {(recentContextPacks.length > 0 || recentDecisionTraces.length > 0) && (
          <div className="mt-4 grid gap-3 lg:grid-cols-2">
            <div className="space-y-2">
              <h3 className="text-xs font-medium uppercase text-gray-500">Recent context packs</h3>
              {recentContextPacks.slice(0, 5).map((pack) => (
                <div key={pack.id} className="rounded-md border border-gray-800 bg-gray-950 px-3 py-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-mono text-xs text-gray-400">{pack.id}</span>
                    <Badge className={pack.status === 'recorded' ? statusClass('read_only') : statusClass('out_of_scope')}>{pack.status}</Badge>
                  </div>
                  <div className="mt-1 truncate font-mono text-xs text-gray-600">{pack.context_hash}</div>
                </div>
              ))}
            </div>
            <div className="space-y-2">
              <h3 className="text-xs font-medium uppercase text-gray-500">Recent decision traces</h3>
              {recentDecisionTraces.slice(0, 5).map((trace) => (
                <div key={trace.id} className="rounded-md border border-gray-800 bg-gray-950 px-3 py-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-mono text-xs text-gray-400">{trace.id}</span>
                    <Badge className={trace.status === 'recorded' ? statusClass('read_only') : statusClass('out_of_scope')}>{trace.status}</Badge>
                  </div>
                  <div className="mt-1 text-xs text-gray-600">{trace.steps.length} steps / {trace.command_schema_version}</div>
                </div>
              ))}
            </div>
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
            <div className="mt-4 border-t border-gray-800 pt-3">
              <div className="mb-3 flex flex-wrap items-center gap-2">
                <span className="text-sm font-medium text-white">Approval Receipt</span>
                <Badge className="bg-gray-800 text-gray-300">no execution</Badge>
              </div>
              <div className="grid gap-3 md:grid-cols-3">
                <label className="block">
                  <span className="text-xs text-gray-400">Risk tier</span>
                  <select
                    value={approvalRiskTier}
                    onChange={(event) => setApprovalRiskTier(event.target.value)}
                    className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
                  >
                    <option value="active">active</option>
                    <option value="intrusive">intrusive</option>
                    <option value="credential">credential</option>
                    <option value="dangerous">dangerous</option>
                  </select>
                </label>
                <label className="block">
                  <span className="text-xs text-gray-400">Approved by</span>
                  <input
                    value={approvalActor}
                    onChange={(event) => setApprovalActor(event.target.value)}
                    className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
                  />
                </label>
                <label className="block">
                  <span className="text-xs text-gray-400">Denial reason</span>
                  <input
                    value={denialReason}
                    onChange={(event) => setDenialReason(event.target.value)}
                    className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
                  />
                </label>
              </div>
              <div className="mt-3 flex flex-wrap items-center gap-3">
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => void recordApproval('approve')}
                  disabled={approvalLoading || scopePreview.verdict === 'blocked'}
                >
                  Record approval
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  onClick={() => void recordApproval('deny')}
                  disabled={approvalLoading}
                >
                  Record denial
                </Button>
                {approvalError && <span role="alert" className="text-sm text-red-300">{approvalError}</span>}
              </div>
              {approvalReceipt && (
                <div className="mt-3 rounded-md border border-gray-800 bg-gray-900 px-3 py-2 text-xs text-gray-400">
                  Receipt: <span className="font-mono text-gray-200">{approvalReceipt.id}</span>
                  <span className="mx-2 text-gray-700">|</span>
                  {approvalReceipt.approved_by ? 'approved' : 'denied'}
                  <span className="mx-2 text-gray-700">|</span>
                  execution disabled
                </div>
              )}
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
