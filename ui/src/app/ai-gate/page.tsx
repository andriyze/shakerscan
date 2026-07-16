'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { Bot, CheckCircle2, Clipboard, Download, Play, Plus, RefreshCw, ShieldCheck, Trash2, Wand2 } from 'lucide-react'
import AISurfaceInventoryPanel from '@/components/AISurfaceInventoryPanel'
import {
  Button,
  Card,
  CardSkeleton,
  ConfirmDialog,
  EmptyState,
  ErrorState,
  useToast,
} from '@/components/ui'
import {
  createAITarget,
  deleteAITarget,
  getAIInventory,
  getAISettings,
  getAITestScenarios,
  getAITargets,
  getAiTargetCampaignHistory,
  runAIDemo,
  scanAITarget,
  testAITargetConnectivity,
  testMCPReadiness,
  type AIDemoRunResponse,
  type AIInventory,
  type AIInventoryCandidate,
  type AIMCPLiveReadinessResult,
  type AITargetConnectivityResult,
  type AISettings,
  type AITestReadinessControl,
  type AITestScenario,
  type AITestTargetTemplate,
  type AiTargetCampaignHistory,
  type AiReadinessTrendPoint,
  type AIAuthKind,
  type AIEnvironment,
  type AIProbePack,
  type AIScanProfile,
  type AITarget,
  type AITargetPayload,
  type AITargetType,
} from '@/lib/api'

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080'

const REDTEAM_RESOURCE_LINKS = [
  { label: 'Learning map', href: `${API_URL}/ai/learning-guide` },
  { label: 'Test cases', href: `${API_URL}/ai/test-cases` },
  { label: 'promptfoo export', href: `${API_URL}/ai/test-cases/export?format=promptfoo` },
  { label: 'PyRIT export', href: `${API_URL}/ai/test-cases/export?format=pyrit` },
  { label: 'garak seed', href: `${API_URL}/ai/test-cases/export?format=garak` },
]

const TARGET_TYPES: Array<{ value: AITargetType; label: string; probePack: AIProbePack; responsePath: string; template: Record<string, unknown> }> = [
  {
    value: 'api_chat',
    label: 'Chat API',
    probePack: 'shaker-ai-smoke',
    responsePath: '$.answer',
    template: { message: '{{prompt}}', session_id: '{{session_id}}' },
  },
  {
    value: 'rag',
    label: 'RAG API',
    probePack: 'shaker-rag-lite',
    responsePath: '$.answer',
    template: { message: '{{prompt}}', session_id: '{{session_id}}' },
  },
  {
    value: 'agent_trace',
    label: 'Agent Trace API',
    probePack: 'shaker-agent-abuse',
    responsePath: '$',
    template: { message: '{{prompt}}', session_id: '{{session_id}}' },
  },
  {
    value: 'mcp_trace',
    label: 'MCP HTTP/SSE',
    probePack: 'shaker-mcp-security',
    responsePath: '$.result',
    template: {
      jsonrpc: '2.0',
      method: 'tools/list',
      params: { cursor: '{{prompt}}' },
      id: '{{session_id}}',
    },
  },
]

const AUTH_KINDS: Array<{ value: AIAuthKind; label: string }> = [
  { value: 'none', label: 'No auth' },
  { value: 'bearer', label: 'Bearer token' },
  { value: 'api_key_header', label: 'API key header' },
  { value: 'custom_header', label: 'Custom header' },
  { value: 'basic_auth', label: 'Basic auth' },
  { value: 'cookie', label: 'Cookie' },
  { value: 'multi_header', label: 'Multiple headers' },
  { value: 'query_param', label: 'Query parameter' },
]

const PROBE_PACKS: Array<{ value: AIProbePack; label: string }> = [
  { value: 'shaker-ai-smoke', label: 'AI Smoke' },
  { value: 'shaker-owasp-llm', label: 'OWASP LLM' },
  { value: 'shaker-agent-abuse', label: 'Agent Abuse' },
  { value: 'shaker-mcp-security', label: 'MCP Security' },
  { value: 'shaker-rag-lite', label: 'RAG Lite' },
]

const SCAN_PROFILES: Array<{ value: AIScanProfile; label: string }> = [
  { value: 'smoke', label: 'Quick' },
  { value: 'trace', label: 'Trace' },
  { value: 'standard', label: 'Standard' },
  { value: 'deep', label: 'Deep' },
]

const ENVIRONMENTS: Array<{ value: AIEnvironment; label: string }> = [
  { value: 'preview', label: 'Preview' },
  { value: 'staging', label: 'Staging' },
  { value: 'production', label: 'Production' },
  { value: 'development', label: 'Development' },
]

type RunConfig = {
  probe_pack: AIProbePack
  scan_profile: AIScanProfile
  environment: AIEnvironment
}

const inputClass =
  'min-w-0 w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none'
const textareaClass =
  'min-w-0 w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 font-mono text-xs text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none'

function jsonText(value: unknown) {
  return JSON.stringify(value, null, 2)
}

function parseJsonObject(label: string, raw: string): Record<string, unknown> {
  const parsed = JSON.parse(raw || '{}')
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`${label} must be a JSON object`)
  }
  return parsed as Record<string, unknown>
}

function validateJsonObjectField(label: string, raw: string, optional = false): string | undefined {
  if (optional && !raw.trim()) return undefined
  try {
    parseJsonObject(label, raw)
    return undefined
  } catch (err) {
    if (err instanceof SyntaxError) return `${label} is not valid JSON`
    return err instanceof Error ? err.message : `${label} is invalid`
  }
}

function validateEndpointUrl(raw: string): string | undefined {
  const trimmed = raw.trim()
  if (!trimmed) return 'Endpoint URL is required'
  try {
    const parsed = new URL(trimmed)
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return 'Endpoint URL must use http or https'
    }
  } catch {
    return 'Endpoint URL must be a valid http(s) URL'
  }
  return undefined
}

function invalidFieldClass(base: string) {
  return base.replace('border-gray-700', 'border-red-500/50')
}

interface TargetFormErrors {
  endpointUrl?: string
  headersTemplate?: string
  requestTemplate?: string
  controlMetadata?: string
}

function parseList(raw: string): string[] {
  return raw
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean)
}

function parseHeaderPairs(raw: string) {
  return raw
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .flatMap((line) => {
      const idx = line.indexOf(':')
      if (idx <= 0) return []
      const name = line.slice(0, idx).trim()
      const value = line.slice(idx + 1).trim()
      return name && value ? [{ name, value }] : []
    })
}

function hasMetadataKey(metadata: Record<string, unknown> | null | undefined, keys: string[]) {
  if (!metadata) return false
  return keys.some((key) => {
    const value = metadata[key]
    if (value === undefined || value === null) return false
    if (typeof value === 'string') return value.trim().length > 0
    if (Array.isArray(value)) return value.length > 0
    if (typeof value === 'object') return Object.keys(value as Record<string, unknown>).length > 0
    return Boolean(value)
  })
}

function applicableControls(targetType: AITargetType | string, controls: AITestReadinessControl[]) {
  const isRag = targetType === 'rag'
  const isAgent = targetType === 'agent_trace' || targetType === 'mcp_trace' || targetType === 'widget'
  return controls.filter((control) => {
    if (!control.applies_to || control.applies_to === 'all') return true
    if (control.applies_to === 'rag') return isRag
    if (control.applies_to === 'agent') return isAgent
    return control.applies_to === targetType
  })
}

function controlSummary(targetType: AITargetType | string, metadata: Record<string, unknown> | null | undefined, controls: AITestReadinessControl[]) {
  const scopedControls = applicableControls(targetType, controls)
  const missing = scopedControls.filter((control) => !hasMetadataKey(metadata, control.keys))
  return {
    present: scopedControls.length - missing.length,
    required: scopedControls.length,
    missing,
  }
}

function isCalibrationLikeTarget(target: AITarget, includeLegacyHints = false) {
  const metadata = target.metadata_json || {}
  const demoFlag = metadata.shakerscan_demo
  if (demoFlag === true || String(demoFlag || '').trim().toLowerCase() === 'true') return true
  if (demoFlag === false || String(demoFlag || '').trim().toLowerCase() === 'false') return false
  if (metadata.calibration_run || metadata.honey_scenario_id || metadata.safe_fixture !== undefined) return true
  if (Array.isArray(metadata.expected_shakerscan_findings)) return true

  if (!includeLegacyHints) return false

  const url = String(target.endpoint_url || '').toLowerCase()
  if (url.includes('honey.shakerscan.com')) return true
  if (url.includes('calibration_run=')) return true

  const name = String(target.name || '').toLowerCase()
  const nameLooksLab = name.includes(' calibration') || name.startsWith('calibration ') || name.includes(' honey ') || name.startsWith('honey ')
  const urlLooksLocalLab = url.includes('host.docker.internal:18080') || url.includes('localhost:18080')
  return nameLooksLab && urlLooksLocalLab
}

function defaultRunConfig(target: AITarget): RunConfig {
  const typeDefault = TARGET_TYPES.find((type) => type.value === target.target_type)
  return {
    probe_pack: typeDefault?.probePack || 'shaker-ai-smoke',
    scan_profile: 'smoke',
    environment: target.production_mode ? 'production' : 'preview',
  }
}

function getRunButtonLabel(config: RunConfig) {
  return config.scan_profile === 'smoke' ? 'Run Quick Scan' : 'Run AI Gate Scan'
}

function summarizeRequestTemplate(template: Record<string, unknown> | null | undefined) {
  const request = template || {}
  const promptFields = ['message', 'prompt', 'query', 'input', 'task', 'params']
    .filter((field) => Object.prototype.hasOwnProperty.call(request, field))
  if (promptFields.length > 0) return promptFields.slice(0, 3).join(', ')
  const keys = Object.keys(request)
  return keys.length ? keys.slice(0, 3).join(', ') : 'custom JSON'
}

function formatCampaignLabel(value: string | null | undefined): string {
  if (!value) return 'unknown'
  return value.replace(/^shaker-/, '').replace(/[-_]/g, ' ')
}

function formatShortDate(value: string | null | undefined): string {
  if (!value) return 'unknown'
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return value
  return parsed.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

function formatDelta(value: number | null | undefined, suffix = ''): string {
  const n = Number(value || 0)
  if (n === 0) return `0${suffix}`
  return `${n > 0 ? '+' : ''}${n}${suffix}`
}

function decisionPillClass(decision: string | null | undefined): string {
  if (decision === 'block') return 'bg-red-500/10 text-red-300'
  if (decision === 'needs_approval') return 'bg-yellow-500/10 text-yellow-200'
  if (decision === 'allow') return 'bg-emerald-500/10 text-emerald-300'
  return 'bg-gray-800 text-gray-300'
}

function readinessTrendClass(state: string | null | undefined): string {
  if (state === 'improving') return 'bg-emerald-500/10 text-emerald-300'
  if (state === 'blocked' || state === 'regressed') return 'bg-red-500/10 text-red-300'
  if (state === 'baseline') return 'bg-blue-500/10 text-blue-200'
  if (state === 'stable') return 'bg-gray-800 text-gray-200'
  return 'bg-gray-800 text-gray-400'
}

function CampaignTrendBars({
  points,
  title,
  compact = false,
}: {
  points?: AiReadinessTrendPoint[]
  title: string
  compact?: boolean
}) {
  if (!points || points.length === 0) return null
  return (
    <div className={compact ? 'mt-2 border-t border-gray-800 pt-2' : 'rounded border border-gray-800 bg-gray-950 p-2'}>
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2 text-xs">
        <span className="font-medium text-gray-200">{title}</span>
        <span className="text-gray-500">{points.length} point{points.length === 1 ? '' : 's'}</span>
      </div>
      <div className={compact ? 'flex h-12 items-end gap-1' : 'flex h-20 items-end gap-1.5'}>
        {points.map((point, index) => {
          const score = Math.max(0, Math.min(100, Number(point.readiness_score ?? 0)))
          const height = Math.max(6, score)
          const tone = point.decision === 'block'
            ? 'bg-red-400'
            : point.errors && point.errors > 0
              ? 'bg-yellow-300'
              : 'bg-emerald-300'
          const label = `${formatShortDate(point.completed_at)} score ${score}, coverage ${point.coverage_pct ?? 0}%, findings ${point.findings_count ?? 0}, errors ${point.errors ?? 0}`
          return (
            <div key={`${point.scan_id || 'run'}-${index}`} className="flex min-w-[14px] flex-1 flex-col items-center justify-end gap-1">
              <div className="flex h-full w-full items-end rounded-sm bg-gray-900" title={label} aria-label={label}>
                <div className={`w-full rounded-sm ${tone}`} style={{ height: `${height}%` }} />
              </div>
              {!compact && <span className="max-w-full truncate text-[10px] text-gray-500">{point.coverage_pct ?? 0}%</span>}
            </div>
          )
        })}
      </div>
    </div>
  )
}

export default function AIGateSettingsPage() {
  const router = useRouter()
  const toast = useToast()
  const initialType = TARGET_TYPES[0]
  const [targets, setTargets] = useState<AITarget[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const [scanning, setScanning] = useState<string | null>(null)
  const [testingTarget, setTestingTarget] = useState<string | null>(null)
  const [testingMCP, setTestingMCP] = useState<string | null>(null)
  const [connectivityResults, setConnectivityResults] = useState<Record<string, AITargetConnectivityResult>>({})
  const [mcpReadinessResults, setMCPReadinessResults] = useState<Record<string, AIMCPLiveReadinessResult>>({})
  const [campaignHistories, setCampaignHistories] = useState<Record<string, AiTargetCampaignHistory>>({})
  const [campaignHistoryErrors, setCampaignHistoryErrors] = useState<Record<string, string>>({})
  const [loadingCampaignHistory, setLoadingCampaignHistory] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [fieldErrors, setFieldErrors] = useState<TargetFormErrors>({})
  const [confirmDisableTarget, setConfirmDisableTarget] = useState<AITarget | null>(null)
  const [disabling, setDisabling] = useState(false)
  const [confirmProductionTarget, setConfirmProductionTarget] = useState<AITarget | null>(null)
  const [confirmingProduction, setConfirmingProduction] = useState(false)
  const [runConfigs, setRunConfigs] = useState<Record<string, RunConfig>>({})
  const [scenario, setScenario] = useState<AITestScenario | null>(null)
  const [inventory, setInventory] = useState<AIInventory | null>(null)
  const [inventoryError, setInventoryError] = useState<string | null>(null)
  const [copied, setCopied] = useState<string | null>(null)
  const [aiSettings, setAISettings] = useState<AISettings | null>(null)
  const [showAddTarget, setShowAddTarget] = useState(false)
  const [showAdvancedTarget, setShowAdvancedTarget] = useState(false)
  const [showDemoTargets, setShowDemoTargets] = useState(false)
  const [demoRunning, setDemoRunning] = useState(false)
  const [demoResult, setDemoResult] = useState<AIDemoRunResponse | null>(null)
  const [controlRemediationMode, setControlRemediationMode] = useState(false)

  const [name, setName] = useState('')
  const [targetType, setTargetType] = useState<AITargetType>(initialType.value)
  const [endpointUrl, setEndpointUrl] = useState('')
  const [method, setMethod] = useState<'GET' | 'POST' | 'PUT' | 'PATCH'>('POST')
  const [responsePath, setResponsePath] = useState(initialType.responsePath)
  const [streamingMode, setStreamingMode] = useState<'json' | 'sse'>('json')
  const [headersTemplate, setHeadersTemplate] = useState(jsonText({ 'Content-Type': 'application/json' }))
  const [requestTemplate, setRequestTemplate] = useState(jsonText(initialType.template))
  const [authKind, setAuthKind] = useState<AIAuthKind>('none')
  const [headerName, setHeaderName] = useState('')
  const [secret, setSecret] = useState('')
  const [rateLimitRps, setRateLimitRps] = useState('2')
  const [requestBudget, setRequestBudget] = useState('3')
  const [tokenBudget, setTokenBudget] = useState('')
  const [canaryTokens, setCanaryTokens] = useState('')
  const [controlMetadata, setControlMetadata] = useState('')
  const [productionMode, setProductionMode] = useState(false)

  const selectedType = useMemo(
    () => TARGET_TYPES.find((type) => type.value === targetType) || initialType,
    [targetType, initialType]
  )

  const loadTargets = useCallback(async () => {
    setLoading(true)
    try {
      const payload = await getAITargets({ includeInactive: false, includeDemo: showDemoTargets, limit: 500 })
      setTargets(payload.targets)
      setRunConfigs((prev) => {
        const next = { ...prev }
        for (const target of payload.targets) {
          if (!next[target.id]) next[target.id] = defaultRunConfig(target)
        }
        return next
      })
      setLoadError(null)
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : 'Failed to load AI targets')
    } finally {
      setLoading(false)
    }
  }, [showDemoTargets])

  const loadInventory = useCallback(async () => {
    try {
      setInventory(await getAIInventory())
      setInventoryError(null)
    } catch (err) {
      setInventory(null)
      setInventoryError(err instanceof Error ? err.message : 'Failed to load AI inventory')
    }
  }, [])

  const loadTargetCampaignHistory = useCallback(async (targetId: string) => {
    setLoadingCampaignHistory(targetId)
    try {
      const history = await getAiTargetCampaignHistory(targetId, 12)
      setCampaignHistories((prev) => ({ ...prev, [targetId]: history }))
      setCampaignHistoryErrors((prev) => {
        const next = { ...prev }
        delete next[targetId]
        return next
      })
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to load AI Gate campaign history'
      setCampaignHistoryErrors((prev) => ({ ...prev, [targetId]: msg }))
    } finally {
      setLoadingCampaignHistory(null)
    }
  }, [])

  useEffect(() => {
    loadTargets()
  }, [loadTargets])

  useEffect(() => {
    setControlRemediationMode(new URLSearchParams(window.location.search).get('remediate') === 'controls')
  }, [])

  useEffect(() => {
    loadInventory()
  }, [loadInventory])

  useEffect(() => {
    async function loadSettingsAndScenario() {
      try {
        const settings = await getAISettings()
        setAISettings(settings)
        const payload = await getAITestScenarios()
        setScenario(payload.scenarios.find((item) => item.id === 'secure-rag-agent') || null)
      } catch {
        setAISettings(null)
        setScenario(null)
      }
    }
    loadSettingsAndScenario()
  }, [])

  function applyTargetType(nextType: AITargetType) {
    const definition = TARGET_TYPES.find((type) => type.value === nextType) || TARGET_TYPES[0]
    setTargetType(nextType)
    setFieldErrors((prev) => ({ ...prev, requestTemplate: undefined, headersTemplate: undefined }))
    setRequestTemplate(jsonText(definition.template))
    setResponsePath(definition.responsePath)
    setMethod('POST')
    setStreamingMode(definition.value === 'mcp_trace' ? 'sse' : 'json')
    setHeadersTemplate(
      jsonText(
        definition.value === 'mcp_trace'
          ? { 'Content-Type': 'application/json', Accept: 'text/event-stream' }
          : { 'Content-Type': 'application/json' }
      )
    )
    setRequestBudget(definition.value === 'api_chat' ? '3' : '5')
  }

  function resetForm() {
    setName('')
    setEndpointUrl('')
    setAuthKind('none')
    setHeaderName('')
    setSecret('')
    setCanaryTokens('')
    setControlMetadata('')
    setProductionMode(false)
    setShowAdvancedTarget(false)
    setFieldErrors({})
    applyTargetType('api_chat')
  }

  function applyScenarioTemplate(template: AITestTargetTemplate) {
    setFieldErrors({})
    setName(template.name)
    setTargetType(template.target_type)
    setEndpointUrl(template.endpoint_url)
    setMethod(template.method)
    setResponsePath(template.response_path || '')
    setStreamingMode(template.streaming_mode)
    setHeadersTemplate(jsonText(template.headers_template || {}))
    setRequestTemplate(jsonText(template.request_template || {}))
    setRateLimitRps(template.rate_limit_rps ? String(template.rate_limit_rps) : '')
    setRequestBudget(template.request_budget ? String(template.request_budget) : '')
    setTokenBudget(template.token_budget ? String(template.token_budget) : '')
    setControlMetadata(jsonText(template.metadata_json || {}))
    setProductionMode(false)
    setShowAdvancedTarget(true)
  }

  async function copyCurrentPayload() {
    try {
      await navigator.clipboard.writeText(jsonText(buildPayload()))
      setCopied('target-payload')
      setTimeout(() => setCopied(null), 1500)
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to copy payload'
      setError(msg)
      toast.error(msg)
    }
  }

  function validateField(field: keyof TargetFormErrors) {
    setFieldErrors((prev) => ({
      ...prev,
      [field]:
        field === 'endpointUrl'
          ? validateEndpointUrl(endpointUrl)
          : field === 'headersTemplate'
            ? validateJsonObjectField('Headers template', headersTemplate)
            : field === 'requestTemplate'
              ? validateJsonObjectField('Request template', requestTemplate)
              : validateJsonObjectField('Control metadata', controlMetadata, true),
    }))
  }

  function validateTargetForm(): boolean {
    const errors: TargetFormErrors = {
      endpointUrl: validateEndpointUrl(endpointUrl),
      headersTemplate: validateJsonObjectField('Headers template', headersTemplate),
      requestTemplate: validateJsonObjectField('Request template', requestTemplate),
      controlMetadata: validateJsonObjectField('Control metadata', controlMetadata, true),
    }
    setFieldErrors(errors)
    return !Object.values(errors).some(Boolean)
  }

  function buildPayload(): AITargetPayload {
    const headers = parseJsonObject('Headers template', headersTemplate)
    const request = parseJsonObject('Request template', requestTemplate)
    const metadata: Record<string, unknown> = controlMetadata.trim()
      ? parseJsonObject('Control metadata', controlMetadata)
      : {}
    const canaries = parseList(canaryTokens)
    if (canaries.length) metadata.canary_tokens = canaries

    const credential: AITargetPayload['credential'] = {
      auth_kind: authKind,
      header_name: headerName.trim() || null,
      secret: secret.trim() || null,
      metadata_json: null,
    }
    if (authKind === 'query_param') {
      credential.metadata_json = { param_name: headerName.trim() }
    }
    if (authKind === 'multi_header') {
      credential.secret = null
      credential.metadata_json = { headers: parseHeaderPairs(secret) }
    }

    return {
      name: name.trim() || undefined,
      target_type: targetType,
      endpoint_url: endpointUrl.trim(),
      method,
      headers_template: headers,
      request_template: request,
      response_path: responsePath.trim() || null,
      streaming_mode: streamingMode,
      rate_limit_rps: rateLimitRps ? Number(rateLimitRps) : null,
      request_budget: requestBudget ? Number(requestBudget) : null,
      token_budget: tokenBudget ? Number(tokenBudget) : null,
      production_mode: productionMode,
      metadata_json: metadata,
      credential,
    }
  }

  async function handleCreate(event: React.FormEvent) {
    event.preventDefault()
    if (!validateTargetForm()) {
      setError('Fix the highlighted fields before saving.')
      return
    }
    setSaving(true)
    setError(null)
    try {
      const payload = buildPayload()
      const result = await createAITarget(payload)
      toast.success(`Saved ${result.target.name}.`)
      resetForm()
      setShowAddTarget(false)
      await loadTargets()
      await loadInventory()
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to save AI target'
      setError(msg)
      toast.error(msg)
    } finally {
      setSaving(false)
    }
  }

  async function handleDisableConfirmed() {
    const target = confirmDisableTarget
    if (!target) return
    setDisabling(true)
    setError(null)
    try {
      await deleteAITarget(target.id)
      toast.success(`${target.name} disabled.`)
      setConfirmDisableTarget(null)
      await loadTargets()
      await loadInventory()
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to disable AI target'
      setError(msg)
      toast.error(msg)
      setConfirmDisableTarget(null)
    } finally {
      setDisabling(false)
    }
  }

  async function executeRun(target: AITarget) {
    const config = runConfigs[target.id] || defaultRunConfig(target)
    setScanning(target.id)
    setError(null)
    try {
      const result = await scanAITarget(target.id, {
        ...config,
        confirm_production: target.production_mode,
      })
      if (result.scan_id) {
        toast.success('AI Gate scan queued.', { link: { href: `/scans/${result.scan_id}`, label: 'View scan' } })
        router.push(`/scans/${result.scan_id}`)
      } else {
        // No scan id came back (e.g. a dry-run/blocked submission) — don't navigate to
        // /scans/undefined; tell the user it was queued without a viewable scan.
        toast.success('AI Gate scan queued.')
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to queue AI Gate scan'
      setError(msg)
      toast.error(msg)
    } finally {
      setScanning(null)
    }
  }

  async function handleRun(target: AITarget) {
    if (target.production_mode) {
      setConfirmProductionTarget(target)
      return
    }
    await executeRun(target)
  }

  async function handleConnectivityTest(target: AITarget) {
    if (testingTarget) return
    setTestingTarget(target.id)
    setError(null)
    try {
      const result = await testAITargetConnectivity(target.id)
      setConnectivityResults((prev) => ({ ...prev, [target.id]: result }))
      if (result.ok) {
        toast.success(`${target.name} connectivity passed.`)
      } else {
        toast.error(`${target.name} connectivity needs attention.`)
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to test AI target'
      setError(msg)
      toast.error(msg)
    } finally {
      setTestingTarget(null)
    }
  }

  async function handleMCPReadiness(target: AITarget) {
    if (testingMCP) return
    setTestingMCP(target.id)
    setError(null)
    try {
      const result = await testMCPReadiness(target.id)
      setMCPReadinessResults((prev) => ({ ...prev, [target.id]: result }))
      const warnings = result.summary?.warnings ?? 0
      if (warnings === 0) {
        toast.success(`${target.name} MCP readiness passed.`)
      } else {
        toast.error(`${target.name} has ${warnings} MCP readiness warning${warnings === 1 ? '' : 's'}.`)
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to test MCP readiness'
      setError(msg)
      toast.error(msg)
    } finally {
      setTestingMCP(null)
    }
  }

  function applyInventoryCandidate(candidate: AIInventoryCandidate) {
    const payload = candidate.suggested_target
    setFieldErrors({})
    setName(payload.name || `Discovered ${candidate.target_type}`)
    setTargetType(payload.target_type)
    setEndpointUrl(payload.endpoint_url)
    setMethod(payload.method)
    setResponsePath(payload.response_path || '')
    setStreamingMode(payload.streaming_mode)
    setHeadersTemplate(jsonText(payload.headers_template || {}))
    setRequestTemplate(jsonText(payload.request_template || {}))
    setRateLimitRps(payload.rate_limit_rps ? String(payload.rate_limit_rps) : '2')
    setRequestBudget(payload.request_budget ? String(payload.request_budget) : '5')
    setTokenBudget(payload.token_budget ? String(payload.token_budget) : '')
    setControlMetadata(jsonText(payload.metadata_json || {}))
    setAuthKind('none')
    setHeaderName('')
    setSecret('')
    setProductionMode(false)
    setShowAddTarget(true)
    setShowAdvancedTarget(true)
    toast.info(`Loaded discovered ${candidate.target_type} candidate into the form.`)
  }

  async function handleRunDemo() {
    if (demoRunning) return
    setDemoRunning(true)
    setError(null)
    setDemoResult(null)
    try {
      const result = await runAIDemo({ scan_profile: 'smoke', request_budget: 1 })
      setDemoResult(result)
      const failedCount = result.failed?.length || 0
      const summary = failedCount
        ? `Queued ${result.queued.length} Honey demo scan${result.queued.length === 1 ? '' : 's'}; ${failedCount} scenario${failedCount === 1 ? '' : 's'} failed to queue.`
        : `Queued ${result.queued.length} Honey demo scan${result.queued.length === 1 ? '' : 's'}.`
      if (failedCount && result.queued.length === 0) {
        toast.error(summary)
      } else {
        toast.success(summary)
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to queue Honey demo'
      setError(msg)
      toast.error(msg)
    } finally {
      setDemoRunning(false)
    }
  }

  function updateRunConfig(targetId: string, patch: Partial<RunConfig>) {
    setRunConfigs((prev) => ({
      ...prev,
      [targetId]: { ...(prev[targetId] || { probe_pack: 'shaker-ai-smoke', scan_profile: 'smoke', environment: 'preview' }), ...patch },
    }))
  }

  let formMetadata: Record<string, unknown> = {}
  try {
    formMetadata = controlMetadata.trim() ? parseJsonObject('Control metadata', controlMetadata) : {}
  } catch {
    formMetadata = {}
  }
  const formControlSummary = scenario
    ? controlSummary(targetType, formMetadata, scenario.readiness_controls || [])
    : null
  const visibleTargets = useMemo(() => {
    const filtered = targets.filter((target) => showDemoTargets || !isCalibrationLikeTarget(target, true))
    if (!controlRemediationMode || !scenario) return filtered
    const readinessControls = scenario.readiness_controls || []
    return [...filtered].sort((a, b) => {
      const aMissing = controlSummary(a.target_type, a.metadata_json || {}, readinessControls).missing.length
      const bMissing = controlSummary(b.target_type, b.metadata_json || {}, readinessControls).missing.length
      if (aMissing && !bMissing) return -1
      if (!aMissing && bMissing) return 1
      return bMissing - aMissing
    })
  }, [controlRemediationMode, scenario, showDemoTargets, targets])
  const inventoryCandidates = useMemo(
    () => (inventory?.candidates || []).slice(0, 5),
    [inventory]
  )
  const hiddenCalibrationCount = targets.length - visibleTargets.length
  const shouldShowCreate = showAddTarget
  const hasFieldErrors = Object.values(fieldErrors).some(Boolean)
  const promptWarning = targetType === 'api_chat' && !requestTemplate.includes('{{prompt}}')
  const confirmProductionConfig = confirmProductionTarget
    ? runConfigs[confirmProductionTarget.id] || defaultRunConfig(confirmProductionTarget)
    : null

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Bot className="h-6 w-6 text-blue-400" />
            <h1 className="text-2xl font-bold text-white">AI Gate</h1>
          </div>
          <p className="mt-1 text-gray-400">Manage AI chat, RAG, agent trace, and MCP targets.</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button onClick={() => setShowAddTarget((value) => !value)}>
            <Plus className="h-4 w-4" aria-hidden="true" />
            {showAddTarget ? 'Close' : 'Add Target'}
          </Button>
        </div>
      </div>

      {error && <div role="alert" className="rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-sm text-red-400">{error}</div>}

      {aiSettings?.demo_mode_enabled && (
        <div className="rounded-lg border border-amber-500/20 bg-amber-500/10 p-3 text-sm text-amber-100">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span>Calibration Lab mode is enabled. Demo controls and lab targets are separated from normal AI targets.</span>
            <Link href="/settings" className="rounded border border-amber-400/30 px-2 py-1 text-xs text-amber-100 hover:bg-amber-500/10">
              Manage in Settings
            </Link>
          </div>
        </div>
      )}

      {!inventory && inventoryError && (
        <Card className="p-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="min-w-0">
              <div className="flex items-center gap-2 text-white">
                <Bot className="h-4 w-4 text-purple-300" />
                <h2 className="text-sm font-semibold">AI Inventory</h2>
              </div>
              <p role="alert" className="mt-2 break-words text-xs text-red-400">{inventoryError}</p>
            </div>
            <button onClick={loadInventory} className="inline-flex items-center gap-2 rounded-lg border border-gray-700 px-3 py-2 text-sm text-gray-300 hover:bg-gray-800">
              <RefreshCw className="h-4 w-4" />
              Retry
            </button>
          </div>
        </Card>
      )}

      {inventory && (
        <Card className="p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="flex items-center gap-2 text-white">
                <Bot className="h-4 w-4 text-purple-300" />
                <h2 className="text-sm font-semibold">AI Inventory</h2>
              </div>
              <div className="mt-2 flex flex-wrap gap-2 text-xs text-gray-400">
                <span className="rounded bg-gray-950 px-2 py-1">{inventory.summary.asset_count} assets</span>
                <span className="rounded bg-gray-950 px-2 py-1">{inventory.summary.candidate_count} candidates</span>
                <span className="rounded bg-gray-950 px-2 py-1">blast radius {inventory.summary.highest_blast_radius_score}</span>
                {inventory.summary.coverage_gaps.slice(0, 3).map((gap) => (
                  <span key={gap} className="rounded bg-yellow-500/10 px-2 py-1 text-yellow-200">{gap.replaceAll('_', ' ')}</span>
                ))}
              </div>
            </div>
            <button onClick={loadInventory} className="inline-flex items-center gap-2 rounded-lg border border-gray-700 px-3 py-2 text-sm text-gray-300 hover:bg-gray-800">
              <RefreshCw className="h-4 w-4" />
              Refresh
            </button>
          </div>
          {inventoryCandidates.length > 0 && (
            <div className="mt-4 grid gap-2 sm:grid-cols-1 lg:grid-cols-2">
              {inventoryCandidates.map((candidate) => {
                const confidencePct = Number.isFinite(candidate.confidence)
                  ? Math.round(candidate.confidence * 100)
                  : null
                return (
                  <button
                    key={candidate.candidate_id}
                    type="button"
                    onClick={() => applyInventoryCandidate(candidate)}
                    className="min-w-0 rounded-lg border border-gray-800 bg-gray-950 p-3 text-left hover:border-blue-500/60 hover:bg-gray-800"
                  >
                    <div className="flex min-w-0 flex-wrap items-center gap-2">
                      <span className="min-w-0 break-all text-sm font-medium text-white">{candidate.method} {candidate.endpoint_url}</span>
                      <span className="rounded bg-purple-500/10 px-2 py-0.5 text-xs text-purple-200">{candidate.target_type}</span>
                      {confidencePct !== null && (
                        <span className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-300">{confidencePct}%</span>
                      )}
                    </div>
                    <div className="mt-2 break-words text-xs text-gray-500">{candidate.evidence.slice(0, 3).join(' · ')}</div>
                  </button>
                )
              })}
            </div>
          )}
        </Card>
      )}

      {shouldShowCreate && (
      <div className="grid gap-6">
        <form onSubmit={handleCreate} className="space-y-4 rounded-lg border border-gray-800 bg-gray-900 p-4">
          <div className="flex items-center gap-2 text-white">
            <Plus className="h-4 w-4 text-blue-400" />
            <h2 className="text-sm font-semibold">Add Target</h2>
          </div>

          <div className="grid gap-3 md:grid-cols-2">
            <label className="grid gap-1 text-sm text-gray-300">
              Name
              <input value={name} onChange={(e) => setName(e.target.value)} className={inputClass} placeholder="Support bot staging" />
            </label>
            <label className="grid gap-1 text-sm text-gray-300">
              Target surface
              <select value={targetType} onChange={(e) => applyTargetType(e.target.value as AITargetType)} className={inputClass}>
                {TARGET_TYPES.map((type) => (
                  <option key={type.value} value={type.value}>{type.label}</option>
                ))}
              </select>
            </label>
          </div>

          <label className="grid gap-1 text-sm text-gray-300">
            Endpoint URL
            <input
              value={endpointUrl}
              onChange={(e) => setEndpointUrl(e.target.value)}
              onBlur={() => validateField('endpointUrl')}
              aria-invalid={fieldErrors.endpointUrl ? true : undefined}
              className={fieldErrors.endpointUrl ? invalidFieldClass(inputClass) : inputClass}
              placeholder="https://example.com/api/chat"
              required
            />
            {fieldErrors.endpointUrl && <span role="alert" className="text-sm text-red-400">{fieldErrors.endpointUrl}</span>}
          </label>

          <div className="grid gap-3 md:grid-cols-3">
            <label className="grid gap-1 text-sm text-gray-300">
              Method
              <select value={method} onChange={(e) => setMethod(e.target.value as typeof method)} className={inputClass}>
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="PATCH">PATCH</option>
              </select>
            </label>
            <label className="grid gap-1 text-sm text-gray-300">
              Response path
              <input value={responsePath} onChange={(e) => setResponsePath(e.target.value)} className={inputClass} placeholder="$.answer" />
            </label>
            <label className="grid gap-1 text-sm text-gray-300">
              Streaming
              <select value={streamingMode} onChange={(e) => setStreamingMode(e.target.value as 'json' | 'sse')} className={inputClass}>
                <option value="json">JSON</option>
                <option value="sse">SSE</option>
              </select>
            </label>
          </div>

          <div className="grid gap-3 md:grid-cols-3">
            <label className="grid gap-1 text-sm text-gray-300">
              Auth
              <select value={authKind} onChange={(e) => setAuthKind(e.target.value as AIAuthKind)} className={inputClass}>
                {AUTH_KINDS.map((kind) => (
                  <option key={kind.value} value={kind.value}>{kind.label}</option>
                ))}
              </select>
            </label>
            {(authKind === 'custom_header' || authKind === 'query_param' || authKind === 'api_key_header') && (
              <label className="grid gap-1 text-sm text-gray-300">
                {authKind === 'query_param' ? 'Parameter name' : 'Header name'}
                <input value={headerName} onChange={(e) => setHeaderName(e.target.value)} className={inputClass} placeholder={authKind === 'query_param' ? 'api_key' : 'X-API-Key'} />
              </label>
            )}
            {authKind !== 'none' && (
              <label className="grid gap-1 text-sm text-gray-300 md:col-span-2">
                {authKind === 'multi_header' ? 'Header pairs' : authKind === 'cookie' ? 'Cookie string' : 'Secret'}
                {authKind === 'multi_header' || authKind === 'cookie' ? (
                  <textarea value={secret} onChange={(e) => setSecret(e.target.value)} className={textareaClass} rows={authKind === 'multi_header' ? 4 : 2} placeholder={authKind === 'multi_header' ? 'Authorization: Bearer token\nX-Org-Id: org_123' : 'session=abc; csrf=xyz'} />
                ) : (
                  <input type="password" value={secret} onChange={(e) => setSecret(e.target.value)} className={inputClass} placeholder={authKind === 'basic_auth' ? 'username:password' : 'secret value'} />
                )}
              </label>
            )}
          </div>

          <div className="rounded-lg border border-gray-800 bg-gray-950/40">
            <button
              type="button"
              onClick={() => setShowAdvancedTarget((value) => !value)}
              className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left text-sm text-gray-200 hover:bg-gray-800/60"
            >
              <span>Advanced request, budgets, and deployment metadata</span>
              <span className="text-xs text-blue-300">{showAdvancedTarget ? 'Hide' : 'Show'}</span>
            </button>

            {showAdvancedTarget && (
              <div className="space-y-4 border-t border-gray-800 p-4">
                <div className="grid gap-3 md:grid-cols-2">
                  <label className="grid gap-1 text-sm text-gray-300">
                    Request template JSON
                    <textarea
                      value={requestTemplate}
                      onChange={(e) => setRequestTemplate(e.target.value)}
                      onBlur={() => validateField('requestTemplate')}
                      aria-invalid={fieldErrors.requestTemplate ? true : undefined}
                      className={fieldErrors.requestTemplate ? invalidFieldClass(textareaClass) : textareaClass}
                      rows={7}
                    />
                    {fieldErrors.requestTemplate && <span role="alert" className="text-sm text-red-400">{fieldErrors.requestTemplate}</span>}
                    {!fieldErrors.requestTemplate && promptWarning && (
                      <span className="text-sm text-amber-400">Chat API targets usually need {'{{prompt}}'} in the request template so probes can inject prompts.</span>
                    )}
                  </label>
                  <label className="grid gap-1 text-sm text-gray-300">
                    Headers template JSON
                    <textarea
                      value={headersTemplate}
                      onChange={(e) => setHeadersTemplate(e.target.value)}
                      onBlur={() => validateField('headersTemplate')}
                      aria-invalid={fieldErrors.headersTemplate ? true : undefined}
                      className={fieldErrors.headersTemplate ? invalidFieldClass(textareaClass) : textareaClass}
                      rows={7}
                    />
                    {fieldErrors.headersTemplate && <span role="alert" className="text-sm text-red-400">{fieldErrors.headersTemplate}</span>}
                  </label>
                </div>

                <div className="grid gap-3 md:grid-cols-3">
                  <label className="grid gap-1 text-sm text-gray-300">
                    Rate limit RPS
                    <input value={rateLimitRps} onChange={(e) => setRateLimitRps(e.target.value)} className={inputClass} inputMode="numeric" />
                  </label>
                  <label className="grid gap-1 text-sm text-gray-300">
                    Request budget
                    <input value={requestBudget} onChange={(e) => setRequestBudget(e.target.value)} className={inputClass} inputMode="numeric" />
                  </label>
                  <label className="grid gap-1 text-sm text-gray-300">
                    Token budget
                    <input value={tokenBudget} onChange={(e) => setTokenBudget(e.target.value)} className={inputClass} inputMode="numeric" placeholder="optional" />
                  </label>
                </div>

                <label className="grid gap-1 text-sm text-gray-300">
                  Canary tokens
                  <textarea value={canaryTokens} onChange={(e) => setCanaryTokens(e.target.value)} className={textareaClass} rows={3} placeholder="One per line or comma-separated" />
                </label>

                <label className="grid gap-1 text-sm text-gray-300">
                  Control metadata JSON
                  <textarea
                    value={controlMetadata}
                    onChange={(e) => setControlMetadata(e.target.value)}
                    onBlur={() => validateField('controlMetadata')}
                    aria-invalid={fieldErrors.controlMetadata ? true : undefined}
                    className={fieldErrors.controlMetadata ? invalidFieldClass(textareaClass) : textareaClass}
                    rows={5}
                    placeholder='{"asset_owner":"security","risk_tier":"high","data_classification":"restricted","retrieval_acl_matrix":"tenant-user-doc","tool_inventory":["refund"],"enforce_ai_control_baseline":true}'
                  />
                  {fieldErrors.controlMetadata && <span role="alert" className="text-sm text-red-400">{fieldErrors.controlMetadata}</span>}
                </label>

                <label className="flex items-center gap-2 text-sm text-gray-300">
                  <input type="checkbox" checked={productionMode} onChange={(e) => setProductionMode(e.target.checked)} className="h-4 w-4 rounded border-gray-700 bg-gray-800" />
                  Production target
                </label>
              </div>
            )}
          </div>

          <div className="grid gap-2 sm:grid-cols-[1fr_auto]">
            <Button type="submit" disabled={saving || hasFieldErrors} className="w-full">
              {saving ? <RefreshCw className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Plus className="h-4 w-4" aria-hidden="true" />}
              Save AI Target
            </Button>
            <button type="button" onClick={copyCurrentPayload} className="inline-flex items-center justify-center gap-2 rounded-lg border border-gray-700 px-4 py-2 text-sm text-gray-300 hover:bg-gray-800">
              <Clipboard className="h-4 w-4" aria-hidden="true" />
              {copied === 'target-payload' ? 'Copied' : 'Copy payload'}
            </button>
          </div>
          {hasFieldErrors && (
            <p role="alert" className="text-sm text-red-400">Fix the highlighted fields above to save this target.</p>
          )}
        </form>

        {scenario && (
          <Card className="p-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <div className="flex items-center gap-2 text-white">
                  <ShieldCheck className="h-4 w-4 text-emerald-300" />
                  <h2 className="text-sm font-semibold">Starter Templates</h2>
                </div>
                <p className="mt-1 max-w-3xl text-sm text-gray-400">
                  Optional quick-fill templates for common RAG, agent, and MCP target shapes. Replace the example URLs before saving.
                </p>
              </div>
            </div>

            <div className="mt-4 grid gap-3 lg:grid-cols-[1fr_0.9fr]">
              <div className="grid gap-2 sm:grid-cols-3">
                {(scenario.target_templates || []).map((template) => (
                  <button
                    key={template.key}
                    type="button"
                    onClick={() => applyScenarioTemplate(template)}
                    className="rounded-lg border border-gray-700 bg-gray-950 p-3 text-left hover:border-blue-500/60 hover:bg-gray-800"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-sm font-medium text-white">{template.name}</span>
                      <Wand2 className="h-4 w-4 text-blue-300" />
                    </div>
                    <div className="mt-2 text-xs text-gray-500">{template.recommended_scan?.probe_pack || 'custom'} · {template.recommended_scan?.scan_profile || 'standard'}</div>
                  </button>
                ))}
              </div>

              <div className="rounded-lg border border-gray-800 bg-gray-950 p-3">
                <div className="mb-2 flex items-center justify-between gap-3">
                  <div className="text-sm font-medium text-gray-200">Form readiness</div>
                  {formControlSummary && (
                    <span className={`rounded px-2 py-1 text-xs ${formControlSummary.missing.length ? 'bg-yellow-900/50 text-yellow-200' : 'bg-green-900/50 text-green-200'}`}>
                      {formControlSummary.present}/{formControlSummary.required}
                    </span>
                  )}
                </div>
                <div className="grid gap-1 sm:grid-cols-2">
                  {(formControlSummary?.missing.length ? formControlSummary.missing : applicableControls(targetType, scenario.readiness_controls || []).slice(0, 6)).slice(0, 6).map((control) => {
                    const present = hasMetadataKey(formMetadata, control.keys)
                    return (
                      <div key={control.id} className="flex min-w-0 items-center gap-2 text-xs">
                        <CheckCircle2 className={`h-3.5 w-3.5 shrink-0 ${present ? 'text-green-300' : 'text-gray-600'}`} />
                        <span className={`min-w-0 break-words ${present ? 'text-gray-300' : 'text-yellow-200'}`}>{control.label}</span>
                      </div>
                    )
                  })}
                </div>
              </div>
            </div>
          </Card>
        )}
      </div>
      )}

        <div className="space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold text-gray-300">Targets</h2>
              <p className="mt-1 text-xs text-gray-500">Saved AI surfaces ready for probe packs and deployment checks.</p>
            </div>
            <div className="flex flex-wrap items-center gap-3">
              {aiSettings?.demo_mode_enabled && (
                <label className="inline-flex items-center gap-2 text-xs text-gray-400">
                  <input
                    type="checkbox"
                    checked={showDemoTargets}
                    onChange={(event) => setShowDemoTargets(event.target.checked)}
                    className="h-4 w-4 rounded border-gray-700 bg-gray-800"
                  />
                  Show demo/lab targets
                </label>
              )}
              <button onClick={loadTargets} disabled={loading} className="inline-flex items-center gap-2 rounded-lg border border-gray-700 px-3 py-2 text-sm text-gray-300 hover:bg-gray-800 disabled:opacity-50">
                <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
                Refresh
              </button>
            </div>
          </div>

          {hiddenCalibrationCount > 0 && !showDemoTargets && (
            <Card className="px-4 py-3 text-sm text-gray-400">
              Hidden {hiddenCalibrationCount} demo/lab target{hiddenCalibrationCount === 1 ? '' : 's'} from the normal list.
            </Card>
          )}

          {loadError ? (
            <ErrorState message={loadError} onRetry={loadTargets} />
          ) : loading && visibleTargets.length === 0 ? (
            <CardSkeleton count={3} />
          ) : visibleTargets.length === 0 && !showAddTarget ? (
            <EmptyState
              message="No AI Gate targets yet."
              hint="Add a chat, RAG, agent trace, or MCP surface to start probing."
              action={{ label: 'Add Target', onClick: () => setShowAddTarget(true) }}
            />
          ) : (
            visibleTargets.map((target) => {
              const config = runConfigs[target.id] || defaultRunConfig(target)
              const targetControlSummary = scenario
                ? controlSummary(target.target_type, target.metadata_json || {}, scenario.readiness_controls || [])
                : null
              const isDemoTarget = isCalibrationLikeTarget(target, true)
              const campaignHistory = campaignHistories[target.id]
              const campaignHistoryError = campaignHistoryErrors[target.id]
              const campaignHistoryLoading = loadingCampaignHistory === target.id
              const isControlRemediationTarget = Boolean(controlRemediationMode && targetControlSummary?.missing.length)
              return (
                <Card key={target.id} className={`p-4 ${isControlRemediationTarget ? 'border-yellow-500/50 bg-yellow-500/5' : ''}`}>
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <h3 className="font-medium text-white">{target.name}</h3>
                        <span className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-300">{TARGET_TYPES.find((type) => type.value === target.target_type)?.label || target.target_type}</span>
                        {isDemoTarget && <span className="rounded bg-emerald-500/10 px-2 py-0.5 text-xs text-emerald-300">demo</span>}
                        {target.production_mode && <span className="rounded bg-yellow-500/10 px-2 py-0.5 text-xs text-yellow-400">production</span>}
                        {isControlRemediationTarget && <span className="rounded bg-yellow-500/10 px-2 py-0.5 text-xs text-yellow-200">control gap</span>}
                      </div>
                      <div className="mt-1 break-all text-sm text-gray-500">{target.method} {target.endpoint_url}</div>
                      <div className="mt-1 text-xs text-gray-500">
                        Auth: {target.credential.auth_kind}
                        {target.credential.secret_configured ? ` (${target.credential.secret_preview || 'configured'})` : ''}
                        {targetControlSummary && (
                          <>
                            {' '}· controls: <span className={targetControlSummary.missing.length ? 'text-yellow-300' : 'text-green-300'}>{targetControlSummary.present}/{targetControlSummary.required}</span>
                          </>
                        )}
                        {target.last_scan_id && (
                          <>
                            {' '}· <Link className="text-blue-400 hover:text-blue-300" href={`/scans/${target.last_scan_id}`}>last scan</Link>
                          </>
                        )}
                      </div>
                      {targetControlSummary && targetControlSummary.missing.length > 0 && (
                        <div className="mt-2 flex flex-wrap gap-1">
                          {targetControlSummary.missing.slice(0, 4).map((control) => (
                            <span key={control.id} className="rounded bg-yellow-900/30 px-2 py-0.5 text-xs text-yellow-200">{control.label}</span>
                          ))}
                          {targetControlSummary.missing.length > 4 && (
                            <span className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-400">+{targetControlSummary.missing.length - 4}</span>
                          )}
                        </div>
                      )}
                      <div className="mt-3 grid gap-2 text-xs grid-cols-1 sm:grid-cols-2 lg:grid-cols-4">
                        <div className="min-w-0 rounded border border-gray-800 bg-gray-950 p-2">
                          <div className="text-gray-500">Endpoint</div>
                          <div className="mt-1 break-all text-gray-200">{target.method} {target.endpoint_url}</div>
                        </div>
                        <div className="min-w-0 rounded border border-gray-800 bg-gray-950 p-2">
                          <div className="text-gray-500">Prompt field</div>
                          <div className="mt-1 break-words text-gray-200">{summarizeRequestTemplate(target.request_template)}</div>
                        </div>
                        <div className="min-w-0 rounded border border-gray-800 bg-gray-950 p-2">
                          <div className="text-gray-500">Response field</div>
                          <div className="mt-1 break-all font-mono text-gray-200">{target.response_path || '$'}</div>
                        </div>
                        <div className="min-w-0 rounded border border-gray-800 bg-gray-950 p-2">
                          <div className="text-gray-500">Last scan</div>
                          <div className="mt-1 break-words text-gray-200">
                            {target.last_scan_id ? (
                              <Link className="text-blue-400 hover:text-blue-300" href={`/scans/${target.last_scan_id}`}>Open result</Link>
                            ) : (
                              'Not run'
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                    <button
                      onClick={() => setConfirmDisableTarget(target)}
                      className="inline-flex items-center gap-2 rounded-lg border border-gray-800 px-2 py-1 text-xs text-gray-500 hover:bg-gray-800 hover:text-red-400"
                      aria-label={`Disable ${target.name}`}
                      title="Disable target"
                    >
                      <Trash2 className="h-4 w-4" aria-hidden="true" />
                      Disable
                    </button>
                  </div>

                  <div className="mt-4 grid gap-3 md:grid-cols-3 lg:grid-cols-[1fr_0.8fr_0.8fr_auto_auto_auto]">
                    <label className="grid gap-1 text-xs text-gray-500">
                      Probe pack
                      <select value={config.probe_pack} onChange={(e) => updateRunConfig(target.id, { probe_pack: e.target.value as AIProbePack })} className={inputClass}>
                        {PROBE_PACKS.map((pack) => <option key={pack.value} value={pack.value}>{pack.label}</option>)}
                      </select>
                    </label>
                    <label className="grid gap-1 text-xs text-gray-500">
                      Depth
                      <select value={config.scan_profile} onChange={(e) => updateRunConfig(target.id, { scan_profile: e.target.value as AIScanProfile })} className={inputClass}>
                        {SCAN_PROFILES.map((profile) => <option key={profile.value} value={profile.value}>{profile.label}</option>)}
                      </select>
                    </label>
                    <label className="grid gap-1 text-xs text-gray-500">
                      Environment
                      <select value={config.environment} onChange={(e) => updateRunConfig(target.id, { environment: e.target.value as AIEnvironment })} className={inputClass}>
                        {ENVIRONMENTS.map((env) => <option key={env.value} value={env.value}>{env.label}</option>)}
                      </select>
                    </label>
                    <button onClick={() => handleConnectivityTest(target)} disabled={testingTarget === target.id} className="inline-flex items-center justify-center gap-2 rounded-lg border border-gray-700 px-4 py-2 text-sm font-medium text-gray-300 hover:bg-gray-800 disabled:opacity-50">
                      {testingTarget === target.id ? <RefreshCw className="h-4 w-4 animate-spin" /> : <CheckCircle2 className="h-4 w-4" />}
                      Test Connection
                    </button>
                    {target.target_type === 'mcp_trace' && (
                      <button onClick={() => handleMCPReadiness(target)} disabled={testingMCP === target.id} className="inline-flex items-center justify-center gap-2 rounded-lg border border-purple-500/30 px-4 py-2 text-sm font-medium text-purple-100 hover:bg-purple-500/10 disabled:opacity-50">
                        {testingMCP === target.id ? <RefreshCw className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
                        MCP
                      </button>
                    )}
                    <button onClick={() => handleRun(target)} disabled={scanning === target.id} className="inline-flex items-center justify-center gap-2 rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-700 disabled:opacity-50">
                      {scanning === target.id ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
                      {getRunButtonLabel(config)}
                    </button>
                  </div>
                  {connectivityResults[target.id] && (
                    <div className={`mt-3 rounded-lg border p-3 text-xs ${
                      connectivityResults[target.id].ok
                        ? 'border-emerald-500/20 bg-emerald-500/10 text-emerald-200'
                        : 'border-yellow-500/20 bg-yellow-500/10 text-yellow-100'
                    }`}>
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-medium">{connectivityResults[target.id].ok ? 'Connectivity passed' : 'Connectivity issue'}</span>
                        {connectivityResults[target.id].status_code && <span>HTTP {connectivityResults[target.id].status_code}</span>}
                        {connectivityResults[target.id].latency_ms !== undefined && <span>{connectivityResults[target.id].latency_ms} ms</span>}
                        {connectivityResults[target.id].stage && <span>stage: {connectivityResults[target.id].stage}</span>}
                      </div>
                      {connectivityResults[target.id].error && (
                        <p className="mt-2 break-words text-yellow-100">{connectivityResults[target.id].error}</p>
                      )}
                      {connectivityResults[target.id].response?.extracted_text && (
                        <pre className="mt-2 max-h-28 overflow-auto whitespace-pre-wrap rounded bg-gray-950/50 p-2 text-gray-200">
                          {connectivityResults[target.id].response?.extracted_text}
                        </pre>
                      )}
                    </div>
                  )}
                  {mcpReadinessResults[target.id] && (
                    <div className={`mt-3 rounded-lg border p-3 text-xs ${
                      mcpReadinessResults[target.id].ok
                        ? 'border-emerald-500/20 bg-emerald-500/10 text-emerald-200'
                        : 'border-purple-500/20 bg-purple-500/10 text-purple-100'
                    }`}>
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-medium">{mcpReadinessResults[target.id].ok ? 'MCP readiness passed' : 'MCP readiness warnings'}</span>
                        {mcpReadinessResults[target.id].summary && (
                          <span>{mcpReadinessResults[target.id].summary?.passed}/{mcpReadinessResults[target.id].summary?.checks} checks</span>
                        )}
                      </div>
                      <div className="mt-2 grid gap-1 sm:grid-cols-2">
                        {(mcpReadinessResults[target.id].checks || []).slice(0, 8).map((check) => (
                          <div key={check.id} className="flex min-w-0 items-center gap-2">
                            <CheckCircle2 className={`h-3.5 w-3.5 shrink-0 ${check.status === 'pass' ? 'text-emerald-300' : 'text-yellow-300'}`} />
                            <span className="min-w-0 break-words text-gray-200">{check.label}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  <div className="mt-3 rounded-lg border border-gray-800 bg-gray-950/40 p-3">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div>
                        <div className="text-sm font-medium text-gray-200">Campaign history</div>
                        <p className="mt-1 text-xs text-gray-500">Recent AI Gate runs for this target across probe packs, profiles, and environments.</p>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {campaignHistory && (
                          <a
                            href={`${API_URL}/ai/targets/${target.id}/campaign-history/export?limit=12`}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-2 rounded-lg border border-gray-700 px-3 py-2 text-xs text-gray-300 hover:bg-gray-800"
                          >
                            <Download className="h-3.5 w-3.5" aria-hidden="true" />
                            Export history
                          </a>
                        )}
                        <button
                          type="button"
                          onClick={() => loadTargetCampaignHistory(target.id)}
                          disabled={campaignHistoryLoading}
                          className="inline-flex items-center gap-2 rounded-lg border border-gray-700 px-3 py-2 text-xs text-gray-300 hover:bg-gray-800 disabled:opacity-50"
                        >
                          <RefreshCw className={`h-3.5 w-3.5 ${campaignHistoryLoading ? 'animate-spin' : ''}`} />
                          {campaignHistory ? 'Refresh history' : 'Load history'}
                        </button>
                      </div>
                    </div>
                    {campaignHistoryError && (
                      <p role="alert" className="mt-2 break-words text-xs text-amber-300">{campaignHistoryError}</p>
                    )}
                    {campaignHistory && (
                      <div className="mt-3 space-y-3">
                        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
                          <div className="rounded border border-gray-800 bg-gray-950 p-2 text-xs">
                            <div className="text-gray-500">Runs</div>
                            <div className="mt-1 text-lg font-semibold text-white">{campaignHistory.summary.total_runs}</div>
                          </div>
                          <div className="rounded border border-gray-800 bg-gray-950 p-2 text-xs">
                            <div className="text-gray-500">Contexts</div>
                            <div className="mt-1 text-lg font-semibold text-white">{campaignHistory.summary.contexts}</div>
                          </div>
                          <div className="rounded border border-gray-800 bg-gray-950 p-2 text-xs">
                            <div className="text-gray-500">Blocked</div>
                            <div className="mt-1 text-lg font-semibold text-red-300">{campaignHistory.summary.blocked_runs}</div>
                          </div>
                          <div className="rounded border border-gray-800 bg-gray-950 p-2 text-xs">
                            <div className="text-gray-500">Errored</div>
                            <div className="mt-1 text-lg font-semibold text-yellow-200">{campaignHistory.summary.errored_runs}</div>
                          </div>
                          <div className="rounded border border-gray-800 bg-gray-950 p-2 text-xs">
                            <div className="text-gray-500">Budget stopped</div>
                            <div className="mt-1 text-lg font-semibold text-blue-200">{campaignHistory.summary.budget_stopped_runs}</div>
                          </div>
                        </div>
                        {campaignHistory.readiness_trends?.overall && (
                          <div className="rounded border border-gray-800 bg-gray-950 p-2 text-xs">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="text-gray-500">Readiness trend</span>
                              <span className="rounded bg-gray-800 px-2 py-0.5 text-gray-200">{formatCampaignLabel(campaignHistory.readiness_trends.overall.state)}</span>
                              {campaignHistory.readiness_trends.overall.coverage_delta !== null && campaignHistory.readiness_trends.overall.coverage_delta !== undefined && (
                                <span className="text-gray-400">coverage {formatDelta(campaignHistory.readiness_trends.overall.coverage_delta)}</span>
                              )}
                              {campaignHistory.readiness_trends.overall.findings_delta !== null && campaignHistory.readiness_trends.overall.findings_delta !== undefined && (
                                <span className="text-gray-400">findings {formatDelta(campaignHistory.readiness_trends.overall.findings_delta)}</span>
                              )}
                              {campaignHistory.readiness_trends.overall.errors_delta !== null && campaignHistory.readiness_trends.overall.errors_delta !== undefined && (
                                <span className="text-gray-400">errors {formatDelta(campaignHistory.readiness_trends.overall.errors_delta)}</span>
                              )}
                            </div>
                          </div>
                        )}
                        <CampaignTrendBars points={campaignHistory.trend_series?.overall} title="Readiness Over Time" />

                        {campaignHistory.contexts.length > 0 && (
                          <div className="grid gap-2 lg:grid-cols-2">
                            {campaignHistory.contexts.slice(0, 4).map((context) => (
                              <div
                                key={`${context.probe_pack || 'pack'}-${context.scan_profile || 'profile'}-${context.environment || 'env'}`}
                                className="rounded border border-gray-800 bg-gray-950 p-2 text-xs"
                              >
                                <div className="flex flex-wrap items-center justify-between gap-2">
                                  <span className="font-medium text-gray-200">
                                    {formatCampaignLabel(context.probe_pack)} · {formatCampaignLabel(context.scan_profile)} · {formatCampaignLabel(context.environment)}
                                  </span>
                                  <span className="rounded bg-gray-800 px-2 py-0.5 text-gray-300">{context.runs_count} run{context.runs_count === 1 ? '' : 's'}</span>
                                </div>
                                {context.latest_run && (
                                  <div className="mt-2 flex flex-wrap gap-2 text-gray-400">
                                    <span className={`rounded px-2 py-0.5 ${decisionPillClass(context.latest_run.decision)}`}>{formatCampaignLabel(context.latest_run.decision)}</span>
                                    <span>{context.latest_run.findings_count} finding{context.latest_run.findings_count === 1 ? '' : 's'}</span>
                                    <span>{context.latest_run.coverage_pct}% coverage</span>
                                    {context.deltas && (
                                      <>
                                        <span>findings {formatDelta(context.deltas.findings_count)}</span>
                                        <span>errors {formatDelta(context.deltas.errors)}</span>
                                      </>
                                    )}
                                  </div>
                                )}
                                {context.readiness_trend && (
                                  <div className="mt-2 flex flex-wrap items-center gap-2 border-t border-gray-800 pt-2 text-gray-400">
                                    <span className={`rounded px-2 py-0.5 ${readinessTrendClass(context.readiness_trend.state)}`}>
                                      {formatCampaignLabel(context.readiness_trend.state)}
                                    </span>
                                    {context.readiness_trend.coverage_delta !== null && context.readiness_trend.coverage_delta !== undefined && (
                                      <span>coverage {formatDelta(context.readiness_trend.coverage_delta)}</span>
                                    )}
                                    {context.readiness_trend.findings_delta !== null && context.readiness_trend.findings_delta !== undefined && (
                                      <span>findings {formatDelta(context.readiness_trend.findings_delta)}</span>
                                    )}
                                    {context.readiness_trend.errors_delta !== null && context.readiness_trend.errors_delta !== undefined && (
                                      <span>errors {formatDelta(context.readiness_trend.errors_delta)}</span>
                                    )}
                                    {context.readiness_trend.decision_changed && (
                                      <span>decision changed</span>
                                    )}
                                  </div>
                                )}
                                <CampaignTrendBars points={context.trend_points} title="Context Trend" compact />
                              </div>
                            ))}
                          </div>
                        )}

                        {campaignHistory.runs.length > 0 ? (
                          <div className="overflow-x-auto">
                            <table className="min-w-full text-left text-xs">
                              <thead className="text-gray-500">
                                <tr>
                                  <th className="py-1 pr-3 font-medium">Completed</th>
                                  <th className="py-1 pr-3 font-medium">Campaign</th>
                                  <th className="py-1 pr-3 font-medium">Decision</th>
                                  <th className="py-1 pr-3 font-medium">Findings</th>
                                  <th className="py-1 pr-3 font-medium">Coverage</th>
                                  <th className="py-1 pr-3 font-medium">Evidence</th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-gray-800">
                                {campaignHistory.runs.slice(0, 8).map((run) => (
                                  <tr key={run.id}>
                                    <td className="py-1 pr-3 text-gray-400">{formatShortDate(run.completed_at || run.created_at)}</td>
                                    <td className="py-1 pr-3 text-gray-300">
                                      {formatCampaignLabel(run.probe_pack)} · {formatCampaignLabel(run.scan_profile)} · {formatCampaignLabel(run.environment)}
                                    </td>
                                    <td className="py-1 pr-3">
                                      <span className={`rounded px-2 py-0.5 ${decisionPillClass(run.decision)}`}>{formatCampaignLabel(run.decision)}</span>
                                    </td>
                                    <td className="py-1 pr-3 text-gray-300">{run.findings_count}</td>
                                    <td className="py-1 pr-3 text-gray-300">{run.coverage_pct}%</td>
                                    <td className="py-1 pr-3">
                                      <Link className="text-blue-400 hover:text-blue-300" href={run.ui_url || `/scans/${run.id}`}>
                                        Open scan
                                      </Link>
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        ) : (
                          <p className="text-xs text-gray-500">No completed AI Gate campaigns have been recorded for this target yet.</p>
                        )}
                      </div>
                    )}
                  </div>
                </Card>
              )
            })
          )}
        </div>

      <AISurfaceInventoryPanel />

      <Card className="p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="flex items-center gap-2 text-white">
              <Clipboard className="h-4 w-4 text-blue-300" />
              <h2 className="text-sm font-semibold">AI Red-Team Resources</h2>
            </div>
            <p className="mt-1 max-w-3xl text-sm text-gray-400">
              Generic probe catalogs, learning checkpoints, and eval seed exports for AI security practice.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            {REDTEAM_RESOURCE_LINKS.map((item) => (
              <a
                key={item.label}
                href={item.href}
                target="_blank"
                rel="noreferrer"
                className="rounded-lg border border-gray-700 px-3 py-2 text-sm text-gray-300 hover:bg-gray-800"
              >
                {item.label}
              </a>
            ))}
          </div>
        </div>
      </Card>

      {aiSettings?.demo_mode_enabled && (
        <section className="rounded-lg border border-emerald-500/20 bg-gray-900 p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <div className="flex items-center gap-2 text-emerald-100">
                <ShieldCheck className="h-4 w-4" />
                <h2 className="text-sm font-semibold">Calibration Lab</h2>
              </div>
              <p className="mt-1 max-w-3xl text-sm text-gray-400">
                Optional Honey demo scans for local practice and regression checks. Keep disabled for normal production-facing use.
              </p>
              {aiSettings.demo_honey_scanner_url && (
                <div className="mt-2 text-xs text-gray-500">
                  Docker scanner URL: {aiSettings.demo_honey_scanner_url}
                </div>
              )}
            </div>
            <button
              type="button"
              onClick={handleRunDemo}
              disabled={demoRunning}
              className="inline-flex items-center justify-center gap-2 rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-700 disabled:opacity-50"
            >
              {demoRunning ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              Run Demo Suite
            </button>
          </div>
          {demoResult && (
            <div className="mt-3 space-y-2">
              <div className="grid gap-2 md:grid-cols-2">
                {demoResult.queued.map((item) => (
                  <Link
                    key={item.scan_id}
                    href={`/scans/${item.scan_id}`}
                    className="rounded border border-emerald-500/20 bg-gray-950/50 px-3 py-2 text-sm text-emerald-100 hover:bg-gray-900"
                  >
                    <div className="font-medium">{item.name}</div>
                    <div className="mt-1 text-xs text-emerald-100/60">
                      {item.surface.toUpperCase()} · {item.expected_findings.length ? `${item.expected_findings.length} expected finding(s)` : 'safe fixture'}
                    </div>
                  </Link>
                ))}
              </div>
              {(demoResult.failed?.length || 0) > 0 && (
                <div className="rounded border border-red-500/30 bg-red-950/30 p-3 text-xs text-red-200">
                  {demoResult.failed?.map((item) => (
                    <div key={item.scenario_id} className="break-words">
                      {item.scenario_id}: {item.error}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </section>
      )}

      <ConfirmDialog
        open={confirmDisableTarget !== null}
        title={confirmDisableTarget ? `Disable ${confirmDisableTarget.name}?` : 'Disable target?'}
        message="The target will be removed from the active list."
        confirmLabel="Disable"
        danger
        busy={disabling}
        onConfirm={handleDisableConfirmed}
        onCancel={() => {
          if (!disabling) setConfirmDisableTarget(null)
        }}
      />

      <ConfirmDialog
        open={confirmProductionTarget !== null}
        title="Run production scan?"
        message={
          confirmProductionTarget && confirmProductionConfig
            ? `Run ${confirmProductionConfig.probe_pack} against production target ${confirmProductionTarget.name}?`
            : undefined
        }
        confirmLabel="Run Scan"
        busy={confirmingProduction}
        onConfirm={async () => {
          const target = confirmProductionTarget
          if (!target || confirmingProduction) return
          setConfirmingProduction(true)
          try {
            await executeRun(target)
          } finally {
            setConfirmingProduction(false)
            setConfirmProductionTarget(null)
          }
        }}
        onCancel={() => {
          if (!confirmingProduction) setConfirmProductionTarget(null)
        }}
      />
    </div>
  )
}
