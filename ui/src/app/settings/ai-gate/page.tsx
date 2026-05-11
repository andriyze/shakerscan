'use client'

import { useEffect, useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { Bot, CheckCircle2, Clipboard, Play, Plus, RefreshCw, ShieldCheck, Trash2, Wand2 } from 'lucide-react'
import {
  createAITarget,
  deleteAITarget,
  getAITestScenarios,
  getAITargets,
  scanAITarget,
  type AITestReadinessControl,
  type AITestScenario,
  type AITestTargetTemplate,
  type AIAuthKind,
  type AIEnvironment,
  type AIProbePack,
  type AIScanProfile,
  type AITarget,
  type AITargetPayload,
  type AITargetType,
} from '@/lib/api'

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
  { value: 'smoke', label: 'Smoke' },
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
  'w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none'
const textareaClass =
  'w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 font-mono text-xs text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none'

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

function defaultRunConfig(target: AITarget): RunConfig {
  const typeDefault = TARGET_TYPES.find((type) => type.value === target.target_type)
  return {
    probe_pack: typeDefault?.probePack || 'shaker-ai-smoke',
    scan_profile: target.target_type === 'mcp_trace' ? 'smoke' : 'standard',
    environment: target.production_mode ? 'production' : 'preview',
  }
}

export default function AIGateSettingsPage() {
  const router = useRouter()
  const initialType = TARGET_TYPES[0]
  const [targets, setTargets] = useState<AITarget[]>([])
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [scanning, setScanning] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const [runConfigs, setRunConfigs] = useState<Record<string, RunConfig>>({})
  const [scenario, setScenario] = useState<AITestScenario | null>(null)
  const [copied, setCopied] = useState<string | null>(null)

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

  async function loadTargets() {
    setLoading(true)
    try {
      const payload = await getAITargets({ includeInactive: false })
      setTargets(payload.targets)
      setRunConfigs((prev) => {
        const next = { ...prev }
        for (const target of payload.targets) {
          if (!next[target.id]) next[target.id] = defaultRunConfig(target)
        }
        return next
      })
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load AI targets')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadTargets()
  }, [])

  useEffect(() => {
    getAITestScenarios()
      .then((payload) => {
        setScenario(payload.scenarios.find((item) => item.id === 'secure-rag-agent') || null)
      })
      .catch(() => {
        setScenario(null)
      })
  }, [])

  function applyTargetType(nextType: AITargetType) {
    const definition = TARGET_TYPES.find((type) => type.value === nextType) || TARGET_TYPES[0]
    setTargetType(nextType)
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
    applyTargetType('api_chat')
  }

  function applyScenarioTemplate(template: AITestTargetTemplate) {
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
  }

  async function copyCurrentPayload() {
    try {
      await navigator.clipboard.writeText(jsonText(buildPayload()))
      setCopied('target-payload')
      setTimeout(() => setCopied(null), 1500)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to copy payload')
    }
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
    setSaving(true)
    setError(null)
    setMessage(null)
    try {
      const payload = buildPayload()
      const result = await createAITarget(payload)
      setMessage(`Saved ${result.target.name}.`)
      resetForm()
      await loadTargets()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save AI target')
    } finally {
      setSaving(false)
    }
  }

  async function handleDelete(target: AITarget) {
    if (!confirm(`Disable ${target.name}?`)) return
    setError(null)
    try {
      await deleteAITarget(target.id)
      setMessage(`${target.name} disabled.`)
      await loadTargets()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to disable AI target')
    }
  }

  async function handleRun(target: AITarget) {
    const config = runConfigs[target.id] || defaultRunConfig(target)
    if (target.production_mode && !confirm(`Run ${config.probe_pack} against production target ${target.name}?`)) {
      return
    }
    setScanning(target.id)
    setError(null)
    try {
      const result = await scanAITarget(target.id, {
        ...config,
        confirm_production: target.production_mode,
      })
      router.push(`/scans/${result.scan_id}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to queue AI Gate scan')
    } finally {
      setScanning(null)
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
        <Link href="/settings" className="rounded-lg border border-gray-700 px-3 py-2 text-sm text-gray-300 hover:bg-gray-800">
          Settings
        </Link>
      </div>

      {error && <div className="rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-sm text-red-400">{error}</div>}
      {message && <div className="rounded-lg border border-green-500/20 bg-green-500/10 p-3 text-sm text-green-400">{message}</div>}

      {scenario && (
        <section className="rounded-lg border border-gray-800 bg-gray-900 p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <div className="flex items-center gap-2 text-white">
                <ShieldCheck className="h-4 w-4 text-emerald-300" />
                <h2 className="text-sm font-semibold">{scenario.title}</h2>
              </div>
              <p className="mt-1 max-w-3xl text-sm text-gray-400">{scenario.summary}</p>
            </div>
            {scenario.honey_contract?.registry_url && (
              <a href={scenario.honey_contract.registry_url} target="_blank" rel="noreferrer" className="rounded-lg border border-gray-700 px-3 py-2 text-sm text-gray-300 hover:bg-gray-800">
                Honey registry
              </a>
            )}
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
                <div className="text-sm font-medium text-gray-200">Current metadata</div>
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
                      <span className={present ? 'truncate text-gray-300' : 'truncate text-yellow-200'}>{control.label}</span>
                    </div>
                  )
                })}
              </div>
            </div>
          </div>
        </section>
      )}

      <div className="grid gap-6 xl:grid-cols-[0.95fr_1.05fr]">
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
            <input value={endpointUrl} onChange={(e) => setEndpointUrl(e.target.value)} className={inputClass} placeholder="https://example.com/api/chat" required />
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

          <div className="grid gap-3 md:grid-cols-2">
            <label className="grid gap-1 text-sm text-gray-300">
              Request template JSON
              <textarea value={requestTemplate} onChange={(e) => setRequestTemplate(e.target.value)} className={textareaClass} rows={7} />
            </label>
            <label className="grid gap-1 text-sm text-gray-300">
              Headers template JSON
              <textarea value={headersTemplate} onChange={(e) => setHeadersTemplate(e.target.value)} className={textareaClass} rows={7} />
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
              className={textareaClass}
              rows={5}
              placeholder='{"asset_owner":"security","risk_tier":"high","data_classification":"restricted","retrieval_acl_matrix":"tenant-user-doc","tool_inventory":["refund"],"enforce_ai_control_baseline":true}'
            />
          </label>

          <label className="flex items-center gap-2 text-sm text-gray-300">
            <input type="checkbox" checked={productionMode} onChange={(e) => setProductionMode(e.target.checked)} className="h-4 w-4 rounded border-gray-700 bg-gray-800" />
            Production target
          </label>

          <div className="grid gap-2 sm:grid-cols-[1fr_auto]">
            <button type="submit" disabled={saving} className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50">
              {saving ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
              Save AI Target
            </button>
            <button type="button" onClick={copyCurrentPayload} className="inline-flex items-center justify-center gap-2 rounded-lg border border-gray-700 px-4 py-2 text-sm text-gray-300 hover:bg-gray-800">
              <Clipboard className="h-4 w-4" />
              {copied === 'target-payload' ? 'Copied' : 'Copy payload'}
            </button>
          </div>
        </form>

        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-gray-300">Targets</h2>
            <button onClick={loadTargets} disabled={loading} className="inline-flex items-center gap-2 rounded-lg border border-gray-700 px-3 py-2 text-sm text-gray-300 hover:bg-gray-800 disabled:opacity-50">
              <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </button>
          </div>

          {targets.length === 0 && !loading ? (
            <div className="rounded-lg border border-gray-800 bg-gray-900 p-6 text-center text-sm text-gray-500">No AI Gate targets yet.</div>
          ) : (
            targets.map((target) => {
              const config = runConfigs[target.id] || defaultRunConfig(target)
              const targetControlSummary = scenario
                ? controlSummary(target.target_type, target.metadata_json || {}, scenario.readiness_controls || [])
                : null
              return (
                <div key={target.id} className="rounded-lg border border-gray-800 bg-gray-900 p-4">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <h3 className="font-medium text-white">{target.name}</h3>
                        <span className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-300">{TARGET_TYPES.find((type) => type.value === target.target_type)?.label || target.target_type}</span>
                        {target.production_mode && <span className="rounded bg-yellow-500/10 px-2 py-0.5 text-xs text-yellow-400">production</span>}
                      </div>
                      <div className="mt-1 truncate text-sm text-gray-500">{target.method} {target.endpoint_url}</div>
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
                    </div>
                    <button onClick={() => handleDelete(target)} className="rounded-lg p-2 text-gray-500 hover:bg-gray-800 hover:text-red-400" title="Disable target">
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>

                  <div className="mt-4 grid gap-3 md:grid-cols-[1fr_0.8fr_0.8fr_auto]">
                    <select value={config.probe_pack} onChange={(e) => updateRunConfig(target.id, { probe_pack: e.target.value as AIProbePack })} className={inputClass}>
                      {PROBE_PACKS.map((pack) => <option key={pack.value} value={pack.value}>{pack.label}</option>)}
                    </select>
                    <select value={config.scan_profile} onChange={(e) => updateRunConfig(target.id, { scan_profile: e.target.value as AIScanProfile })} className={inputClass}>
                      {SCAN_PROFILES.map((profile) => <option key={profile.value} value={profile.value}>{profile.label}</option>)}
                    </select>
                    <select value={config.environment} onChange={(e) => updateRunConfig(target.id, { environment: e.target.value as AIEnvironment })} className={inputClass}>
                      {ENVIRONMENTS.map((env) => <option key={env.value} value={env.value}>{env.label}</option>)}
                    </select>
                    <button onClick={() => handleRun(target)} disabled={scanning === target.id} className="inline-flex items-center justify-center gap-2 rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-700 disabled:opacity-50">
                      {scanning === target.id ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
                      Run
                    </button>
                  </div>
                </div>
              )
            })
          )}
        </div>
      </div>
    </div>
  )
}
