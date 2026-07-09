'use client'

import Link from 'next/link'
import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  captureInteractiveScreenshot,
  createTargetPrincipal,
  createInteractiveSessionFinding,
  deactivateTargetPrincipal,
  deleteTargetPrincipalExpectation,
  endInteractiveSession,
  getInteractiveSession,
  getTargetPrincipalMatrix,
  listInteractiveSessions,
  runInteractiveAction,
  startInteractiveSession,
  testInteractiveEndpoint,
  updateTargetPrincipal,
  upsertTargetPrincipalExpectation,
  type InteractiveEndpointTestResult,
  type InteractiveSessionState,
  type InteractiveSessionSummary,
  type TargetPrincipalMatrixResponse,
} from '@/lib/api'
import { SEVERITY_LEVELS } from '@/lib/constants'
import { Badge, Button, Card, ErrorState, useToast } from '@/components/ui'
import {
  buildPrincipalProfilePayload,
  emptyPrincipalProfileDraft,
  type PrincipalProfileDraft,
} from '@/lib/principalProfile'
import {
  buildPrincipalExpectationPayload,
  emptyPrincipalExpectationDraft,
  type PrincipalExpectationDraft,
} from '@/lib/principalExpectation'

type UserKey = 'user1' | 'user2'

type AuthFormState = {
  token: string
  authHeader: string
  cookies: string
}

type FindingFormState = {
  title: string
  severity: typeof SEVERITY_LEVELS[number]
  description: string
  category: string
  cwe: string
  url: string
  evidence: string
  request: string
  response: string
  remediation: string
  notes: string
}

const REQUEST_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']

const OUTLINE_BUTTON_CLASSES =
  'rounded-lg border border-gray-700 px-4 py-2 text-sm text-gray-300 hover:border-gray-600 disabled:cursor-not-allowed disabled:opacity-60 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500'

function parseJsonInput(value: string): Record<string, unknown> | undefined {
  if (!value.trim()) return undefined
  const parsed = JSON.parse(value)
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Request body must be a JSON object')
  }
  return parsed as Record<string, unknown>
}

function stringifyPretty(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return String(value)
  }
}

function getOriginFromUrl(url: string): string {
  try {
    return new URL(url).origin
  } catch {
    return url
  }
}

export default function InteractiveSessionPage() {
  const toast = useToast()
  const [target, setTarget] = useState('')
  const [sessionInput, setSessionInput] = useState('')
  const [session, setSession] = useState<InteractiveSessionState | null>(null)
  const [activeSessions, setActiveSessions] = useState<InteractiveSessionSummary[]>([])
  const [sessionsError, setSessionsError] = useState<string | null>(null)
  const [targetId, setTargetId] = useState('')
  const [principalMatrix, setPrincipalMatrix] = useState<TargetPrincipalMatrixResponse | null>(null)
  const [principalMatrixError, setPrincipalMatrixError] = useState<string | null>(null)
  const [principalDrafts, setPrincipalDrafts] = useState<Record<UserKey, PrincipalProfileDraft>>({
    user1: emptyPrincipalProfileDraft(),
    user2: emptyPrincipalProfileDraft(),
  })
  const [principalBusy, setPrincipalBusy] = useState<UserKey | null>(null)
  const [expectationDraft, setExpectationDraft] = useState<PrincipalExpectationDraft>(emptyPrincipalExpectationDraft)
  const [expectationBusy, setExpectationBusy] = useState<string | null>(null)

  const loadPrincipalMatrix = useCallback(async (id: string) => {
    if (!id) return
    try {
      const matrix = await getTargetPrincipalMatrix(id, 100)
      setPrincipalMatrix(matrix)
      setPrincipalMatrixError(null)
    } catch (err) {
      setPrincipalMatrix(null)
      setPrincipalMatrixError(err instanceof Error ? err.message : 'Failed to load principal matrix')
    }
  }, [])

  useEffect(() => {
    const requestedTarget = new URLSearchParams(window.location.search).get('target')
    const requestedTargetId = new URLSearchParams(window.location.search).get('target_id')
    if (requestedTarget) setTarget(requestedTarget)
    if (requestedTargetId) setTargetId(requestedTargetId)
  }, [])

  useEffect(() => {
    if (!targetId) return
    setPrincipalDrafts({ user1: emptyPrincipalProfileDraft(), user2: emptyPrincipalProfileDraft() })
    void loadPrincipalMatrix(targetId)
  }, [loadPrincipalMatrix, targetId])

  const [endpoint, setEndpoint] = useState('')
  const [method, setMethod] = useState('GET')
  const [asUser, setAsUser] = useState<UserKey>('user1')
  const [allowOutOfScope, setAllowOutOfScope] = useState(false)
  const [endpointBody, setEndpointBody] = useState('')
  const [endpointResult, setEndpointResult] = useState<InteractiveEndpointTestResult | null>(null)

  const [authForms, setAuthForms] = useState<Record<UserKey, AuthFormState>>({
    user1: { token: '', authHeader: '', cookies: '' },
    user2: { token: '', authHeader: '', cookies: '' },
  })

  const [findingForm, setFindingForm] = useState<FindingFormState>({
    title: '',
    severity: 'high',
    description: '',
    category: 'BOLA',
    cwe: 'CWE-639',
    url: '',
    evidence: '',
    request: '',
    response: '',
    remediation: '',
    notes: '',
  })

  const [createdFindingId, setCreatedFindingId] = useState<string | null>(null)
  const [screenshot, setScreenshot] = useState<{ dataUrl: string; url: string; user: string } | null>(null)
  const [screenshotUser, setScreenshotUser] = useState<string>('default')

  const [busyAction, setBusyAction] = useState<string | null>(null)

  const currentSessionId = session?.session_id || ''

  const fetchActiveSessions = useCallback(async () => {
    try {
      const data = await listInteractiveSessions()
      setActiveSessions(data.sessions || [])
      setSessionsError(null)
    } catch (err) {
      setActiveSessions([])
      setSessionsError(err instanceof Error ? err.message : 'Failed to load active sessions')
    }
  }, [])

  const loadSessionState = useCallback(async (sessionId: string, silent = false) => {
    if (!sessionId) return
    if (!silent) {
      setBusyAction('load-session')
    }
    try {
      const data = await getInteractiveSession(sessionId)
      setSession(data)
      setSessionInput(data.session_id)
      setTarget(data.target_url)
    } catch (err) {
      setSession(null)
      if (!silent) {
        toast.error(err instanceof Error ? err.message : 'Failed to load session')
      }
    } finally {
      if (!silent) {
        setBusyAction(null)
      }
    }
  }, [toast])

  useEffect(() => {
    void fetchActiveSessions()
  }, [fetchActiveSessions])

  useEffect(() => {
    if (!currentSessionId) return
    const interval = setInterval(() => {
      void loadSessionState(currentSessionId, true)
    }, 5000)
    return () => clearInterval(interval)
  }, [currentSessionId, loadSessionState])

  const userList = useMemo(() => {
    if (!session?.users) return ['default', 'user1', 'user2']
    const keys = Object.keys(session.users)
    return Array.from(new Set(['default', ...keys]))
  }, [session?.users])

  const principalsByAuthState = useMemo(() => {
    const mapped: Partial<Record<UserKey, TargetPrincipalMatrixResponse['principals'][number]>> = {}
    for (const principal of principalMatrix?.principals || []) {
      if ((principal.auth_state === 'user1' || principal.auth_state === 'user2') && !mapped[principal.auth_state]) {
        mapped[principal.auth_state] = principal
      }
    }
    return mapped
  }, [principalMatrix])

  useEffect(() => {
    if (!principalMatrix) return
    setPrincipalDrafts((current) => {
      const next = { ...current }
      for (const slot of ['user1', 'user2'] as UserKey[]) {
        const principal = principalMatrix.principals.find((item) => item.auth_state === slot)
        if (!principal) continue
        next[slot] = {
          label: principal.label,
          role: principal.role,
          tenantId: principal.tenant_id || '',
          credentialProfile: principal.credential_profile || '',
        }
      }
      return next
    })
  }, [principalMatrix])

  async function handleSavePrincipal(slot: UserKey) {
    if (!targetId) return
    const principal = principalsByAuthState[slot]
    const payload = buildPrincipalProfilePayload(slot, principalDrafts[slot], Boolean(principal))
    if (!payload.label) {
      toast.error(`${slot} label is required`)
      return
    }

    setPrincipalBusy(slot)
    try {
      if (principal) {
        await updateTargetPrincipal(targetId, principal.id, payload)
      } else {
        await createTargetPrincipal(targetId, payload)
      }
      await loadPrincipalMatrix(targetId)
      toast.success(`${slot} principal ${principal ? 'updated' : 'created'}`)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : `Failed to save ${slot} principal`)
    } finally {
      setPrincipalBusy(null)
    }
  }

  async function handleDeactivatePrincipal(slot: UserKey) {
    if (!targetId) return
    const principal = principalsByAuthState[slot]
    if (!principal || !window.confirm(`Deactivate principal ${principal.label}?`)) return

    setPrincipalBusy(slot)
    try {
      await deactivateTargetPrincipal(targetId, principal.id)
      setPrincipalDrafts((current) => ({ ...current, [slot]: emptyPrincipalProfileDraft() }))
      await loadPrincipalMatrix(targetId)
      toast.success(`${slot} principal deactivated`)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : `Failed to deactivate ${slot} principal`)
    } finally {
      setPrincipalBusy(null)
    }
  }

  async function handleSaveExpectation() {
    if (!targetId) return
    let payload
    try {
      payload = buildPrincipalExpectationPayload(expectationDraft)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Invalid expectation')
      return
    }
    if (!payload.path) {
      toast.error('Endpoint path is required')
      return
    }
    if (!payload.principal_id && !payload.principal_role) {
      toast.error('Select a principal or provide a role')
      return
    }

    setExpectationBusy('save')
    try {
      await upsertTargetPrincipalExpectation(targetId, payload)
      await loadPrincipalMatrix(targetId)
      setExpectationDraft(emptyPrincipalExpectationDraft())
      toast.success('Principal expectation saved')
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to save principal expectation')
    } finally {
      setExpectationBusy(null)
    }
  }

  async function handleDeleteExpectation(expectationId: string) {
    if (!targetId || !window.confirm('Delete this principal expectation?')) return
    setExpectationBusy(expectationId)
    try {
      await deleteTargetPrincipalExpectation(targetId, expectationId)
      await loadPrincipalMatrix(targetId)
      toast.success('Principal expectation deleted')
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to delete principal expectation')
    } finally {
      setExpectationBusy(null)
    }
  }

  async function handleStartSession() {
    if (!target.trim()) {
      toast.error('Target URL is required')
      return
    }

    setBusyAction('start-session')
    try {
      const res = await startInteractiveSession(target.trim())
      toast.success(`Session started: ${res.session_id}`)
      await loadSessionState(res.session_id)
      await fetchActiveSessions()
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to start session')
    } finally {
      setBusyAction(null)
    }
  }

  async function handleAttachSession() {
    const id = sessionInput.trim()
    if (!id) {
      toast.error('Session ID is required')
      return
    }

    await loadSessionState(id)
  }

  async function handleEndSession() {
    if (!currentSessionId) return

    setBusyAction('end-session')
    try {
      await endInteractiveSession(currentSessionId)
      toast.success(`Session closed: ${currentSessionId}`)
      setSession(null)
      setEndpointResult(null)
      setScreenshot(null)
      await fetchActiveSessions()
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to close session')
    } finally {
      setBusyAction(null)
    }
  }

  async function handleApplyAuth(user: UserKey) {
    if (!currentSessionId) {
      toast.error('Start or attach a session first')
      return
    }

    const form = authForms[user]
    if (!form.token.trim() && !form.authHeader.trim() && !form.cookies.trim()) {
      toast.error(`Provide token/auth header/cookies for ${user}`)
      return
    }

    const data: Record<string, unknown> = {}
    if (form.token.trim()) data.token = form.token.trim()
    if (form.authHeader.trim()) data.auth_header = form.authHeader.trim()
    if (form.cookies.trim()) data.cookie_string = form.cookies.trim()

    setBusyAction(`auth-${user}`)
    try {
      const res = await runInteractiveAction(currentSessionId, {
        action: 'set_auth',
        user,
        data,
      })
      toast.success(`${user} auth applied (${res.auth_method || 'unknown method'})`)
      await loadSessionState(currentSessionId, true)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : `Failed to apply auth for ${user}`)
    } finally {
      setBusyAction(null)
    }
  }

  async function handleCaptureScreenshot() {
    if (!currentSessionId) {
      toast.error('Start or attach a session first')
      return
    }

    setBusyAction('capture-screenshot')
    try {
      const res = await captureInteractiveScreenshot(currentSessionId, {
        full_page: true,
        user: screenshotUser,
      })
      setScreenshot({
        dataUrl: `data:image/png;base64,${res.data}`,
        url: res.url,
        user: res.user,
      })
      toast.success(`Screenshot captured for ${res.user}`)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to capture screenshot')
    } finally {
      setBusyAction(null)
    }
  }

  async function handleTestEndpoint() {
    if (!currentSessionId) {
      toast.error('Start or attach a session first')
      return
    }
    if (!endpoint.trim()) {
      toast.error('Endpoint is required')
      return
    }

    let parsedBody: Record<string, unknown> | undefined
    try {
      parsedBody = parseJsonInput(endpointBody)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Invalid JSON body')
      return
    }

    setBusyAction('test-endpoint')
    try {
      const result = await testInteractiveEndpoint(currentSessionId, {
        endpoint: endpoint.trim(),
        method,
        as_user: asUser,
        body: parsedBody,
        allow_out_of_scope: allowOutOfScope,
      })
      setEndpointResult(result)
      toast.success(`Endpoint tested as ${asUser}: ${result.status || 'no-status'}`)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Endpoint test failed')
    } finally {
      setBusyAction(null)
    }
  }

  function handlePrefillFindingFromEndpoint() {
    if (!endpointResult) {
      toast.error('Run an endpoint test first')
      return
    }

    let resolvedUrl = endpoint.trim()
    if (session?.target_url && endpoint.trim().startsWith('/')) {
      resolvedUrl = `${getOriginFromUrl(session.target_url)}${endpoint.trim()}`
    }

    setFindingForm(prev => ({
      ...prev,
      url: prev.url || resolvedUrl,
      evidence: prev.evidence || `Endpoint test as ${asUser}: HTTP ${endpointResult.status ?? 'unknown'}`,
      request: prev.request || `${method} ${endpoint.trim()}`,
      response: prev.response || (endpointResult.body ? endpointResult.body.slice(0, 3000) : ''),
    }))
    toast.info('Finding form prefilled from latest endpoint test')
  }

  async function handleCreateFinding() {
    if (!currentSessionId) {
      toast.error('Start or attach a session first')
      return
    }

    const title = findingForm.title.trim()
    if (!title) {
      toast.error('Finding title is required')
      return
    }

    const payload: {
      title: string
      severity: typeof SEVERITY_LEVELS[number]
      description?: string
      category?: string
      cwe?: string
      url?: string
      evidence?: string
      request?: string
      response?: string
      remediation?: string
      notes?: string
    } = {
      title,
      severity: findingForm.severity,
    }

    if (findingForm.description.trim()) payload.description = findingForm.description.trim()
    if (findingForm.category.trim()) payload.category = findingForm.category.trim()
    if (findingForm.cwe.trim()) payload.cwe = findingForm.cwe.trim()
    if (findingForm.url.trim()) payload.url = findingForm.url.trim()
    if (findingForm.evidence.trim()) payload.evidence = findingForm.evidence.trim()
    if (findingForm.request.trim()) payload.request = findingForm.request.trim()
    if (findingForm.response.trim()) payload.response = findingForm.response.trim()
    if (findingForm.remediation.trim()) payload.remediation = findingForm.remediation.trim()
    if (findingForm.notes.trim()) payload.notes = findingForm.notes.trim()

    setBusyAction('create-finding')
    try {
      const result = await createInteractiveSessionFinding(currentSessionId, payload)
      setCreatedFindingId(result.id)
      if (result.id) {
        toast.success('Finding saved', { link: { href: `/findings/${result.id}`, label: 'View finding' } })
      } else {
        toast.success('Finding saved')
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to create finding')
    } finally {
      setBusyAction(null)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Interactive Session</h1>
          <p className="mt-1 text-gray-400">
            Guided exploit validation workflow: start session, set two user auth contexts, run endpoint checks, save verified findings.
          </p>
        </div>
        <Link
          href="/findings"
          className="inline-flex items-center gap-2 rounded-lg border border-gray-700 px-3 py-2 text-sm text-gray-300 hover:border-blue-500 hover:text-blue-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
        >
          Open Findings
        </Link>
      </div>

      <Card className="p-5 space-y-4">
        <h2 className="text-lg font-semibold text-white">Step 1. Session Setup</h2>
        <div className="grid gap-4 lg:grid-cols-[2fr_1fr]">
          <div className="space-y-3">
            <label className="block text-sm text-gray-300">Target URL</label>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://target.example"
              className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
            />
            <div className="flex flex-wrap items-center gap-2">
              <Button
                onClick={handleStartSession}
                disabled={busyAction === 'start-session'}
              >
                {busyAction === 'start-session' ? 'Starting...' : 'Start Session'}
              </Button>
              <button
                type="button"
                onClick={() => {
                  if (!currentSessionId) return
                  void loadSessionState(currentSessionId)
                }}
                disabled={!currentSessionId || busyAction === 'load-session'}
                className={OUTLINE_BUTTON_CLASSES}
              >
                Refresh State
              </button>
              <button
                type="button"
                onClick={handleEndSession}
                disabled={!currentSessionId || busyAction === 'end-session'}
                className="rounded-lg border border-red-500/50 px-4 py-2 text-sm text-red-300 hover:bg-red-500/10 disabled:cursor-not-allowed disabled:opacity-60 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
              >
                {busyAction === 'end-session' ? 'Closing...' : 'Close Session'}
              </button>
            </div>

            <div className="border-t border-gray-800 pt-3 space-y-2">
              <label className="block text-sm text-gray-300">Attach Existing Session</label>
              <div className="flex gap-2">
                <input
                  value={sessionInput}
                  onChange={(e) => setSessionInput(e.target.value)}
                  placeholder="session_id"
                  className="flex-1 rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
                />
                <button
                  type="button"
                  onClick={handleAttachSession}
                  disabled={busyAction === 'load-session'}
                  className={OUTLINE_BUTTON_CLASSES}
                >
                  Attach
                </button>
              </div>
            </div>
          </div>

          <div className="rounded-lg border border-gray-800 bg-gray-950 p-3">
            <h3 className="text-sm font-medium text-gray-200">Active Sessions</h3>
            <div className="mt-2 max-h-40 space-y-2 overflow-auto pr-1">
              {sessionsError ? (
                <ErrorState message={sessionsError} onRetry={() => void fetchActiveSessions()} />
              ) : (
                <>
                  {activeSessions.length === 0 && <p className="text-xs text-gray-500">No active sessions</p>}
                  {activeSessions.map((item) => (
                    <button
                      type="button"
                      key={item.session_id}
                      onClick={() => {
                        setSessionInput(item.session_id)
                        void loadSessionState(item.session_id)
                      }}
                      className="w-full rounded-md border border-gray-800 px-2 py-2 text-left text-xs text-gray-300 hover:border-blue-500 hover:bg-blue-500/5 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                    >
                      <p className="font-mono text-[11px] text-blue-300">{item.session_id}</p>
                      <p className="truncate text-gray-400">{item.target_url}</p>
                    </button>
                  ))}
                </>
              )}
            </div>
          </div>
        </div>

        {session && (
          <div className="rounded-lg border border-gray-800 bg-gray-950 p-3 text-sm text-gray-300 grid gap-1 md:grid-cols-2">
            <p><span className="text-gray-500">Session ID:</span> <span className="font-mono text-blue-300">{session.session_id}</span></p>
            <p><span className="text-gray-500">Target:</span> {session.target_url}</p>
            <p><span className="text-gray-500">Current URL:</span> {session.current_url || '-'}</p>
            <p><span className="text-gray-500">Network Entries:</span> {session.network_log_count}</p>
            <p><span className="text-gray-500">Discovered Endpoints:</span> {session.discovered_endpoints_count}</p>
            <p><span className="text-gray-500">Last Activity:</span> {(() => {
              const d = session.last_activity ? new Date(session.last_activity) : null
              return d && !isNaN(d.getTime()) ? d.toLocaleString() : '—'
            })()}</p>
          </div>
        )}
      </Card>

      {(principalMatrix || principalMatrixError) && (
        <Card className="p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h2 className="text-lg font-semibold text-white">Principal Replay Plan</h2>
            {principalMatrix && <Badge className="bg-gray-800 text-gray-300">{principalMatrix.expectations.length} expectations</Badge>}
          </div>
          {principalMatrixError ? (
            <ErrorState message={principalMatrixError} />
          ) : principalMatrix && (
            <>
              <div className="grid gap-3 md:grid-cols-2">
                {(['user1', 'user2'] as UserKey[]).map((authState) => {
                  const principal = principalsByAuthState[authState]
                  const expectations = principalMatrix.expectations.filter((item) => item.principal_auth_state === authState || item.principal_id === principal?.id)
                  const allowCount = expectations.filter((item) => item.expected_access === 'allow').length
                  const denyCount = expectations.filter((item) => item.expected_access === 'deny').length
                  return (
                    <div key={authState} className="space-y-3 rounded-md border border-gray-800 bg-gray-950 p-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge className="bg-blue-500/15 text-blue-300">{authState}</Badge>
                        <span className="text-sm font-medium text-white">{principal?.label || 'Unassigned principal'}</span>
                        {principal?.role && <Badge className="bg-gray-800 text-gray-300">{principal.role}</Badge>}
                        {principal?.credential_configured && <Badge className="bg-green-500/15 text-green-300">credential profile</Badge>}
                      </div>
                      <div className="flex flex-wrap gap-2 text-xs text-gray-500">
                        <span>tenant: <span className="text-gray-300">{principal?.tenant_id || 'none'}</span></span>
                        <span>allow: <span className="text-green-300">{allowCount}</span></span>
                        <span>deny: <span className="text-amber-300">{denyCount}</span></span>
                      </div>
                      <div className="grid gap-2 sm:grid-cols-2">
                        <label className="space-y-1 text-xs text-gray-500">
                          <span>Label</span>
                          <input
                            value={principalDrafts[authState].label}
                            onChange={(event) => setPrincipalDrafts((current) => ({ ...current, [authState]: { ...current[authState], label: event.target.value } }))}
                            placeholder="Customer account"
                            className="w-full rounded-md border border-gray-800 bg-gray-900 px-2.5 py-2 text-sm text-white placeholder-gray-600 focus:border-blue-500 focus:outline-none"
                          />
                        </label>
                        <label className="space-y-1 text-xs text-gray-500">
                          <span>Role</span>
                          <input
                            value={principalDrafts[authState].role}
                            onChange={(event) => setPrincipalDrafts((current) => ({ ...current, [authState]: { ...current[authState], role: event.target.value } }))}
                            placeholder="user"
                            className="w-full rounded-md border border-gray-800 bg-gray-900 px-2.5 py-2 text-sm text-white placeholder-gray-600 focus:border-blue-500 focus:outline-none"
                          />
                        </label>
                        <label className="space-y-1 text-xs text-gray-500">
                          <span>Tenant ID</span>
                          <input
                            value={principalDrafts[authState].tenantId}
                            onChange={(event) => setPrincipalDrafts((current) => ({ ...current, [authState]: { ...current[authState], tenantId: event.target.value } }))}
                            placeholder="tenant-a"
                            className="w-full rounded-md border border-gray-800 bg-gray-900 px-2.5 py-2 text-sm text-white placeholder-gray-600 focus:border-blue-500 focus:outline-none"
                          />
                        </label>
                        <label className="space-y-1 text-xs text-gray-500">
                          <span>Credential profile reference</span>
                          <input
                            value={principalDrafts[authState].credentialProfile}
                            onChange={(event) => setPrincipalDrafts((current) => ({ ...current, [authState]: { ...current[authState], credentialProfile: event.target.value } }))}
                            placeholder="vault/customer-a"
                            className="w-full rounded-md border border-gray-800 bg-gray-900 px-2.5 py-2 text-sm text-white placeholder-gray-600 focus:border-blue-500 focus:outline-none"
                          />
                        </label>
                      </div>
                      <div className="flex flex-wrap items-center justify-end gap-2">
                        {principal && (
                          <Button size="sm" variant="ghost" disabled={principalBusy === authState} onClick={() => void handleDeactivatePrincipal(authState)}>
                            Deactivate
                          </Button>
                        )}
                        <Button size="sm" disabled={principalBusy === authState} onClick={() => void handleSavePrincipal(authState)}>
                          {principalBusy === authState ? 'Saving...' : principal ? 'Update principal' : 'Create principal'}
                        </Button>
                      </div>
                    </div>
                  )
                })}
              </div>
              <div className="border-t border-gray-800 pt-4">
                <div className="grid gap-3 lg:grid-cols-[auto_minmax(12rem,2fr)_minmax(11rem,1fr)_minmax(9rem,1fr)_7rem_auto]">
                  <label className="space-y-1 text-xs text-gray-500">
                    <span>Method</span>
                    <select
                      value={expectationDraft.method}
                      onChange={(event) => setExpectationDraft((current) => ({ ...current, method: event.target.value }))}
                      className="w-full rounded-md border border-gray-800 bg-gray-950 px-2.5 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
                    >
                      {REQUEST_METHODS.map((option) => <option key={option} value={option}>{option}</option>)}
                    </select>
                  </label>
                  <label className="space-y-1 text-xs text-gray-500">
                    <span>Endpoint path</span>
                    <input
                      value={expectationDraft.path}
                      onChange={(event) => setExpectationDraft((current) => ({ ...current, path: event.target.value }))}
                      placeholder="/api/orders/{id}"
                      className="w-full rounded-md border border-gray-800 bg-gray-950 px-2.5 py-2 text-sm font-mono text-white placeholder-gray-600 focus:border-blue-500 focus:outline-none"
                    />
                  </label>
                  <label className="space-y-1 text-xs text-gray-500">
                    <span>Principal</span>
                    <select
                      value={expectationDraft.principalId}
                      onChange={(event) => {
                        const selected = principalMatrix.principals.find((item) => item.id === event.target.value)
                        setExpectationDraft((current) => ({
                          ...current,
                          principalId: event.target.value,
                          principalRole: selected?.role || current.principalRole,
                          tenantId: selected?.tenant_id || current.tenantId,
                        }))
                      }}
                      className="w-full rounded-md border border-gray-800 bg-gray-950 px-2.5 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
                    >
                      <option value="">Role only</option>
                      {principalMatrix.principals.map((item) => <option key={item.id} value={item.id}>{item.auth_state}: {item.label}</option>)}
                    </select>
                  </label>
                  <label className="space-y-1 text-xs text-gray-500">
                    <span>Expected access</span>
                    <select
                      value={expectationDraft.expectedAccess}
                      onChange={(event) => setExpectationDraft((current) => ({ ...current, expectedAccess: event.target.value as PrincipalExpectationDraft['expectedAccess'] }))}
                      className="w-full rounded-md border border-gray-800 bg-gray-950 px-2.5 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
                    >
                      <option value="allow">Allow</option>
                      <option value="deny">Deny</option>
                      <option value="requires_role">Requires role</option>
                      <option value="unknown">Unknown</option>
                    </select>
                  </label>
                  <label className="space-y-1 text-xs text-gray-500">
                    <span>HTTP status</span>
                    <input
                      value={expectationDraft.expectedHttpStatus}
                      onChange={(event) => setExpectationDraft((current) => ({ ...current, expectedHttpStatus: event.target.value }))}
                      inputMode="numeric"
                      placeholder="403"
                      className="w-full rounded-md border border-gray-800 bg-gray-950 px-2.5 py-2 text-sm text-white placeholder-gray-600 focus:border-blue-500 focus:outline-none"
                    />
                  </label>
                  <div className="flex items-end">
                    <Button className="w-full" disabled={expectationBusy === 'save'} onClick={() => void handleSaveExpectation()}>
                      {expectationBusy === 'save' ? 'Saving...' : 'Save expectation'}
                    </Button>
                  </div>
                </div>
                {!expectationDraft.principalId && (
                  <label className="mt-3 block max-w-xs space-y-1 text-xs text-gray-500">
                    <span>Required role</span>
                    <input
                      value={expectationDraft.principalRole}
                      onChange={(event) => setExpectationDraft((current) => ({ ...current, principalRole: event.target.value }))}
                      placeholder="admin"
                      className="w-full rounded-md border border-gray-800 bg-gray-950 px-2.5 py-2 text-sm text-white placeholder-gray-600 focus:border-blue-500 focus:outline-none"
                    />
                  </label>
                )}
              </div>
              {principalMatrix.expectations.length > 0 && (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead><tr className="border-b border-gray-800 text-left text-xs text-gray-500"><th className="px-2 py-2">Endpoint</th><th className="px-2 py-2">Principal</th><th className="px-2 py-2">Expected</th><th className="px-2 py-2" /></tr></thead>
                    <tbody>
                      {principalMatrix.expectations.slice(0, 8).map((item) => (
                        <tr key={item.id} className="border-b border-gray-800/70">
                          <td className="px-2 py-2 font-mono text-xs text-gray-300">{item.method} {item.path}</td>
                          <td className="px-2 py-2 text-gray-400">{item.principal_label || item.principal_auth_state || item.principal_role || 'unspecified'}</td>
                          <td className="px-2 py-2"><Badge className={item.expected_access === 'deny' ? 'bg-amber-500/15 text-amber-300' : item.expected_access === 'allow' ? 'bg-green-500/15 text-green-300' : 'bg-gray-800 text-gray-300'}>{item.expected_access}{item.expected_http_status ? ` · ${item.expected_http_status}` : ''}</Badge></td>
                          <td className="px-2 py-2 text-right">
                            <div className="flex justify-end gap-1">
                              <Button size="sm" variant="ghost" onClick={() => setExpectationDraft({
                                method: item.method,
                                path: item.path,
                                principalId: item.principal_id || '',
                                principalRole: item.principal_role || '',
                                tenantId: item.tenant_id || '',
                                expectedAccess: item.expected_access,
                                expectedHttpStatus: item.expected_http_status ? String(item.expected_http_status) : '',
                              })}>Edit</Button>
                              <Button size="sm" variant="ghost" onClick={() => {
                                setEndpoint(item.path)
                                setMethod(item.method)
                                if (item.principal_auth_state === 'user1' || item.principal_auth_state === 'user2') setAsUser(item.principal_auth_state)
                              }}>Load test</Button>
                              <Button size="sm" variant="ghost" disabled={expectationBusy === item.id} onClick={() => void handleDeleteExpectation(item.id)}>Delete</Button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}
        </Card>
      )}

      <Card className="p-5 space-y-4">
        <h2 className="text-lg font-semibold text-white">Step 2. Configure Two User Contexts</h2>
        <div className="grid gap-4 lg:grid-cols-2">
          {(['user1', 'user2'] as UserKey[]).map((user) => {
            const userState = session?.users?.[user]
            const plannedPrincipal = principalsByAuthState[user]
            return (
              <div key={user} className="rounded-lg border border-gray-800 bg-gray-950 p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-semibold text-white uppercase tracking-wide">{user}</h3>
                    {plannedPrincipal && <p className="mt-0.5 text-xs text-gray-500">{plannedPrincipal.label} · {plannedPrincipal.role}{plannedPrincipal.tenant_id ? ` · tenant ${plannedPrincipal.tenant_id}` : ''}</p>}
                  </div>
                  <Badge className={userState?.is_authenticated ? 'bg-green-500/20 text-green-300' : 'bg-gray-700 text-gray-400'}>
                    {userState?.is_authenticated ? `${userState.auth_method || 'auth'} ready` : 'not authenticated'}
                  </Badge>
                </div>

                <div className="space-y-2">
                  <input
                    value={authForms[user].token}
                    onChange={(e) => setAuthForms(prev => ({ ...prev, [user]: { ...prev[user], token: e.target.value } }))}
                    placeholder="Bearer token (without Bearer prefix)"
                    className="w-full rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
                  />
                  <input
                    value={authForms[user].authHeader}
                    onChange={(e) => setAuthForms(prev => ({ ...prev, [user]: { ...prev[user], authHeader: e.target.value } }))}
                    placeholder="Auth header (e.g., Bearer eyJ...)"
                    className="w-full rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
                  />
                  <textarea
                    value={authForms[user].cookies}
                    onChange={(e) => setAuthForms(prev => ({ ...prev, [user]: { ...prev[user], cookies: e.target.value } }))}
                    placeholder="Cookies (session=abc; token=xyz)"
                    rows={2}
                    className="w-full rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
                  />
                </div>

                <Button
                  onClick={() => void handleApplyAuth(user)}
                  disabled={!currentSessionId || busyAction === `auth-${user}`}
                  className="w-full"
                >
                  {busyAction === `auth-${user}` ? `Applying ${user}...` : `Apply ${user} Auth`}
                </Button>
              </div>
            )
          })}
        </div>
      </Card>

      <Card className="p-5 space-y-4">
        <h2 className="text-lg font-semibold text-white">Step 3. Endpoint Validation</h2>
        <div className="grid gap-4 lg:grid-cols-[1.2fr_1fr]">
          <div className="space-y-3">
            <div className="grid gap-3 md:grid-cols-[1fr_auto_auto]">
              <input
                value={endpoint}
                onChange={(e) => setEndpoint(e.target.value)}
                placeholder="/api/resource/123"
                className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
              />
              <select
                value={method}
                onChange={(e) => setMethod(e.target.value)}
                aria-label="Request method"
                className="rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
              >
                {REQUEST_METHODS.map((option) => (
                  <option key={option} value={option}>{option}</option>
                ))}
              </select>
              <select
                value={asUser}
                onChange={(e) => setAsUser(e.target.value as UserKey)}
                aria-label="Test as user"
                className="rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
              >
                <option value="user1">as user1</option>
                <option value="user2">as user2</option>
              </select>
            </div>

            <textarea
              value={endpointBody}
              onChange={(e) => setEndpointBody(e.target.value)}
              placeholder='Optional JSON body, e.g. {"id": 1}'
              rows={3}
              className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm font-mono text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
            />

            <label className="inline-flex items-center gap-2 text-sm text-gray-300">
              <input
                type="checkbox"
                checked={allowOutOfScope}
                onChange={(e) => setAllowOutOfScope(e.target.checked)}
                className="rounded border-gray-600 bg-gray-900 text-blue-600"
              />
              Allow out-of-scope request (cross-origin)
            </label>

            <div className="flex flex-wrap gap-2">
              <Button
                onClick={() => void handleTestEndpoint()}
                disabled={!currentSessionId || busyAction === 'test-endpoint'}
              >
                {busyAction === 'test-endpoint' ? 'Testing...' : 'Run Endpoint Test'}
              </Button>
              <button
                type="button"
                onClick={handlePrefillFindingFromEndpoint}
                disabled={!endpointResult}
                className={OUTLINE_BUTTON_CLASSES}
              >
                Prefill Finding from Result
              </button>
            </div>
          </div>

          <div className="rounded-lg border border-gray-800 bg-gray-950 p-3 space-y-2">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-medium text-gray-200">Latest Result</h3>
              {endpointResult?.status !== undefined && (
                <Badge className="bg-gray-800 text-gray-300">HTTP {endpointResult.status}</Badge>
              )}
            </div>
            {!endpointResult && <p className="text-xs text-gray-500">No result yet</p>}
            {endpointResult && (
              <>
                <p className="text-xs text-gray-300">Accessible: <span className={endpointResult.accessible ? 'text-green-400' : 'text-gray-400'}>{String(endpointResult.accessible)}</span></p>
                <p className="text-xs text-gray-300">User: <span className="text-blue-300">{endpointResult.as_user || 'default'}</span></p>
                <pre className="max-h-44 overflow-auto rounded-md border border-gray-800 bg-gray-900 p-2 text-[11px] text-gray-300">
                  {endpointResult.body ? endpointResult.body.slice(0, 2000) : stringifyPretty(endpointResult.json || endpointResult.error || 'No response body')}
                </pre>
              </>
            )}
          </div>
        </div>
      </Card>

      <Card className="p-5 space-y-4">
        <h2 className="text-lg font-semibold text-white">Step 4. Save Verified Finding</h2>
        <div className="grid gap-4 lg:grid-cols-2">
          <div className="space-y-3">
            <input
              value={findingForm.title}
              onChange={(e) => setFindingForm(prev => ({ ...prev, title: e.target.value }))}
              placeholder="Finding title"
              className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
            />
            <div className="grid gap-3 md:grid-cols-3">
              <select
                value={findingForm.severity}
                onChange={(e) => setFindingForm(prev => ({ ...prev, severity: e.target.value as typeof SEVERITY_LEVELS[number] }))}
                aria-label="Finding severity"
                className="rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
              >
                {SEVERITY_LEVELS.map(level => (
                  <option key={level} value={level}>{level}</option>
                ))}
              </select>
              <input
                value={findingForm.category}
                onChange={(e) => setFindingForm(prev => ({ ...prev, category: e.target.value }))}
                placeholder="Category (e.g., BOLA)"
                className="rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
              />
              <input
                value={findingForm.cwe}
                onChange={(e) => setFindingForm(prev => ({ ...prev, cwe: e.target.value }))}
                placeholder="CWE-639"
                className="rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
              />
            </div>
            <input
              value={findingForm.url}
              onChange={(e) => setFindingForm(prev => ({ ...prev, url: e.target.value }))}
              placeholder="Vulnerable URL"
              className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
            />
            <textarea
              value={findingForm.description}
              onChange={(e) => setFindingForm(prev => ({ ...prev, description: e.target.value }))}
              placeholder="Description"
              rows={3}
              className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
            />
            <textarea
              value={findingForm.evidence}
              onChange={(e) => setFindingForm(prev => ({ ...prev, evidence: e.target.value }))}
              placeholder="Exploit evidence"
              rows={3}
              className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
            />
          </div>

          <div className="space-y-3">
            <textarea
              value={findingForm.request}
              onChange={(e) => setFindingForm(prev => ({ ...prev, request: e.target.value }))}
              placeholder="Raw HTTP request"
              rows={4}
              className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm font-mono text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
            />
            <textarea
              value={findingForm.response}
              onChange={(e) => setFindingForm(prev => ({ ...prev, response: e.target.value }))}
              placeholder="Raw HTTP response"
              rows={4}
              className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm font-mono text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
            />
            <textarea
              value={findingForm.remediation}
              onChange={(e) => setFindingForm(prev => ({ ...prev, remediation: e.target.value }))}
              placeholder="Remediation guidance"
              rows={2}
              className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
            />
            <textarea
              value={findingForm.notes}
              onChange={(e) => setFindingForm(prev => ({ ...prev, notes: e.target.value }))}
              placeholder="Analyst notes"
              rows={2}
              className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
            />
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <Button
            onClick={() => void handleCreateFinding()}
            disabled={!currentSessionId || busyAction === 'create-finding'}
          >
            {busyAction === 'create-finding' ? 'Saving...' : 'Save Finding'}
          </Button>
          {createdFindingId && (
            <Link
              href={`/findings/${createdFindingId}`}
              className="rounded-lg border border-green-500/40 px-3 py-2 text-sm text-green-300 hover:bg-green-500/10 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
            >
              Open Finding {createdFindingId.slice(0, 8)}
            </Link>
          )}
        </div>
      </Card>

      <Card className="p-5 space-y-3">
        <h2 className="text-lg font-semibold text-white">Step 5. Visual + Discovery Context</h2>
        <div className="flex flex-wrap items-center gap-2">
          <select
            value={screenshotUser}
            onChange={(e) => setScreenshotUser(e.target.value)}
            aria-label="Screenshot user context"
            className="rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
          >
            {userList.map((user) => (
              <option key={user} value={user}>{user}</option>
            ))}
          </select>
          <button
            type="button"
            onClick={() => void handleCaptureScreenshot()}
            disabled={!currentSessionId || busyAction === 'capture-screenshot'}
            className={OUTLINE_BUTTON_CLASSES}
          >
            {busyAction === 'capture-screenshot' ? 'Capturing...' : 'Capture Screenshot'}
          </button>
        </div>

        {screenshot && (
          <div className="rounded-lg border border-gray-800 bg-gray-950 p-3">
            <p className="mb-2 text-xs text-gray-400">Captured for <span className="text-blue-300">{screenshot.user}</span> at {screenshot.url}</p>
            <img
              src={screenshot.dataUrl}
              alt={`Screenshot for ${screenshot.user}`}
              className="w-full rounded border border-gray-800"
            />
          </div>
        )}

        <div className="rounded-lg border border-gray-800 bg-gray-950 p-3">
          <h3 className="mb-2 text-sm font-medium text-gray-200">Discovered Endpoints</h3>
          {session?.discovered_endpoints?.length ? (
            <div className="max-h-48 overflow-auto">
              <table className="w-full text-xs text-gray-300">
                <thead>
                  <tr className="text-left text-gray-500">
                    <th className="py-1 pr-2">Method</th>
                    <th className="py-1 pr-2">Path</th>
                    <th className="py-1 pr-2">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {session.discovered_endpoints.map((item, idx) => (
                    <tr key={`${item.method}-${item.path}-${idx}`} className="border-t border-gray-800">
                      <td className="py-1 pr-2 text-blue-300">{item.method}</td>
                      <td className="py-1 pr-2 font-mono text-[11px]">{item.path}</td>
                      <td className="py-1 pr-2">{item.status ?? '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-xs text-gray-500">No endpoints discovered yet.</p>
          )}
        </div>
      </Card>
    </div>
  )
}
