'use client'

import Link from 'next/link'
import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  captureInteractiveScreenshot,
  createInteractiveSessionFinding,
  endInteractiveSession,
  getInteractiveSession,
  listInteractiveSessions,
  runInteractiveAction,
  startInteractiveSession,
  testInteractiveEndpoint,
  type InteractiveEndpointTestResult,
  type InteractiveSessionState,
  type InteractiveSessionSummary,
} from '@/lib/api'
import { SEVERITY_LEVELS } from '@/lib/constants'

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
  const [target, setTarget] = useState('https://cr.shakerscan.com')
  const [sessionInput, setSessionInput] = useState('')
  const [session, setSession] = useState<InteractiveSessionState | null>(null)
  const [activeSessions, setActiveSessions] = useState<InteractiveSessionSummary[]>([])

  const [endpoint, setEndpoint] = useState('/identity/api/v2/user/dashboard')
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
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  const currentSessionId = session?.session_id || ''

  const fetchActiveSessions = useCallback(async () => {
    try {
      const data = await listInteractiveSessions()
      setActiveSessions(data.sessions || [])
    } catch {
      setActiveSessions([])
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
      setError(null)
    } catch (err) {
      setSession(null)
      setError(err instanceof Error ? err.message : 'Failed to load session')
    } finally {
      if (!silent) {
        setBusyAction(null)
      }
    }
  }, [])

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

  async function handleStartSession() {
    if (!target.trim()) {
      setError('Target URL is required')
      return
    }

    setBusyAction('start-session')
    setError(null)
    setNotice(null)
    try {
      const res = await startInteractiveSession(target.trim())
      setNotice(`Session started: ${res.session_id}`)
      await loadSessionState(res.session_id)
      await fetchActiveSessions()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start session')
    } finally {
      setBusyAction(null)
    }
  }

  async function handleAttachSession() {
    const id = sessionInput.trim()
    if (!id) {
      setError('Session ID is required')
      return
    }

    setError(null)
    setNotice(null)
    await loadSessionState(id)
  }

  async function handleEndSession() {
    if (!currentSessionId) return

    setBusyAction('end-session')
    setError(null)
    setNotice(null)
    try {
      await endInteractiveSession(currentSessionId)
      setNotice(`Session closed: ${currentSessionId}`)
      setSession(null)
      setEndpointResult(null)
      setScreenshot(null)
      await fetchActiveSessions()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to close session')
    } finally {
      setBusyAction(null)
    }
  }

  async function handleApplyAuth(user: UserKey) {
    if (!currentSessionId) {
      setError('Start or attach a session first')
      return
    }

    const form = authForms[user]
    if (!form.token.trim() && !form.authHeader.trim() && !form.cookies.trim()) {
      setError(`Provide token/auth header/cookies for ${user}`)
      return
    }

    const data: Record<string, unknown> = {}
    if (form.token.trim()) data.token = form.token.trim()
    if (form.authHeader.trim()) data.auth_header = form.authHeader.trim()
    if (form.cookies.trim()) data.cookie_string = form.cookies.trim()

    setBusyAction(`auth-${user}`)
    setError(null)
    setNotice(null)
    try {
      const res = await runInteractiveAction(currentSessionId, {
        action: 'set_auth',
        user,
        data,
      })
      setNotice(`${user} auth applied (${res.auth_method || 'unknown method'})`)
      await loadSessionState(currentSessionId, true)
    } catch (err) {
      setError(err instanceof Error ? err.message : `Failed to apply auth for ${user}`)
    } finally {
      setBusyAction(null)
    }
  }

  async function handleCaptureScreenshot() {
    if (!currentSessionId) {
      setError('Start or attach a session first')
      return
    }

    setBusyAction('capture-screenshot')
    setError(null)
    setNotice(null)
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
      setNotice(`Screenshot captured for ${res.user}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to capture screenshot')
    } finally {
      setBusyAction(null)
    }
  }

  async function handleTestEndpoint() {
    if (!currentSessionId) {
      setError('Start or attach a session first')
      return
    }
    if (!endpoint.trim()) {
      setError('Endpoint is required')
      return
    }

    let parsedBody: Record<string, unknown> | undefined
    try {
      parsedBody = parseJsonInput(endpointBody)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Invalid JSON body')
      return
    }

    setBusyAction('test-endpoint')
    setError(null)
    setNotice(null)
    try {
      const result = await testInteractiveEndpoint(currentSessionId, {
        endpoint: endpoint.trim(),
        method,
        as_user: asUser,
        body: parsedBody,
        allow_out_of_scope: allowOutOfScope,
      })
      setEndpointResult(result)
      setNotice(`Endpoint tested as ${asUser}: ${result.status || 'no-status'}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Endpoint test failed')
    } finally {
      setBusyAction(null)
    }
  }

  function handlePrefillFindingFromEndpoint() {
    if (!endpointResult) {
      setError('Run an endpoint test first')
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
    setNotice('Finding form prefilled from latest endpoint test')
    setError(null)
  }

  async function handleCreateFinding() {
    if (!currentSessionId) {
      setError('Start or attach a session first')
      return
    }

    const title = findingForm.title.trim()
    if (!title) {
      setError('Finding title is required')
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
    setError(null)
    setNotice(null)
    try {
      const result = await createInteractiveSessionFinding(currentSessionId, payload)
      setCreatedFindingId(result.id)
      setNotice(`Finding created: ${result.id}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create finding')
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
          className="inline-flex items-center gap-2 rounded-lg border border-gray-700 px-3 py-2 text-sm text-gray-300 hover:border-blue-500 hover:text-blue-300"
        >
          Open Findings
        </Link>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">{error}</div>
      )}
      {notice && (
        <div className="rounded-lg border border-green-500/30 bg-green-500/10 px-4 py-3 text-sm text-green-300">{notice}</div>
      )}

      <section className="rounded-lg border border-gray-800 bg-gray-900 p-5 space-y-4">
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
              <button
                onClick={handleStartSession}
                disabled={busyAction === 'start-session'}
                className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {busyAction === 'start-session' ? 'Starting...' : 'Start Session'}
              </button>
              <button
                onClick={() => {
                  if (!currentSessionId) return
                  void loadSessionState(currentSessionId)
                }}
                disabled={!currentSessionId || busyAction === 'load-session'}
                className="rounded-lg border border-gray-700 px-4 py-2 text-sm text-gray-300 hover:border-gray-600 disabled:cursor-not-allowed disabled:opacity-60"
              >
                Refresh State
              </button>
              <button
                onClick={handleEndSession}
                disabled={!currentSessionId || busyAction === 'end-session'}
                className="rounded-lg border border-red-500/50 px-4 py-2 text-sm text-red-300 hover:bg-red-500/10 disabled:cursor-not-allowed disabled:opacity-60"
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
                  onClick={handleAttachSession}
                  disabled={busyAction === 'load-session'}
                  className="rounded-lg border border-gray-700 px-4 py-2 text-sm text-gray-300 hover:border-gray-600 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  Attach
                </button>
              </div>
            </div>
          </div>

          <div className="rounded-lg border border-gray-800 bg-gray-950 p-3">
            <h3 className="text-sm font-medium text-gray-200">Active Sessions</h3>
            <div className="mt-2 max-h-40 space-y-2 overflow-auto pr-1">
              {activeSessions.length === 0 && <p className="text-xs text-gray-500">No active sessions</p>}
              {activeSessions.map((item) => (
                <button
                  key={item.session_id}
                  onClick={() => {
                    setSessionInput(item.session_id)
                    void loadSessionState(item.session_id)
                  }}
                  className="w-full rounded-md border border-gray-800 px-2 py-2 text-left text-xs text-gray-300 hover:border-blue-500 hover:bg-blue-500/5"
                >
                  <p className="font-mono text-[11px] text-blue-300">{item.session_id}</p>
                  <p className="truncate text-gray-400">{item.target_url}</p>
                </button>
              ))}
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
            <p><span className="text-gray-500">Last Activity:</span> {new Date(session.last_activity).toLocaleString()}</p>
          </div>
        )}
      </section>

      <section className="rounded-lg border border-gray-800 bg-gray-900 p-5 space-y-4">
        <h2 className="text-lg font-semibold text-white">Step 2. Configure Two User Contexts</h2>
        <div className="grid gap-4 lg:grid-cols-2">
          {(['user1', 'user2'] as UserKey[]).map((user) => {
            const userState = session?.users?.[user]
            return (
              <div key={user} className="rounded-lg border border-gray-800 bg-gray-950 p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-white uppercase tracking-wide">{user}</h3>
                  <span className={`rounded px-2 py-0.5 text-xs ${userState?.is_authenticated ? 'bg-green-500/20 text-green-300' : 'bg-gray-700 text-gray-400'}`}>
                    {userState?.is_authenticated ? `${userState.auth_method || 'auth'} ready` : 'not authenticated'}
                  </span>
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

                <button
                  onClick={() => void handleApplyAuth(user)}
                  disabled={!currentSessionId || busyAction === `auth-${user}`}
                  className="w-full rounded-lg bg-blue-600 px-3 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {busyAction === `auth-${user}` ? `Applying ${user}...` : `Apply ${user} Auth`}
                </button>
              </div>
            )
          })}
        </div>
      </section>

      <section className="rounded-lg border border-gray-800 bg-gray-900 p-5 space-y-4">
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
                className="rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
              >
                {REQUEST_METHODS.map((option) => (
                  <option key={option} value={option}>{option}</option>
                ))}
              </select>
              <select
                value={asUser}
                onChange={(e) => setAsUser(e.target.value as UserKey)}
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
              <button
                onClick={() => void handleTestEndpoint()}
                disabled={!currentSessionId || busyAction === 'test-endpoint'}
                className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {busyAction === 'test-endpoint' ? 'Testing...' : 'Run Endpoint Test'}
              </button>
              <button
                onClick={handlePrefillFindingFromEndpoint}
                disabled={!endpointResult}
                className="rounded-lg border border-gray-700 px-4 py-2 text-sm text-gray-300 hover:border-gray-600 disabled:cursor-not-allowed disabled:opacity-60"
              >
                Prefill Finding from Result
              </button>
            </div>
          </div>

          <div className="rounded-lg border border-gray-800 bg-gray-950 p-3 space-y-2">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-medium text-gray-200">Latest Result</h3>
              {endpointResult?.status !== undefined && (
                <span className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-300">HTTP {endpointResult.status}</span>
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
      </section>

      <section className="rounded-lg border border-gray-800 bg-gray-900 p-5 space-y-4">
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
          <button
            onClick={() => void handleCreateFinding()}
            disabled={!currentSessionId || busyAction === 'create-finding'}
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {busyAction === 'create-finding' ? 'Saving...' : 'Save Finding'}
          </button>
          {createdFindingId && (
            <Link
              href={`/findings/${createdFindingId}`}
              className="rounded-lg border border-green-500/40 px-3 py-2 text-sm text-green-300 hover:bg-green-500/10"
            >
              Open Finding {createdFindingId.slice(0, 8)}
            </Link>
          )}
        </div>
      </section>

      <section className="rounded-lg border border-gray-800 bg-gray-900 p-5 space-y-3">
        <h2 className="text-lg font-semibold text-white">Step 5. Visual + Discovery Context</h2>
        <div className="flex flex-wrap items-center gap-2">
          <select
            value={screenshotUser}
            onChange={(e) => setScreenshotUser(e.target.value)}
            className="rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
          >
            {userList.map((user) => (
              <option key={user} value={user}>{user}</option>
            ))}
          </select>
          <button
            onClick={() => void handleCaptureScreenshot()}
            disabled={!currentSessionId || busyAction === 'capture-screenshot'}
            className="rounded-lg border border-gray-700 px-4 py-2 text-sm text-gray-300 hover:border-gray-600 disabled:cursor-not-allowed disabled:opacity-60"
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
      </section>
    </div>
  )
}
