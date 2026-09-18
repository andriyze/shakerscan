'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { API_URL } from '@/lib/apiConfig'
import { featureEnabled } from '@/lib/workspaceCapabilities'
import { formatRelativeTime } from '@/lib/format'
import type { CredentialProfile } from '@/lib/credentialApi'
import type { ProfileConfiguration, ProfileWrite } from '@/lib/publicApi.generated'
import AuthenticationValidation from './AuthenticationValidation'
import AuthenticationHistory from './AuthenticationHistory'

type Profile = {
  profile_id: string
  revision: number
  credential_version: number
  configuration: ProfileConfiguration
  assurance: { state: string; reason_code: string; last_validated_at: string | null; last_checked_at?: string | null }
}

export default function AuthenticationProfiles({ targetId, credentials }: {
  targetId: string
  credentials: CredentialProfile[]
}) {
  const [enabled, setEnabled] = useState(false)
  const [validationMethods, setValidationMethods] = useState<string[]>([])
  const [historySupported, setHistorySupported] = useState(false)
  const [profiles, setProfiles] = useState<Profile[]>([])
  const [editing, setEditing] = useState<Profile | null>(null)
  const [draft, setDraft] = useState<ProfileConfiguration | null>(null)
  const [reviewed, setReviewed] = useState(false)
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)
  const activeTarget = useRef(targetId)
  activeTarget.current = targetId

  useEffect(() => {
    let cancelled = false
    setEnabled(false)
    setValidationMethods([])
    setHistorySupported(false)
    setProfiles([])
    setDraft(null)
    setError('')
    if (!targetId || !featureEnabled('authenticated_assurance')) return
    void (async () => {
      try {
        const contractResponse = await fetch(`${API_URL}/authenticated-scan-profiles/contract`, { cache: 'no-store' })
        if (!contractResponse.ok) return
        const contract = await contractResponse.json()
        if (!contract.enabled || contract.schema_version !== 'authenticated-scan-profile/v1') return
        const response = await fetch(`${API_URL}/authenticated-scan-profiles?target_id=${encodeURIComponent(targetId)}`, { cache: 'no-store' })
        if (!response.ok) throw new Error('Authentication profile management is unavailable for this deployment.')
        const data = await response.json()
        if (!cancelled) {
          setProfiles(data.profiles); setEnabled(true)
          setValidationMethods(contract.validation_execution === 'queued_read_only' ? contract.supported_validation_methods || [] : [])
          setHistorySupported(contract.validation_history === true)
        }
      } catch {
        if (!cancelled) setError('Authentication profile management is unavailable for this deployment.')
      }
    })()
    return () => { cancelled = true }
  }, [targetId])

  const refresh = useCallback(() => {
    void fetch(`${API_URL}/authenticated-scan-profiles?target_id=${encodeURIComponent(targetId)}`, { cache: 'no-store' })
      .then(async response => {
        if (!response.ok) throw new Error()
        const data = await response.json()
        if (activeTarget.current === targetId) setProfiles(data.profiles)
      }).catch(() => {
        if (activeTarget.current === targetId) setProfiles(previous => previous.map(profile => ({ ...profile,
          assurance: { ...profile.assurance, state: 'unknown', reason_code: 'validation_unavailable' } })))
      })
  }, [targetId])

  useEffect(() => {
    if (!enabled) return
    const timer = setInterval(refresh, 15000)
    return () => clearInterval(timer)
  }, [enabled, refresh])

  function start(profile: Profile | null) {
    const credential = credentials.find(item => item.is_active && ['web', 'api'].includes(item.target_kind))
    if (!profile && !credential) { setError('Connect a test identity using the secure credential form first.'); return }
    setEditing(profile)
    setReviewed(false)
    setError('')
    setDraft(profile ? structuredClone(profile.configuration) : {
      schema_version: 'authenticated-scan-profile/v1', target_id: targetId,
      credential_reference: credential!.id,
      display_name: '', environment_label: '', declared_role: null,
      credential_destinations: [''], lifecycle_state: 'draft',
      validation_policy: {
        path: '/api/me', identity_field: 'user_id', expected_identity: '',
        freshness_seconds: 300, timeout_seconds: 5, owner_confirmed_read_only: true,
      },
    })
  }

  async function save(event: React.FormEvent) {
    event.preventDefault()
    if (!draft || !reviewed) return
    if (['disabled', 'archived'].includes(draft.lifecycle_state || '') &&
        !window.confirm('Stop new use of this authentication configuration? Historical revisions and the saved credential remain available. Archived configurations cannot be edited.')) return
    const body: ProfileWrite = { configuration: draft, expected_revision: editing?.revision || 0, reviewed: true }
    const savedTarget = targetId
    setSaving(true)
    setError('')
    try {
      const response = await fetch(`${API_URL}/authenticated-scan-profiles`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
      })
      if (!response.ok) throw new Error(response.status === 409
        ? 'The profile or credential changed. Close this form and reload before reviewing the latest revision.'
        : 'The profile could not be saved. Check the destination, identity criteria, and required fields.')
      const saved: Profile = await response.json()
      if (activeTarget.current !== savedTarget) return
      setProfiles(previous => [...previous.filter(item => item.profile_id !== saved.profile_id), saved])
      setDraft(null)
    } catch (cause) {
      if (activeTarget.current === savedTarget) setError(cause instanceof Error ? cause.message : 'The profile could not be saved.')
    } finally { setSaving(false) }
  }

  if (!enabled) return error ? <p role="status" className="mb-4 text-sm text-amber-300">{error}</p> : null
  const inputClass = 'mt-1 w-full rounded border border-gray-700 bg-gray-950 p-2 focus:outline-none focus:ring-2 focus:ring-blue-400'
  return <section aria-label="Authentication profiles" className="mb-6 rounded-xl border border-gray-800 p-5">
    <h2 className="text-lg font-semibold">Authentication profiles · internal preview</h2>
    <p className="my-2 text-sm text-gray-400">Reviewed configuration does not grant target authorization. Scan selection is not supported in this preview. Existing credentials do not prove accepted identity.</p>
    <button type="button" className="my-2 rounded border border-gray-600 px-3 py-2 focus:ring-2 focus:ring-blue-400" onClick={() => start(null)}>New authentication profile</button>
    {error && <p role="alert" className="my-2 text-sm text-amber-300">{error}</p>}
    <ul className="divide-y divide-gray-800">
      {profiles.map(profile => <li key={profile.profile_id} className="py-3">
        <p>{profile.configuration.display_name} · revision {profile.revision} · credential version {profile.credential_version}</p>
        <p className="text-sm text-gray-400">{profile.configuration.environment_label} · declared role: {profile.configuration.declared_role || 'not specified'} · {profile.configuration.lifecycle_state}</p>
        <p className="text-sm">Identity: {profile.assurance.state} · {profile.assurance.reason_code.replaceAll('_', ' ')}</p>
        <p className="text-sm text-gray-400">{profile.assurance.last_validated_at ? `Validated at ${new Date(profile.assurance.last_validated_at).toLocaleString()} (${formatRelativeTime(profile.assurance.last_validated_at)}); this is a historical observation.` : 'No successful validation recorded.'}</p>
        {profile.assurance.last_checked_at && <p className="text-sm text-gray-400">Latest status observation: {formatRelativeTime(profile.assurance.last_checked_at)}</p>}
        {profile.configuration.lifecycle_state !== 'archived' && <button type="button" className="mt-1 underline focus:ring-2 focus:ring-blue-400" onClick={() => start(profile)}>Review or edit</button>}
        {validationMethods.includes(credentials.find(item => item.is_active && item.allowed_capabilities.includes('http.request') && item.id === profile.profile_id)?.auth_kind || '') && !['disabled', 'archived'].includes(profile.configuration.lifecycle_state || '')
          ? <AuthenticationValidation key={`${targetId}:${profile.profile_id}:${profile.revision}`} profileId={profile.profile_id} revision={profile.revision} targetId={targetId}
            origin={profile.configuration.credential_destinations[0]} path={profile.configuration.validation_policy.path} onUpdated={refresh} />
          : <p className="mt-1 text-sm text-gray-400">Live identity validation is unavailable for this method or profile state. Interactive sign-in is unsupported.</p>}
        {historySupported && <AuthenticationHistory key={`history:${targetId}:${profile.profile_id}`} profileId={profile.profile_id} />}
      </li>)}
    </ul>
    {draft && <form onSubmit={save} className="mt-4 space-y-3 border-t border-gray-700 pt-4">
      <p className="text-sm">Use identity labels here. Connect passwords, tokens, and cookies only in the secure credential form.</p>
      <label className="block">Name<input required maxLength={120} className={inputClass} value={draft.display_name} onChange={e => setDraft({ ...draft, display_name: e.target.value })} /></label>
      <label className="block">Environment<input required maxLength={80} className={inputClass} value={draft.environment_label} onChange={e => setDraft({ ...draft, environment_label: e.target.value })} /></label>
      <label className="block">Declared role<input maxLength={120} className={inputClass} value={draft.declared_role || ''} onChange={e => setDraft({ ...draft, declared_role: e.target.value || null })} /></label>
      <label className="block">Saved test identity<select disabled={!!editing} className={inputClass} value={draft.credential_reference} onChange={e => setDraft({ ...draft, credential_reference: e.target.value })}>
        {credentials.filter(item => item.is_active && ['web', 'api'].includes(item.target_kind)).map(item => <option key={item.id} value={item.id}>{item.name} · {item.auth_kind}</option>)}
      </select></label>
      <label className="block">Exact credential destination (scheme, host, port)<input required placeholder="https://staging.example.test" className={inputClass} value={draft.credential_destinations[0]} onChange={e => setDraft({ ...draft, credential_destinations: [e.target.value] })} /></label>
      <label className="block">Owner-provided read-only health path<input required className={inputClass} value={draft.validation_policy.path} onChange={e => setDraft({ ...draft, validation_policy: { ...draft.validation_policy, path: e.target.value } })} /></label>
      <label className="block">JSON identity field<input required className={inputClass} value={draft.validation_policy.identity_field} onChange={e => setDraft({ ...draft, validation_policy: { ...draft.validation_policy, identity_field: e.target.value } })} /></label>
      <label className="block">Expected non-secret identity label<input required maxLength={120} className={inputClass} value={draft.validation_policy.expected_identity} onChange={e => setDraft({ ...draft, validation_policy: { ...draft.validation_policy, expected_identity: e.target.value } })} /></label>
      {draft.validation_policy.role_field && <p className="text-sm text-gray-400">Observed-role criterion: {draft.validation_policy.role_field} must match {draft.validation_policy.expected_role}. This is separate from the declared role label.</p>}
      <details className="rounded border border-gray-700 p-3">
        <summary className="cursor-pointer focus:ring-2 focus:ring-blue-400">Advanced validation: role, timeout, and freshness</summary>
        <div className="mt-2 space-y-3">
          <label className="block">Optional JSON role field<input required={!!draft.validation_policy.expected_role} maxLength={64} pattern="[A-Za-z_][A-Za-z0-9_]{0,63}" className={inputClass} value={draft.validation_policy.role_field || ''} onChange={e => setDraft({ ...draft, validation_policy: { ...draft.validation_policy, role_field: e.target.value || null } })} /></label>
          <label className="block">Expected non-secret role value<input required={!!draft.validation_policy.role_field} maxLength={120} className={inputClass} value={draft.validation_policy.expected_role || ''} onChange={e => setDraft({ ...draft, validation_policy: { ...draft.validation_policy, expected_role: e.target.value || null } })} /></label>
          <label className="block">Health request timeout (seconds)<input required type="number" min={1} max={10} step={1} className={inputClass} value={draft.validation_policy.timeout_seconds ?? 5} onChange={e => setDraft({ ...draft, validation_policy: { ...draft.validation_policy, timeout_seconds: Number(e.target.value) } })} /></label>
          <label className="block">Validation freshness (seconds)<input required type="number" min={30} max={900} step={1} className={inputClass} value={draft.validation_policy.freshness_seconds ?? 300} onChange={e => setDraft({ ...draft, validation_policy: { ...draft.validation_policy, freshness_seconds: Number(e.target.value) } })} /></label>
        </div>
      </details>
      <label className="block">Lifecycle<select className={inputClass} value={draft.lifecycle_state} onChange={e => setDraft({ ...draft, lifecycle_state: e.target.value as ProfileConfiguration['lifecycle_state'] })}>
        <option value="draft">Draft</option><option value="ready">Reviewed configuration (identity unverified)</option><option value="disabled">Disabled</option><option value="archived">Archived (permanent)</option>
      </select></label>
      <label className="flex items-start gap-2"><input type="checkbox" checked={reviewed} onChange={e => setReviewed(e.target.checked)} className="mt-1" />I reviewed the destination and non-secret identity criteria, and confirm the health resource is read-only. This does not authorize assessment work.</label>
      <div className="flex gap-3"><button disabled={!reviewed || saving} className="rounded bg-blue-700 px-3 py-2 disabled:opacity-40 focus:ring-2 focus:ring-blue-400">{saving ? 'Saving…' : 'Save reviewed revision'}</button><button type="button" onClick={() => setDraft(null)} className="rounded border border-gray-600 px-3 py-2 focus:ring-2 focus:ring-blue-400">Close</button></div>
    </form>}
  </section>
}
