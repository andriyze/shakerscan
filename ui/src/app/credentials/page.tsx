'use client'

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { KeyRound, Plus, RefreshCw, RotateCw, ShieldCheck, Trash2 } from 'lucide-react'
import {
  getDevices,
  getTargets,
  type DeviceTarget,
  type Target,
} from '@/lib/api'
import {
  createCredentialProfile,
  deactivateCredentialProfile,
  listCredentialCapabilities,
  listCredentialProfiles,
  type CredentialCapabilityOption,
  rotateCredentialProfile,
  type CredentialAuthKind,
  type CredentialPrincipalSlot,
  type CredentialProfile,
  type CredentialSecretPayload,
  type CredentialTargetKind,
} from '@/lib/credentialApi'
import {
  Button,
  Card,
  ConfirmDialog,
  EmptyState,
  ErrorState,
  Field,
  Input,
  Modal,
  PageHeader,
  Select,
  Textarea,
  useToast,
} from '@/components/ui'
import { usableWebTargets } from '@/lib/targetChoices'

const HTTP_KINDS: { value: CredentialAuthKind; label: string }[] = [
  { value: 'bearer_token', label: 'Bearer token' },
  { value: 'authorization_header', label: 'Authorization header' },
  { value: 'api_key_header', label: 'API key header' },
  { value: 'cookie', label: 'Cookie' },
  { value: 'basic_auth', label: 'Basic authentication' },
  { value: 'form_login', label: 'Form login' },
  { value: 'oauth_client_credentials', label: 'OAuth client credentials' },
  { value: 'oauth_password', label: 'OAuth password flow' },
  { value: 'custom_headers', label: 'Custom headers' },
  { value: 'query_parameter', label: 'Query parameter' },
]
const SSH_KINDS: { value: CredentialAuthKind; label: string }[] = [
  { value: 'ssh_password', label: 'SSH password' },
  { value: 'ssh_private_key', label: 'SSH private key' },
  { value: 'ssh_private_key_with_passphrase', label: 'SSH key + passphrase' },
]

type Draft = {
  name: string
  authKind: CredentialAuthKind
  principalLabel: string
  principalSlot: CredentialPrincipalSlot
  secret: string
  username: string
  secondarySecret: string
  headerName: string
  endpointUrl: string
  clientId: string
  scopes: string
  customHeaders: string
  expiresAt: string
  capabilities: string
  allowActiveCapabilities: boolean
}

type DraftErrors = Partial<Record<keyof Draft, string>>

const EMPTY_DRAFT: Draft = {
  name: '',
  authKind: 'bearer_token',
  principalLabel: '',
  principalSlot: 'primary',
  secret: '',
  username: '',
  secondarySecret: '',
  headerName: 'X-API-Key',
  endpointUrl: '',
  clientId: '',
  scopes: '',
  customHeaders: '',
  expiresAt: '',
  capabilities: '',
  allowActiveCapabilities: false,
}

function splitValues(value: string): string[] {
  return Array.from(new Set(value.split(/[\s,]+/).map((item) => item.trim()).filter(Boolean)))
}

function customHeaders(value: string): Record<string, string> | undefined {
  if (!value.trim()) return undefined
  const result: Record<string, string> = {}
  for (const line of value.split('\n').map((item) => item.trim()).filter(Boolean)) {
    const separator = line.indexOf(':')
    if (separator < 1 || !line.slice(separator + 1).trim()) {
      throw new Error('Each custom header must use “Name: value” on its own line.')
    }
    result[line.slice(0, separator).trim()] = line.slice(separator + 1).trim()
  }
  return result
}

function isSsh(kind: CredentialAuthKind): boolean {
  return kind.startsWith('ssh_')
}

// Mirrors IDENTITY_PAIR_KINDS in api/runtime/credentials.py. These flows accept either half
// of the username/secret pair on its own, so neither field is individually required -- but at
// least one must be present. A UI test asserts this list matches the backend constant.
const IDENTITY_PAIR_KINDS: CredentialAuthKind[] = ['basic_auth', 'form_login', 'oauth_password']

function isIdentityPair(kind: CredentialAuthKind): boolean {
  return IDENTITY_PAIR_KINDS.includes(kind)
}

// Which kinds show a username field at all. SSH additionally requires it.
function showsUsername(kind: CredentialAuthKind): boolean {
  return isIdentityPair(kind) || isSsh(kind)
}

function needsEndpoint(kind: CredentialAuthKind): boolean {
  return ['form_login', 'oauth_client_credentials', 'oauth_password'].includes(kind)
}

function validateDraft(draft: Draft, rotating: boolean): DraftErrors {
  const errors: DraftErrors = {}
  if (!rotating && !draft.name.trim()) errors.name = 'Enter a profile name.'
  if (isSsh(draft.authKind) && !draft.username.trim()) errors.username = 'Enter the username for this identity.'
  if ((draft.authKind === 'api_key_header' || draft.authKind === 'query_parameter') && !draft.headerName.trim()) {
    errors.headerName = draft.authKind === 'query_parameter' ? 'Enter the parameter name.' : 'Enter the header name.'
  }
  if (needsEndpoint(draft.authKind) && !draft.endpointUrl.trim()) errors.endpointUrl = 'Enter the login or token endpoint.'
  if (draft.authKind === 'oauth_client_credentials' && !draft.clientId.trim()) errors.clientId = 'Enter the OAuth client ID.'
  if (draft.authKind === 'custom_headers') {
    if (!draft.customHeaders.trim()) errors.customHeaders = 'Enter at least one Name: value header.'
  } else if (isIdentityPair(draft.authKind)) {
    if (!draft.username.trim() && !draft.secret.trim()) {
      const message = 'Enter a username, a secret, or both.'
      errors.username = message
      errors.secret = message
    }
  } else if (!draft.secret.trim()) {
    errors.secret = draft.authKind.startsWith('ssh_private_key') ? 'Paste the private key.' : 'Enter the secret value.'
  }
  if (draft.authKind === 'ssh_private_key_with_passphrase' && !draft.secondarySecret.trim()) {
    errors.secondarySecret = 'Enter the private-key passphrase.'
  }
  return errors
}

function secretPayload(draft: Draft): CredentialSecretPayload {
  const kind = draft.authKind
  const payload: CredentialSecretPayload = {}
  // A pair kind omits the half it does not hold rather than sending an empty string, so the
  // stored envelope records absence instead of a blank value.
  if (isIdentityPair(kind)) {
    if (draft.secret.trim()) payload.secret = draft.secret
    if (draft.username.trim()) payload.username = draft.username
  } else {
    if (kind !== 'custom_headers') payload.secret = draft.secret
    if (showsUsername(kind)) payload.username = draft.username
  }
  if (kind === 'ssh_private_key_with_passphrase') payload.secondary_secret = draft.secondarySecret
  if (kind === 'api_key_header') payload.header_name = draft.headerName
  if (kind === 'query_parameter') payload.parameter_name = draft.headerName
  if (needsEndpoint(kind)) payload.endpoint_url = draft.endpointUrl
  if ((kind === 'oauth_client_credentials' || kind === 'oauth_password') && draft.clientId.trim()) {
    payload.client_id = draft.clientId
  }
  if (kind === 'oauth_client_credentials' || kind === 'oauth_password') {
    payload.scopes = splitValues(draft.scopes)
  }
  if (kind === 'custom_headers') payload.custom_headers = customHeaders(draft.customHeaders)
  if (draft.expiresAt) payload.expires_at = new Date(draft.expiresAt).toISOString()
  return payload
}

// Content-free description of which half of a username/secret pair a profile holds. Only
// meaningful for pair kinds, where either half alone is a valid identity.
function identityComposition(profile: CredentialProfile): string | null {
  if (!isIdentityPair(profile.auth_kind)) return null
  const hasUsername = profile.configuration.username_configured
  const hasSecret = profile.configuration.secret_configured
  if (hasUsername && hasSecret) return 'username + secret'
  if (hasUsername) return 'username only'
  if (hasSecret) return 'secret only'
  return null
}

function statusClass(profile: CredentialProfile): string {
  if (profile.status === 'active' && !profile.refresh_required) {
    return 'bg-emerald-500/10 text-emerald-300'
  }
  if (profile.status === 'expired' || profile.refresh_required) {
    return 'bg-amber-500/10 text-amber-300'
  }
  return 'bg-gray-800 text-gray-400'
}

export default function CredentialsPage() {
  const toast = useToast()
  const appliedDeepLink = useRef(false)
  const [targets, setTargets] = useState<Target[]>([])
  const [devices, setDevices] = useState<DeviceTarget[]>([])
  const [targetKind, setTargetKind] = useState<CredentialTargetKind>('web')
  const [targetId, setTargetId] = useState('')
  const [profiles, setProfiles] = useState<CredentialProfile[]>([])
  const [includeInactive, setIncludeInactive] = useState(false)
  const [loading, setLoading] = useState(true)
  const [profilesLoading, setProfilesLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [editorOpen, setEditorOpen] = useState(false)
  const [rotating, setRotating] = useState<CredentialProfile | null>(null)
  const [deactivating, setDeactivating] = useState<CredentialProfile | null>(null)
  const [busy, setBusy] = useState(false)
  const [draft, setDraft] = useState<Draft>(EMPTY_DRAFT)
  const [draftErrors, setDraftErrors] = useState<DraftErrors>({})
  const [editorError, setEditorError] = useState<string | null>(null)
  const [capabilityOptions, setCapabilityOptions] = useState<CredentialCapabilityOption[]>([])
  const [capabilitiesLoading, setCapabilitiesLoading] = useState(false)

  useEffect(() => {
    let cancelled = false
    Promise.all([getTargets({ limit: 500 }), getDevices({ limit: 500 })])
      .then(([web, connected]) => {
        if (cancelled) return
        setTargets(usableWebTargets(web.targets || []))
        setDevices((connected.devices || []).filter((item) => item.is_active))
      })
      .catch((cause) => {
        if (!cancelled) setError(cause instanceof Error ? cause.message : 'Failed to load targets')
      })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [])

  const choices = useMemo(() => targetKind === 'device'
    ? devices.map((item) => ({ id: item.id, label: item.name, detail: item.primary_locator }))
    : targets.map((item) => ({ id: item.id, label: item.name || item.url, detail: item.url })),
  [targetKind, devices, targets])

  useEffect(() => {
    if (targetId && !choices.some((item) => item.id === targetId)) setTargetId('')
  }, [choices, targetId])

  useEffect(() => {
    if (loading || appliedDeepLink.current) return
    appliedDeepLink.current = true
    const params = new URLSearchParams(window.location.search)
    const requestedId = params.get('target_id')?.trim()
    const requestedUrl = params.get('target')?.trim()
    const web = targets.find((item) => item.id === requestedId || (requestedUrl && item.url === requestedUrl))
    const device = devices.find((item) => item.id === requestedId)
    if (web) {
      setTargetKind('web')
      setTargetId(web.id)
    } else if (device) {
      setTargetKind('device')
      setTargetId(device.id)
    }
  }, [devices, loading, targets])

  const loadProfiles = useCallback(async () => {
    if (!targetId) {
      setProfiles([])
      return
    }
    setProfilesLoading(true)
    try {
      const result = await listCredentialProfiles({
        target_kind: targetKind,
        target_id: targetId,
        include_inactive: includeInactive,
      })
      setProfiles(result.profiles || [])
      setError(null)
    } catch (cause) {
      setProfiles([])
      setError(cause instanceof Error ? cause.message : 'Failed to load credential profiles')
    } finally {
      setProfilesLoading(false)
    }
  }, [includeInactive, targetId, targetKind])

  useEffect(() => { void loadProfiles() }, [loadProfiles])

  const availableKinds = targetKind === 'network'
    ? SSH_KINDS
    : targetKind === 'device'
      ? [...HTTP_KINDS, ...SSH_KINDS]
      : HTTP_KINDS

  function openCreate() {
    const firstKind = availableKinds[0]?.value || 'bearer_token'
    setRotating(null)
    setDraft({
      ...EMPTY_DRAFT,
      authKind: firstKind,
      principalSlot: isSsh(firstKind) ? 'ssh' : 'primary',
    })
    setDraftErrors({})
    setEditorError(null)
    setEditorOpen(true)
  }

  useEffect(() => {
    if (!editorOpen || rotating) return
    let cancelled = false
    setCapabilitiesLoading(true)
    listCredentialCapabilities({ target_kind: targetKind, auth_kind: draft.authKind })
      .then((result) => {
        if (cancelled) return
        setCapabilityOptions(result.capabilities || [])
        setDraft((current) => ({
          ...current,
          capabilities: (result.safe_defaults || []).join(', '),
          allowActiveCapabilities: false,
        }))
      })
      .catch((cause) => {
        if (!cancelled) setEditorError(cause instanceof Error ? cause.message : 'Failed to load capability registry')
      })
      .finally(() => { if (!cancelled) setCapabilitiesLoading(false) })
    return () => { cancelled = true }
  }, [draft.authKind, editorOpen, rotating, targetKind])

  function openRotate(profile: CredentialProfile) {
    setRotating(profile)
    setDraft({
      ...EMPTY_DRAFT,
      name: profile.name,
      authKind: profile.auth_kind,
      principalLabel: profile.principal_label || '',
      principalSlot: profile.principal_slot,
      headerName: profile.configuration.parameter_name || profile.configuration.header_name || 'X-API-Key',
      capabilities: profile.allowed_capabilities.join(', '),
    })
    setDraftErrors({})
    setEditorError(null)
    setEditorOpen(true)
  }

  function updateDraft(patch: Partial<Draft>) {
    setDraft((current) => ({ ...current, ...patch }))
    setDraftErrors((current) => {
      const next = { ...current }
      for (const key of Object.keys(patch) as (keyof Draft)[]) delete next[key]
      return next
    })
    setEditorError(null)
  }

  function changeTargetKind(kind: CredentialTargetKind) {
    if (kind === targetKind) return
    // A target ID is meaningful only inside its kind. Clear it in the same
    // event before the profile-loading effect can combine a new kind with the
    // previous kind's ID and surface a misleading 404.
    setTargetId('')
    setProfiles([])
    setError(null)
    setTargetKind(kind)
  }

  async function saveProfile() {
    if (!targetId) return
    const validationErrors = validateDraft(draft, Boolean(rotating))
    if (Object.keys(validationErrors).length) {
      setDraftErrors(validationErrors)
      setEditorError('Complete the highlighted required fields before saving this credential.')
      return
    }
    setEditorError(null)
    setBusy(true)
    try {
      const material = secretPayload(draft)
      if (rotating) {
        await rotateCredentialProfile(rotating.id, {
          ...material,
          expected_record_version: rotating.record_version,
          created_by: 'credentials_ui',
        })
        toast.success('Credential rotated. Existing jobs remain bound to their admitted version.')
      } else {
        await createCredentialProfile({
          ...material,
          target_kind: targetKind,
          target_id: targetId,
          name: draft.name.trim(),
          auth_kind: draft.authKind,
          principal_label: draft.principalLabel.trim() || undefined,
          principal_slot: draft.principalSlot,
          allowed_capabilities: splitValues(draft.capabilities),
          allow_active_capabilities: draft.allowActiveCapabilities,
          created_by: 'credentials_ui',
        })
        toast.success('Encrypted credential profile created')
      }
      setEditorOpen(false)
      await loadProfiles()
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : 'Credential update failed'
      setEditorError(message)
      toast.error(message)
    } finally {
      setBusy(false)
    }
  }

  async function deactivate() {
    if (!deactivating) return
    setBusy(true)
    try {
      await deactivateCredentialProfile(deactivating.id)
      toast.success('Credential profile deactivated')
      setDeactivating(null)
      await loadProfiles()
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : 'Failed to deactivate profile')
    } finally {
      setBusy(false)
    }
  }

  if (loading) return <div className="p-6 text-sm text-gray-400">Loading credential targets…</div>
  if (error && !targets.length && !devices.length) return <ErrorState message={error} />

  return (
    <div className="mx-auto max-w-6xl p-6">
      <PageHeader
        title="Credentials"
        description="Manage encrypted, target-bound identities used by Scan and Hunt. Secret values are accepted only when creating or rotating a profile and are never returned to this screen."
        icon={<KeyRound className="h-6 w-6" />}
        actions={<><Button variant="secondary" onClick={() => void loadProfiles()} disabled={!targetId || profilesLoading}><RefreshCw className="h-4 w-4" /> Refresh</Button><Button onClick={openCreate} disabled={!targetId}><Plus className="h-4 w-4" /> New profile</Button></>}
      />

      <Card className="mb-5 p-5">
        <div className="grid gap-4 md:grid-cols-[180px_minmax(0,1fr)_auto] md:items-end">
          <Field label="Target type">
            <Select value={targetKind} onChange={(event) => changeTargetKind(event.target.value as CredentialTargetKind)}>
              <option value="web">Web</option>
              <option value="api">API</option>
              <option value="network">Network / SSH</option>
              <option value="device">Connected device</option>
            </Select>
          </Field>
          <Field label="Bound target">
            <Select value={targetId} onChange={(event) => setTargetId(event.target.value)}>
              <option value="">{choices.length ? 'Choose a target…' : 'No active targets'}</option>
              {choices.map((item) => <option key={item.id} value={item.id}>{item.label} — {item.detail}</option>)}
            </Select>
          </Field>
          <label className="flex h-10 items-center gap-2 text-sm text-gray-400">
            <input type="checkbox" checked={includeInactive} onChange={(event) => setIncludeInactive(event.target.checked)} />
            Show inactive
          </label>
        </div>
      </Card>

      {error && <div className="mb-4 rounded border border-red-900/60 bg-red-950/30 p-3 text-sm text-red-300">{error}</div>}
      {profilesLoading ? (
        <Card className="p-6 text-sm text-gray-400">Loading profiles…</Card>
      ) : !profiles.length ? (
        <EmptyState
          message={targetId ? 'No credential profiles' : 'Choose a bound target'}
          hint={targetId
            ? 'Create a profile for this exact target. Workers decrypt it only after approval and destination checks pass.'
            : 'Select the exact asset that will be allowed to use this credential. ShakerScan never shares profiles across targets.'}
          action={targetId ? { label: 'Create profile', onClick: openCreate } : undefined}
        />
      ) : (
        <div className="space-y-3">
          {profiles.map((profile) => (
            <Card key={profile.id} className="p-5">
              <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <h2 className="font-semibold text-white">{profile.name}</h2>
                    <span className={`rounded px-2 py-0.5 text-xs ${statusClass(profile)}`}>
                      {profile.refresh_required && profile.status === 'active' ? 'expiring soon' : profile.status}
                    </span>
                    <span className="rounded bg-blue-500/10 px-2 py-0.5 text-xs text-blue-300">{profile.principal_slot}</span>
                  </div>
                  <p className="mt-1 text-sm text-gray-400">
                    {profile.auth_kind.replaceAll('_', ' ')} · version {profile.current_version}
                    {identityComposition(profile) ? ` · ${identityComposition(profile)}` : ''}
                    {profile.principal_label ? ` · ${profile.principal_label}` : ''}
                  </p>
                  <div className="mt-3 flex flex-wrap gap-2 text-xs text-gray-500">
                    {profile.allowed_capabilities.length
                      ? profile.allowed_capabilities.map((item) => <span key={item} className="rounded bg-gray-900 px-2 py-1">{item}</span>)
                      : <span className="rounded bg-amber-500/10 px-2 py-1 text-amber-300">no capabilities · legacy profile is unusable until narrowed explicitly</span>}
                    {profile.expires_at && <span>expires {new Date(profile.expires_at).toLocaleString()}</span>}
                  </div>
                  <p className="mt-3 flex items-center gap-1.5 text-xs text-emerald-400">
                    <ShieldCheck className="h-3.5 w-3.5" /> encrypted storage · secret values hidden
                  </p>
                </div>
                <div className="flex shrink-0 gap-2">
                  {profile.is_active && <Button size="sm" variant="secondary" onClick={() => openRotate(profile)}><RotateCw className="h-4 w-4" /> Rotate</Button>}
                  {profile.is_active && <Button size="sm" variant="ghost" onClick={() => setDeactivating(profile)}><Trash2 className="h-4 w-4" /> Deactivate</Button>}
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}

      <Modal
        open={editorOpen}
        title={rotating ? `Rotate ${rotating.name}` : 'New credential profile'}
        onClose={() => { if (!busy) setEditorOpen(false) }}
        footer={<><Button variant="secondary" disabled={busy} onClick={() => setEditorOpen(false)}>Cancel</Button><Button loading={busy} onClick={() => void saveProfile()}>{rotating ? 'Rotate credential' : 'Create profile'}</Button></>}
      >
        {editorError && (
          <div role="alert" className="mb-4 rounded border border-red-900/60 bg-red-950/30 p-3 text-sm text-red-300">
            {editorError}
          </div>
        )}
        <div className="grid gap-4 sm:grid-cols-2">
          {!rotating && <Field label="Profile name" error={draftErrors.name} required><Input value={draft.name} onChange={(event) => updateDraft({ name: event.target.value })} /></Field>}
          <Field label="Authentication type" required>
            <Select
              value={draft.authKind}
              disabled={Boolean(rotating)}
              onChange={(event) => {
                const kind = event.target.value as CredentialAuthKind
                updateDraft({
                  authKind: kind,
                  principalSlot: isSsh(kind) ? 'ssh' : draft.principalSlot === 'ssh' ? 'primary' : draft.principalSlot,
                  capabilities: '',
                  allowActiveCapabilities: false,
                })
                setDraftErrors({})
              }}
            >
              {availableKinds.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
            </Select>
          </Field>
          {!rotating && <Field label="Principal slot"><Select value={draft.principalSlot} disabled={isSsh(draft.authKind)} onChange={(event) => updateDraft({ principalSlot: event.target.value as CredentialPrincipalSlot })}><option value="primary">Primary</option><option value="secondary">Secondary</option><option value="service">Service</option>{isSsh(draft.authKind) && <option value="ssh">SSH</option>}</Select></Field>}
          {!rotating && <Field label="Principal label"><Input value={draft.principalLabel} onChange={(event) => updateDraft({ principalLabel: event.target.value })} placeholder="Optional human-readable identity" /></Field>}
          {showsUsername(draft.authKind) && <Field label="Username" error={draftErrors.username} required={isSsh(draft.authKind)} hint={isIdentityPair(draft.authKind) ? 'Optional if you supply a secret below.' : undefined}><Input autoComplete="off" value={draft.username} onChange={(event) => updateDraft({ username: event.target.value })} /></Field>}
          {(draft.authKind === 'api_key_header' || draft.authKind === 'query_parameter') && <Field label={draft.authKind === 'query_parameter' ? 'Parameter name' : 'Header name'} error={draftErrors.headerName} required><Input value={draft.headerName} onChange={(event) => updateDraft({ headerName: event.target.value })} /></Field>}
          {needsEndpoint(draft.authKind) && <Field label="Login / token endpoint" error={draftErrors.endpointUrl} required><Input value={draft.endpointUrl} onChange={(event) => updateDraft({ endpointUrl: event.target.value })} placeholder="/login or https://target/token" /></Field>}
          {(draft.authKind === 'oauth_client_credentials' || draft.authKind === 'oauth_password') && <Field label={draft.authKind === 'oauth_client_credentials' ? 'Client ID' : 'Client ID (required for Scan)'} error={draftErrors.clientId} required={draft.authKind === 'oauth_client_credentials'}><Input autoComplete="off" value={draft.clientId} onChange={(event) => updateDraft({ clientId: event.target.value })} /></Field>}
          {(draft.authKind === 'oauth_client_credentials' || draft.authKind === 'oauth_password') && <Field label="OAuth scopes"><Input value={draft.scopes} onChange={(event) => updateDraft({ scopes: event.target.value })} placeholder="openid profile" /></Field>}
          {draft.authKind !== 'custom_headers' && (draft.authKind === 'ssh_private_key' || draft.authKind === 'ssh_private_key_with_passphrase' ? (
            <Field className="sm:col-span-2" label="Private key" error={draftErrors.secret} required><Textarea rows={7} value={draft.secret} onChange={(event) => updateDraft({ secret: event.target.value })} /></Field>
          ) : (
            <Field className="sm:col-span-2" label={draft.authKind === 'authorization_header' ? 'Full Authorization value' : draft.authKind === 'cookie' ? 'Cookie value' : 'Secret'} error={draftErrors.secret} required={!isIdentityPair(draft.authKind)} hint={isIdentityPair(draft.authKind) ? 'Optional if you supply a username above.' : undefined}><Input type="password" autoComplete="new-password" value={draft.secret} onChange={(event) => updateDraft({ secret: event.target.value })} /></Field>
          ))}
          {draft.authKind === 'ssh_private_key_with_passphrase' && <Field className="sm:col-span-2" label="Key passphrase" error={draftErrors.secondarySecret} required><Input type="password" autoComplete="new-password" value={draft.secondarySecret} onChange={(event) => updateDraft({ secondarySecret: event.target.value })} /></Field>}
          {draft.authKind === 'custom_headers' && <Field className="sm:col-span-2" label="Headers" hint="One Name: value pair per line. Values are encrypted and will not be shown again." error={draftErrors.customHeaders} required><Textarea rows={6} value={draft.customHeaders} onChange={(event) => updateDraft({ customHeaders: event.target.value })} /></Field>}
          <Field label="Expires at"><Input type="datetime-local" value={draft.expiresAt} onChange={(event) => updateDraft({ expiresAt: event.target.value })} /></Field>
          {!rotating && (
            <div className="sm:col-span-2 rounded-lg border border-gray-800 bg-gray-950 p-3">
              <p className="text-sm font-medium text-gray-200">Allowed capabilities</p>
              <p className="mt-1 text-xs text-gray-500">
                Selected from the canonical registry. No selection resolves to the server&apos;s safe defaults, never unrestricted access.
              </p>
              {capabilitiesLoading ? (
                <p className="mt-3 text-xs text-gray-500">Loading canonical capabilities…</p>
              ) : (
                <div className="mt-3 space-y-2">
                  {capabilityOptions.map((capability) => {
                    const selected = splitValues(draft.capabilities).includes(capability.name)
                    return (
                      <label key={capability.name} className="flex items-start gap-3 rounded border border-gray-800 p-2 text-xs text-gray-300">
                        <input
                          type="checkbox"
                          checked={selected}
                          onChange={(event) => {
                            const values = new Set(splitValues(draft.capabilities))
                            if (event.target.checked) values.add(capability.name)
                            else values.delete(capability.name)
                            updateDraft({ capabilities: Array.from(values).sort().join(', ') })
                          }}
                          className="mt-1"
                        />
                        <span className="min-w-0 flex-1">
                          <span className="flex flex-wrap items-center gap-2">
                            <code>{capability.name}</code>
                            <span className={`rounded px-1.5 py-0.5 ${capability.requires_active_approval ? 'bg-amber-500/10 text-amber-300' : 'bg-emerald-500/10 text-emerald-300'}`}>
                              {capability.risk_tier}
                            </span>
                            {capability.default && <span className="text-blue-300">safe default</span>}
                          </span>
                          <span className="mt-1 block text-gray-500">{capability.description}</span>
                        </span>
                      </label>
                    )
                  })}
                </div>
              )}
              {capabilityOptions.some((item) => item.requires_active_approval && splitValues(draft.capabilities).includes(item.name)) && (
                <label className="mt-3 flex items-start gap-2 rounded border border-amber-700/50 bg-amber-500/10 p-2 text-xs text-amber-100">
                  <input type="checkbox" checked={draft.allowActiveCapabilities} onChange={(event) => updateDraft({ allowActiveCapabilities: event.target.checked })} className="mt-0.5" />
                  I explicitly elevate this profile for the selected active capabilities. Runtime policy and target-bound approval are still required.
                </label>
              )}
            </div>
          )}
        </div>
        <p className="mt-5 text-xs text-gray-500">The secret is sent once over the local API, encrypted before storage, and resolved only inside an authorized worker action.</p>
      </Modal>

      <ConfirmDialog
        open={Boolean(deactivating)}
        title="Deactivate credential profile?"
        message="New Scan and Hunt actions will no longer be able to resolve this profile. Historical receipts remain intact."
        confirmLabel="Deactivate"
        danger
        busy={busy}
        onConfirm={() => void deactivate()}
        onCancel={() => setDeactivating(null)}
      />
    </div>
  )
}
