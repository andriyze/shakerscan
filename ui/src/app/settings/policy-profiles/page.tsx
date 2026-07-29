'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import { Edit3, Plus, RefreshCw, Save, ShieldCheck, Trash2, X } from 'lucide-react'
import {
  createPolicyProfile,
  deletePolicyProfile,
  getModelIntakeTrustAnchors,
  getPolicyProfiles,
  updatePolicyProfile,
  type ModelIntakeTrustAnchor,
  type PolicyProfile,
  type PolicyProfilePayload,
} from '@/lib/api'
import { Button, Card, ConfirmDialog, ErrorState, PageHeader, SectionCard, fieldClasses, useToast } from '@/components/ui'

// Point the local field class at the shared field styling so every input/select
// here matches the rest of the app and gets a real focus ring.
const inputClass = `w-full ${fieldClasses()}`
const selectClass = inputClass

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']
const PRODUCT_AREAS = ['ai_gate', 'model_intake', 'dast']
const MODEL_INTAKE_OPERATOR_TOKEN_KEY = 'shakerscan:model-intake-operator-token'

interface ProfileFormState {
  id?: string
  name: string
  product_area: string
  environment: string
  minimum_block_severity: string
  expires_days: string
  strict_model_intake: boolean
  allow_active_exceptions: boolean
  required_trust_anchor_ids: string[]
  owner: string
  version: string
  is_active: boolean
}

const EMPTY_FORM: ProfileFormState = {
  name: '',
  product_area: 'model_intake',
  environment: 'production',
  minimum_block_severity: 'high',
  expires_days: '30',
  strict_model_intake: false,
  allow_active_exceptions: true,
  required_trust_anchor_ids: [],
  owner: '',
  version: '',
  is_active: true,
}

function profileToForm(profile: PolicyProfile): ProfileFormState {
  return {
    id: profile.id,
    name: profile.name || '',
    product_area: profile.product_area || 'model_intake',
    environment: profile.environment || 'production',
    minimum_block_severity: profile.minimum_block_severity || 'high',
    expires_days: String(profile.expires_days ?? 30),
    strict_model_intake: Boolean(profile.strict_model_intake),
    allow_active_exceptions: Boolean(profile.allow_active_exceptions),
    required_trust_anchor_ids: profile.required_trust_anchor_ids || [],
    owner: profile.owner || '',
    version: profile.version || '',
    is_active: Boolean(profile.is_active),
  }
}

function formToPayload(form: ProfileFormState): PolicyProfilePayload {
  const expiresDays = Number(form.expires_days || 30)
  if (!form.name.trim()) throw new Error('Name is required')
  if (!form.environment.trim()) throw new Error('Environment is required')
  if (!Number.isFinite(expiresDays) || expiresDays < 1) throw new Error('Exception expiry must be at least 1 day')
  return {
    name: form.name.trim(),
    product_area: form.product_area,
    environment: form.environment.trim().toLowerCase(),
    minimum_block_severity: form.minimum_block_severity,
    expires_days: Math.round(expiresDays),
    strict_model_intake: form.strict_model_intake,
    allow_active_exceptions: form.allow_active_exceptions,
    required_trust_anchor_ids: form.product_area === 'model_intake' && form.strict_model_intake
      ? form.required_trust_anchor_ids
      : [],
    owner: form.owner.trim() || null,
    version: form.version.trim() || null,
    is_active: form.is_active,
  }
}

function fmt(value?: string | null) {
  return value && value.trim() ? value : 'unassigned'
}

export default function PolicyProfilesPage() {
  const toast = useToast()
  const [profiles, setProfiles] = useState<PolicyProfile[]>([])
  const [loading, setLoading] = useState(true)
  const [trustAnchors, setTrustAnchors] = useState<ModelIntakeTrustAnchor[]>([])
  const [trustAnchorsError, setTrustAnchorsError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [form, setForm] = useState<ProfileFormState>(EMPTY_FORM)
  const [deleteTarget, setDeleteTarget] = useState<PolicyProfile | null>(null)
  const [operatorToken, setOperatorToken] = useState('')

  useEffect(() => {
    setOperatorToken(sessionStorage.getItem(MODEL_INTAKE_OPERATOR_TOKEN_KEY) || '')
  }, [])

  function updateOperatorToken(value: string) {
    setOperatorToken(value)
    if (value) sessionStorage.setItem(MODEL_INTAKE_OPERATOR_TOKEN_KEY, value)
    else sessionStorage.removeItem(MODEL_INTAKE_OPERATOR_TOKEN_KEY)
  }

  const loadProfiles = useCallback(async () => {
    setLoading(true)
    try {
      const result = await getPolicyProfiles()
      setProfiles(result.policy_profiles || [])
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load policy profiles')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadProfiles()
  }, [loadProfiles])

  const loadTrustAnchors = useCallback(async () => {
    try {
      const result = await getModelIntakeTrustAnchors(true)
      setTrustAnchors(result.trust_anchors || [])
      setTrustAnchorsError(null)
    } catch (err) {
      setTrustAnchors([])
      setTrustAnchorsError(err instanceof Error ? err.message : 'Failed to load Model Intake trust anchors')
    }
  }, [])

  useEffect(() => {
    loadTrustAnchors()
  }, [loadTrustAnchors])

  const activeCount = useMemo(() => profiles.filter((profile) => profile.is_active).length, [profiles])
  const modelIntakeCount = useMemo(
    () => profiles.filter((profile) => profile.product_area === 'model_intake').length,
    [profiles]
  )

  function updateForm<K extends keyof ProfileFormState>(key: K, value: ProfileFormState[K]) {
    setForm((prev) => ({ ...prev, [key]: value }))
  }

  function toggleRequiredAnchor(anchorId: string, checked: boolean) {
    setForm((prev) => ({
      ...prev,
      required_trust_anchor_ids: checked
        ? Array.from(new Set([...prev.required_trust_anchor_ids, anchorId]))
        : prev.required_trust_anchor_ids.filter((id) => id !== anchorId),
    }))
  }

  function anchorLabel(anchorId: string) {
    const anchor = trustAnchors.find((item) => item.id === anchorId)
    if (!anchor) return anchorId.slice(0, 8)
    const fp = anchor.public_key_sha256 ? ` · ${anchor.public_key_sha256.slice(0, 12)}...` : ' · PEM'
    return `${anchor.name}${fp}`
  }

  async function saveProfile(event: React.FormEvent) {
    event.preventDefault()
    setSaving(true)
    try {
      const payload = formToPayload(form)
      if (form.id) {
        const updated = await updatePolicyProfile(form.id, payload, operatorToken.trim())
        setProfiles((prev) => prev.map((profile) => (profile.id === updated.id ? updated : profile)))
        toast.success('Policy profile updated')
      } else {
        const created = await createPolicyProfile(payload, operatorToken.trim())
        setProfiles((prev) => [created, ...prev])
        toast.success('Policy profile created')
      }
      setForm(EMPTY_FORM)
      setError(null)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to save policy profile'
      setError(message)
      toast.error(message)
    } finally {
      setSaving(false)
    }
  }

  async function confirmDelete() {
    if (!deleteTarget) return
    try {
      await deletePolicyProfile(deleteTarget.id, operatorToken.trim())
      setProfiles((prev) => prev.filter((profile) => profile.id !== deleteTarget.id))
      toast.success('Policy profile deleted')
      if (form.id === deleteTarget.id) setForm(EMPTY_FORM)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to delete policy profile')
    } finally {
      setDeleteTarget(null)
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Policy Profiles"
        description="Deployment gate policies used by AI Gate, Model Intake, and CI/CD decisions."
        icon={<ShieldCheck className="h-6 w-6" />}
        actions={
          <Button variant="secondary" onClick={loadProfiles} disabled={loading}>
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        }
      />

      {error && <div role="alert" className="rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-sm text-red-300">{error}</div>}

      <Card className="p-4">
        <label className="block text-sm text-gray-300">
          Model Intake operator token
          <input
            type="password"
            autoComplete="off"
            value={operatorToken}
            onChange={(event) => updateOperatorToken(event.target.value)}
            className={`${inputClass} mt-2`}
            placeholder="Required for remote create, update, and delete"
          />
        </label>
        <div className="mt-2 text-xs text-gray-500">Kept only in this browser session. Loopback administration does not require a token.</div>
      </Card>

      <div className="grid gap-3 sm:grid-cols-3">
        <Card className="p-4">
          <div className="text-xs text-gray-500">Profiles</div>
          <div className="mt-1 text-2xl font-semibold text-white">{profiles.length}</div>
        </Card>
        <Card className="p-4">
          <div className="text-xs text-gray-500">Active</div>
          <div className="mt-1 text-2xl font-semibold text-green-300">{activeCount}</div>
        </Card>
        <Card className="p-4">
          <div className="text-xs text-gray-500">Model Intake</div>
          <div className="mt-1 text-2xl font-semibold text-cyan-300">{modelIntakeCount}</div>
        </Card>
      </div>

      <form onSubmit={saveProfile} className="rounded-lg border border-gray-800 bg-gray-900 p-4">
        <div className="mb-4 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-sm font-medium text-white">
            {form.id ? <Edit3 className="h-4 w-4 text-blue-300" /> : <Plus className="h-4 w-4 text-blue-300" />}
            {form.id ? 'Edit Profile' : 'Create Profile'}
          </div>
          {form.id && (
            <button
              type="button"
              onClick={() => setForm(EMPTY_FORM)}
              className="inline-flex items-center gap-1 rounded border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-800"
            >
              <X className="h-3.5 w-3.5" />
              Cancel edit
            </button>
          )}
        </div>

        <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4">
          <label className="grid gap-1 text-sm text-gray-300">
            Name
            <input value={form.name} onChange={(e) => updateForm('name', e.target.value)} className={inputClass} required placeholder="Production strict" />
          </label>
          <label className="grid gap-1 text-sm text-gray-300">
            Product
            <select value={form.product_area} onChange={(e) => updateForm('product_area', e.target.value)} className={selectClass}>
              {PRODUCT_AREAS.map((area) => <option key={area} value={area}>{area.replace(/_/g, ' ')}</option>)}
            </select>
          </label>
          <label className="grid gap-1 text-sm text-gray-300">
            Environment
            <input value={form.environment} onChange={(e) => updateForm('environment', e.target.value)} className={inputClass} required placeholder="production" />
          </label>
          <label className="grid gap-1 text-sm text-gray-300">
            Block severity
            <select value={form.minimum_block_severity} onChange={(e) => updateForm('minimum_block_severity', e.target.value)} className={selectClass}>
              {SEVERITIES.map((severity) => <option key={severity} value={severity}>{severity}</option>)}
            </select>
          </label>
        </div>

        <div className="mt-3 grid gap-3 md:grid-cols-2 lg:grid-cols-4">
          <label className="grid gap-1 text-sm text-gray-300">
            Exception expiry days
            <input value={form.expires_days} onChange={(e) => updateForm('expires_days', e.target.value)} className={inputClass} inputMode="numeric" />
          </label>
          <label className="grid gap-1 text-sm text-gray-300">
            Owner
            <input value={form.owner} onChange={(e) => updateForm('owner', e.target.value)} className={inputClass} placeholder="security" />
          </label>
          <label className="grid gap-1 text-sm text-gray-300">
            Version
            <input value={form.version} onChange={(e) => updateForm('version', e.target.value)} className={inputClass} placeholder="v1" />
          </label>
          <div className="grid gap-2 pt-6 text-sm text-gray-300">
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={form.is_active} onChange={(e) => updateForm('is_active', e.target.checked)} className="h-4 w-4 rounded border-gray-700 bg-gray-800" />
              Active
            </label>
          </div>
        </div>

        <div className="mt-3 grid gap-2 sm:grid-cols-2">
          <label className="flex items-center gap-2 text-sm text-gray-300">
            <input type="checkbox" checked={form.strict_model_intake} onChange={(e) => updateForm('strict_model_intake', e.target.checked)} className="h-4 w-4 rounded border-gray-700 bg-gray-800" />
            Strict Model Intake
          </label>
          <label className="flex items-center gap-2 text-sm text-gray-300">
            <input type="checkbox" checked={form.allow_active_exceptions} onChange={(e) => updateForm('allow_active_exceptions', e.target.checked)} className="h-4 w-4 rounded border-gray-700 bg-gray-800" />
            Allow active exceptions
          </label>
        </div>

        {form.product_area === 'model_intake' && form.strict_model_intake && (
          <div className="mt-4 rounded-lg border border-gray-800 bg-gray-950 p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <div className="text-sm font-medium text-gray-200">Required Model Intake trust anchors</div>
                <div className="mt-1 text-xs text-gray-500">
                  Strict scans using this profile automatically include these saved operator roots.
                </div>
              </div>
              <button
                type="button"
                onClick={loadTrustAnchors}
                className="rounded border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-800"
              >
                Refresh anchors
              </button>
            </div>
            {trustAnchorsError && <div role="alert" className="mt-3 text-xs text-red-400">{trustAnchorsError}</div>}
            {trustAnchors.length === 0 ? (
              <div className="mt-3 rounded border border-gray-800 bg-gray-900 p-3 text-sm text-gray-500">
                No active saved trust anchors. Create anchors in Model Intake, then bind them here.
              </div>
            ) : (
              <div className="mt-3 grid gap-2 md:grid-cols-2">
                {trustAnchors.map((anchor) => {
                  const selected = form.required_trust_anchor_ids.includes(anchor.id)
                  return (
                    <label
                      key={anchor.id}
                      className={`flex min-w-0 items-start gap-2 rounded border p-3 text-sm ${
                        selected ? 'border-cyan-500 bg-cyan-950/30 text-cyan-100' : 'border-gray-800 bg-gray-900 text-gray-300'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={selected}
                        onChange={(e) => toggleRequiredAnchor(anchor.id, e.target.checked)}
                        className="mt-0.5 h-4 w-4 rounded border-gray-700 bg-gray-800"
                      />
                      <span className="min-w-0">
                        <span className="block break-words font-medium">{anchor.name}</span>
                        <span className="mt-1 block break-words text-xs text-gray-500">
                          {anchor.policy_profile || 'any profile'}{anchor.owner ? ` · ${anchor.owner}` : ''}{anchor.public_key_sha256 ? ` · ${anchor.public_key_sha256.slice(0, 12)}...` : ' · PEM anchor'}
                        </span>
                      </span>
                    </label>
                  )
                })}
              </div>
            )}
          </div>
        )}

        <div className="mt-4 flex justify-end">
          <Button type="submit" disabled={saving}>
            <Save className="h-4 w-4" />
            {saving ? 'Saving...' : form.id ? 'Save Profile' : 'Create Profile'}
          </Button>
        </div>
      </form>

      <SectionCard title="Profiles">
        {loading ? (
          <div className="py-8 text-center text-sm text-gray-500">Loading profiles...</div>
        ) : profiles.length === 0 ? (
          <div className="rounded-lg border border-gray-800 bg-gray-950 p-4 text-sm text-gray-500">No policy profiles yet.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-800 text-sm">
              <thead className="text-left text-xs uppercase text-gray-500">
                <tr>
                  <th className="px-3 py-2">Name</th>
                  <th className="px-3 py-2">Product</th>
                  <th className="px-3 py-2">Environment</th>
                  <th className="px-3 py-2">Gate</th>
                  <th className="px-3 py-2">Owner</th>
                  <th className="px-3 py-2">Status</th>
                  <th className="px-3 py-2 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {profiles.map((profile) => (
                  <tr key={profile.id} className="text-gray-300">
                    <td className="px-3 py-3">
                      <div className="font-medium text-white">{profile.name}</div>
                      <div className="text-xs text-gray-500">{fmt(profile.version)}</div>
                    </td>
                    <td className="px-3 py-3">{profile.product_area.replace(/_/g, ' ')}</td>
                    <td className="px-3 py-3 font-mono text-xs">{profile.environment}</td>
                    <td className="px-3 py-3">
                      <div className="text-xs">block {profile.minimum_block_severity}+</div>
                      <div className="text-xs text-gray-500">{profile.expires_days}d exception expiry</div>
                      {profile.strict_model_intake && <div className="mt-1 text-xs text-cyan-300">strict intake</div>}
                      {profile.strict_model_intake && (profile.required_trust_anchor_ids || []).length > 0 && (
                        <div className="mt-1 text-xs text-cyan-200">
                          {(profile.required_trust_anchor_ids || []).length} required anchor{(profile.required_trust_anchor_ids || []).length === 1 ? '' : 's'}
                        </div>
                      )}
                    </td>
                    <td className="px-3 py-3">{fmt(profile.owner)}</td>
                    <td className="px-3 py-3">
                      {profile.strict_model_intake && (profile.required_trust_anchor_ids || []).length > 0 && (
                        <div className="mb-2 max-w-xs space-y-1 text-xs text-gray-500">
                          {(profile.required_trust_anchor_ids || []).slice(0, 2).map((anchorId) => (
                            <div key={anchorId} className="truncate">{anchorLabel(anchorId)}</div>
                          ))}
                          {(profile.required_trust_anchor_ids || []).length > 2 && (
                            <div>+{(profile.required_trust_anchor_ids || []).length - 2} more</div>
                          )}
                        </div>
                      )}
                      <span className={`rounded px-2 py-1 text-xs ${profile.is_active ? 'bg-green-900/50 text-green-200' : 'bg-gray-800 text-gray-400'}`}>
                        {profile.is_active ? 'active' : 'inactive'}
                      </span>
                    </td>
                    <td className="px-3 py-3">
                      <div className="flex justify-end gap-2">
                        <button
                          type="button"
                          onClick={() => setForm(profileToForm(profile))}
                          className="rounded border border-gray-700 p-2 text-gray-300 hover:bg-gray-800"
                          aria-label={`Edit ${profile.name}`}
                        >
                          <Edit3 className="h-4 w-4" />
                        </button>
                        <button
                          type="button"
                          onClick={() => setDeleteTarget(profile)}
                          className="rounded border border-red-900/70 p-2 text-red-300 hover:bg-red-950/40"
                          aria-label={`Delete ${profile.name}`}
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </SectionCard>

      <ConfirmDialog
        open={Boolean(deleteTarget)}
        title="Delete policy profile"
        message={deleteTarget ? `Delete ${deleteTarget.name}? Existing scan history is not changed, but future deployment decisions will no longer use this profile.` : ''}
        confirmLabel="Delete"
        danger
        onConfirm={confirmDelete}
        onCancel={() => setDeleteTarget(null)}
      />
    </div>
  )
}
