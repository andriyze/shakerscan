'use client'

import { useCallback, useEffect, useState } from 'react'
import { Pencil, Plus, Power, ShieldCheck, Trash2 } from 'lucide-react'
import { createDevicePolicy, getDevicePolicies, updateDevicePolicy, type DevicePolicy, type DevicePolicyRule } from '@/lib/api'
import { Button, Card, EmptyState, ErrorState, Field, Input, Modal, PageHeader, Select, Textarea, useToast } from '@/components/ui'

type EditableRule = DevicePolicyRule & { portsText: string }

const newRule = (): EditableRule => ({ action: 'deny', transport: 'tcp', service: 'any', portsText: '', severity: 'high', reason: '' })

export default function DevicePoliciesPage() {
  const toast = useToast()
  const [policies, setPolicies] = useState<DevicePolicy[]>([])
  const [loading, setLoading] = useState(true)
  const [failed, setFailed] = useState(false)
  const [open, setOpen] = useState(false)
  const [editingPolicy, setEditingPolicy] = useState<DevicePolicy | null>(null)
  const [saving, setSaving] = useState(false)
  const [form, setForm] = useState({ name: '', description: '', device_class: 'generic', environment: 'production' })
  const [rules, setRules] = useState<EditableRule[]>([newRule()])

  const load = useCallback(async () => {
    try { setPolicies((await getDevicePolicies(true)).policies || []); setFailed(false) } catch { setFailed(true) } finally { setLoading(false) }
  }, [])
  useEffect(() => { load() }, [load])

  function updateRule(index: number, patch: Partial<EditableRule>) {
    setRules((current) => current.map((rule, i) => i === index ? { ...rule, ...patch } : rule))
  }

  function openCreate() {
    setEditingPolicy(null)
    setForm({ name: '', description: '', device_class: 'generic', environment: 'production' })
    setRules([newRule()])
    setOpen(true)
  }

  function openEdit(policy: DevicePolicy) {
    setEditingPolicy(policy)
    setForm({
      name: policy.name,
      description: policy.description || '',
      device_class: policy.device_class,
      environment: policy.environment,
    })
    setRules(policy.rules.map((rule) => ({ ...rule, portsText: rule.ports?.join(', ') || '' })))
    setOpen(true)
  }

  async function save() {
    setSaving(true)
    try {
      const normalized: DevicePolicyRule[] = rules.map(({ portsText, ...rule }, index) => {
        const segments = portsText === '' ? [] : portsText.split(',').map((value) => value.trim())
        if (segments.some((value) => !/^\d+$/.test(value))) throw new Error(`Rule ${index + 1}: ports must be comma-separated whole numbers without empty entries`)
        const ports = segments.map(Number)
        if (ports.some((value) => value < 1 || value > 65535)) throw new Error(`Rule ${index + 1}: ports must be between 1 and 65535`)
        return {
          ...rule,
          ports: ports.length ? ports : undefined,
          service: rule.service?.trim().toLowerCase() || 'any',
          reason: rule.reason?.trim() || undefined,
        }
      })
      if (editingPolicy) await updateDevicePolicy(editingPolicy.id, { ...form, rules: normalized })
      else await createDevicePolicy({ ...form, rules: normalized })
      setOpen(false)
      setForm({ name: '', description: '', device_class: 'generic', environment: 'production' })
      setRules([newRule()])
      toast.success(editingPolicy ? 'Device service policy updated' : 'Device service policy created')
      await load()
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to create policy')
    } finally { setSaving(false) }
  }

  async function togglePolicy(policy: DevicePolicy) {
    try {
      await updateDevicePolicy(policy.id, { is_active: !policy.is_active })
      toast.success(policy.is_active ? 'Device policy deactivated' : 'Device policy activated')
      await load()
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to update policy')
    }
  }

  return (
    <div className="mx-auto max-w-6xl">
      <PageHeader backHref="/devices" backLabel="Connected devices" title="Device Service Policies" description="Define which listening services are expected, forbidden, or require review for each class of connected device." icon={<ShieldCheck className="h-6 w-6" />} actions={<Button onClick={openCreate}><Plus className="h-4 w-4" /> New policy</Button>} />
      {loading ? <p className="text-sm text-gray-500">Loading policies…</p> : failed ? <ErrorState message="Could not load device policies" onRetry={load} /> : policies.length === 0 ? <EmptyState message="No device policies" hint="Create a service allowlist and deny policy for connected devices." /> : (
        <div className="space-y-4">{policies.map((policy) => <Card key={policy.id} className="p-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between"><div><div className="flex items-center gap-2"><h2 className="font-semibold text-white">{policy.name}</h2>{policy.is_builtin && <span className="rounded-full bg-blue-500/15 px-2 py-0.5 text-[10px] uppercase text-blue-300">Built in</span>}{!policy.is_active && <span className="rounded-full bg-gray-700 px-2 py-0.5 text-[10px] uppercase text-gray-400">Inactive</span>}</div><p className="mt-1 text-sm text-gray-400">{policy.description || 'No description'}</p></div><div className="flex items-center gap-2"><span className="mr-2 text-xs text-gray-500">{policy.device_class} · {policy.environment} · {policy.rules.length} rules</span>{!policy.is_builtin && <Button size="sm" variant="secondary" onClick={() => openEdit(policy)}><Pencil className="h-3.5 w-3.5" /> Edit</Button>}<Button size="sm" variant="ghost" disabled={policy.is_builtin} title={policy.is_builtin ? 'Built-in safety policies cannot be deactivated' : undefined} onClick={() => togglePolicy(policy)}><Power className="h-3.5 w-3.5" /> {policy.is_active ? 'Deactivate' : 'Activate'}</Button></div></div>
          <div className="mt-4 overflow-x-auto"><table className="w-full text-left text-xs"><thead className="text-gray-600"><tr><th className="pb-2">Decision</th><th className="pb-2">Transport</th><th className="pb-2">Service</th><th className="pb-2">Ports</th><th className="pb-2">Reason</th></tr></thead><tbody className="divide-y divide-gray-800">{policy.rules.map((rule, index) => <tr key={index}><td className="py-2 font-medium text-gray-200">{rule.action}</td><td className="py-2 text-gray-400">{rule.transport || 'any'}</td><td className="py-2 text-gray-400">{rule.service || 'any'}</td><td className="py-2 font-mono text-gray-400">{rule.ports?.join(', ') || 'any'}</td><td className="py-2 text-gray-500">{rule.reason || '—'}</td></tr>)}</tbody></table></div>
        </Card>)}</div>
      )}

      <Modal open={open} title={editingPolicy ? 'Edit device service policy' : 'New device service policy'} size="xl" onClose={() => setOpen(false)} footer={<><Button variant="secondary" onClick={() => setOpen(false)}>Cancel</Button><Button loading={saving} disabled={!form.name.trim() || rules.length === 0} onClick={save}>{editingPolicy ? 'Save changes' : 'Create policy'}</Button></>}>
        <div className="space-y-5">
          <div className="grid gap-4 sm:grid-cols-3"><Field label="Policy name" required><Input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="Conference rooms — production" /></Field><Field label="Device class"><Input value={form.device_class} onChange={(event) => setForm({ ...form, device_class: event.target.value })} placeholder="conference" /></Field><Field label="Environment"><Select value={form.environment} onChange={(event) => setForm({ ...form, environment: event.target.value })}><option value="production">Production</option><option value="staging">Staging</option><option value="lab">Lab</option><option value="development">Development</option></Select></Field></div>
          <Field label="Description"><Textarea rows={2} value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} placeholder="What this service policy protects" /></Field>
          <div className="flex items-center justify-between"><div><h3 className="font-medium text-white">Service rules</h3><p className="text-xs text-gray-500">Rules are evaluated from top to bottom. Unmatched listening services require review.</p></div><Button size="sm" variant="secondary" onClick={() => setRules((current) => [...current, newRule()])}><Plus className="h-3.5 w-3.5" /> Add rule</Button></div>
          <div className="space-y-3">{rules.map((rule, index) => <div key={index} className="rounded-lg border border-gray-800 bg-gray-950 p-3">
            <div className="mb-3 flex items-center justify-between"><span className="text-xs font-medium text-gray-400">Rule {index + 1}</span><Button size="sm" variant="ghost" disabled={rules.length === 1} onClick={() => setRules((current) => current.filter((_, i) => i !== index))}><Trash2 className="h-3.5 w-3.5" /> Remove</Button></div>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-6"><Field label="Decision"><Select value={rule.action} onChange={(event) => updateRule(index, { action: event.target.value as EditableRule['action'] })}><option value="allow">Allow</option><option value="deny">Deny</option><option value="review">Review</option><option value="require">Require controls</option></Select></Field><Field label="Transport"><Select value={rule.transport} onChange={(event) => updateRule(index, { transport: event.target.value as EditableRule['transport'] })}><option value="any">Any</option><option value="tcp">TCP</option><option value="udp">UDP</option></Select></Field><Field label="Service"><Input value={rule.service || ''} onChange={(event) => updateRule(index, { service: event.target.value })} placeholder="ssh, https, unknown" /></Field><Field label="Ports" hint="Comma separated; blank means any"><Input value={rule.portsText} onChange={(event) => updateRule(index, { portsText: event.target.value })} placeholder="22, 2222" /></Field><Field label="Encryption"><Select value={rule.encrypted === undefined ? 'any' : rule.encrypted ? 'required' : 'cleartext'} onChange={(event) => updateRule(index, { encrypted: event.target.value === 'any' ? undefined : event.target.value === 'required' })}><option value="any">Any</option><option value="required">Encrypted</option><option value="cleartext">Cleartext</option></Select></Field><Field label="Severity"><Select value={rule.severity || 'medium'} onChange={(event) => updateRule(index, { severity: event.target.value as EditableRule['severity'] })}><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="info">Info</option></Select></Field></div>
            {rule.action === 'require' && <div className="mt-3 flex flex-wrap gap-4 rounded border border-gray-800 bg-gray-900/60 p-3 text-xs text-gray-300"><span className="font-medium text-white">Required controls</span><label className="flex items-center gap-2"><input type="checkbox" checked={rule.requirements?.password_auth === false} onChange={(event) => updateRule(index, { requirements: { ...rule.requirements, password_auth: event.target.checked ? false : undefined } })} /> Disable SSH password auth</label><label className="flex items-center gap-2"><input type="checkbox" checked={rule.requirements?.weak_algorithms === false} onChange={(event) => updateRule(index, { requirements: { ...rule.requirements, weak_algorithms: event.target.checked ? false : undefined } })} /> No weak SSH algorithms</label><label className="flex items-center gap-2"><input type="checkbox" checked={rule.requirements?.publickey_auth === true} onChange={(event) => updateRule(index, { requirements: { ...rule.requirements, publickey_auth: event.target.checked ? true : undefined } })} /> Require public-key auth</label></div>}
            <Field className="mt-3" label="Reason shown to the operator"><Input value={rule.reason || ''} onChange={(event) => updateRule(index, { reason: event.target.value })} placeholder="Remote administration is allowed only on the management network." /></Field>
          </div>)}</div>
        </div>
      </Modal>
    </div>
  )
}
