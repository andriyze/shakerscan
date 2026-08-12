'use client'

import { useCallback, useEffect, useState } from 'react'
import { Plus, ShieldCheck, Trash2 } from 'lucide-react'
import { createDevicePolicy, getDevicePolicies, type DevicePolicy, type DevicePolicyRule } from '@/lib/api'
import { Button, Card, EmptyState, ErrorState, Field, Input, Modal, PageHeader, Select, Textarea, useToast } from '@/components/ui'

type EditableRule = DevicePolicyRule & { portsText: string }

const newRule = (): EditableRule => ({ action: 'deny', transport: 'tcp', service: 'any', portsText: '', severity: 'high', reason: '' })

export default function DevicePoliciesPage() {
  const toast = useToast()
  const [policies, setPolicies] = useState<DevicePolicy[]>([])
  const [loading, setLoading] = useState(true)
  const [failed, setFailed] = useState(false)
  const [open, setOpen] = useState(false)
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

  async function save() {
    setSaving(true)
    try {
      const normalized: DevicePolicyRule[] = rules.map(({ portsText, ...rule }) => ({
        ...rule,
        ports: portsText.trim() ? portsText.split(',').map((value) => Number(value.trim())).filter((value) => Number.isInteger(value)) : undefined,
        service: rule.service?.trim().toLowerCase() || 'any',
        reason: rule.reason?.trim() || undefined,
      }))
      await createDevicePolicy({ ...form, rules: normalized })
      setOpen(false)
      setForm({ name: '', description: '', device_class: 'generic', environment: 'production' })
      setRules([newRule()])
      toast.success('Device service policy created')
      await load()
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to create policy')
    } finally { setSaving(false) }
  }

  return (
    <div className="mx-auto max-w-6xl">
      <PageHeader backHref="/devices" backLabel="Connected devices" title="Device Service Policies" description="Define which listening services are expected, forbidden, or require review for each class of connected device." icon={<ShieldCheck className="h-6 w-6" />} actions={<Button onClick={() => setOpen(true)}><Plus className="h-4 w-4" /> New policy</Button>} />
      {loading ? <p className="text-sm text-gray-500">Loading policies…</p> : failed ? <ErrorState message="Could not load device policies" onRetry={load} /> : policies.length === 0 ? <EmptyState message="No device policies" hint="Create a service allowlist and deny policy for connected devices." /> : (
        <div className="space-y-4">{policies.map((policy) => <Card key={policy.id} className="p-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between"><div><div className="flex items-center gap-2"><h2 className="font-semibold text-white">{policy.name}</h2>{policy.is_builtin && <span className="rounded-full bg-blue-500/15 px-2 py-0.5 text-[10px] uppercase text-blue-300">Built in</span>}{!policy.is_active && <span className="rounded-full bg-gray-700 px-2 py-0.5 text-[10px] uppercase text-gray-400">Inactive</span>}</div><p className="mt-1 text-sm text-gray-400">{policy.description || 'No description'}</p></div><div className="text-xs text-gray-500">{policy.device_class} · {policy.environment} · {policy.rules.length} rules</div></div>
          <div className="mt-4 overflow-x-auto"><table className="w-full text-left text-xs"><thead className="text-gray-600"><tr><th className="pb-2">Decision</th><th className="pb-2">Transport</th><th className="pb-2">Service</th><th className="pb-2">Ports</th><th className="pb-2">Reason</th></tr></thead><tbody className="divide-y divide-gray-800">{policy.rules.map((rule, index) => <tr key={index}><td className="py-2 font-medium text-gray-200">{rule.action}</td><td className="py-2 text-gray-400">{rule.transport || 'any'}</td><td className="py-2 text-gray-400">{rule.service || 'any'}</td><td className="py-2 font-mono text-gray-400">{rule.ports?.join(', ') || 'any'}</td><td className="py-2 text-gray-500">{rule.reason || '—'}</td></tr>)}</tbody></table></div>
        </Card>)}</div>
      )}

      <Modal open={open} title="New device service policy" size="xl" onClose={() => setOpen(false)} footer={<><Button variant="secondary" onClick={() => setOpen(false)}>Cancel</Button><Button loading={saving} disabled={!form.name.trim() || rules.length === 0} onClick={save}>Create policy</Button></>}>
        <div className="space-y-5">
          <div className="grid gap-4 sm:grid-cols-2"><Field label="Policy name" required><Input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="Conference rooms — production" /></Field><Field label="Device class"><Input value={form.device_class} onChange={(event) => setForm({ ...form, device_class: event.target.value })} placeholder="conference" /></Field></div>
          <Field label="Description"><Textarea rows={2} value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} placeholder="What this service policy protects" /></Field>
          <div className="flex items-center justify-between"><div><h3 className="font-medium text-white">Service rules</h3><p className="text-xs text-gray-500">Rules are evaluated from top to bottom. Unmatched listening services require review.</p></div><Button size="sm" variant="secondary" onClick={() => setRules((current) => [...current, newRule()])}><Plus className="h-3.5 w-3.5" /> Add rule</Button></div>
          <div className="space-y-3">{rules.map((rule, index) => <div key={index} className="rounded-lg border border-gray-800 bg-gray-950 p-3">
            <div className="mb-3 flex items-center justify-between"><span className="text-xs font-medium text-gray-400">Rule {index + 1}</span><Button size="sm" variant="ghost" disabled={rules.length === 1} onClick={() => setRules((current) => current.filter((_, i) => i !== index))}><Trash2 className="h-3.5 w-3.5" /> Remove</Button></div>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5"><Field label="Decision"><Select value={rule.action} onChange={(event) => updateRule(index, { action: event.target.value as EditableRule['action'] })}><option value="allow">Allow</option><option value="deny">Deny</option><option value="review">Review</option><option value="require">Require controls</option></Select></Field><Field label="Transport"><Select value={rule.transport} onChange={(event) => updateRule(index, { transport: event.target.value as EditableRule['transport'] })}><option value="any">Any</option><option value="tcp">TCP</option><option value="udp">UDP</option></Select></Field><Field label="Service"><Input value={rule.service || ''} onChange={(event) => updateRule(index, { service: event.target.value })} placeholder="ssh, https, unknown" /></Field><Field label="Ports" hint="Comma separated; blank means any"><Input value={rule.portsText} onChange={(event) => updateRule(index, { portsText: event.target.value })} placeholder="22, 2222" /></Field><Field label="Severity"><Select value={rule.severity || 'medium'} onChange={(event) => updateRule(index, { severity: event.target.value as EditableRule['severity'] })}><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="info">Info</option></Select></Field></div>
            <Field className="mt-3" label="Reason shown to the operator"><Input value={rule.reason || ''} onChange={(event) => updateRule(index, { reason: event.target.value })} placeholder="Remote administration is allowed only on the management network." /></Field>
          </div>)}</div>
        </div>
      </Modal>
    </div>
  )
}
