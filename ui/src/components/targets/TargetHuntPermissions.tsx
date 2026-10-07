'use client'

import { useEffect, useState } from 'react'
import { KeyRound, Settings2, Plus, X } from 'lucide-react'
import { Button, Card, Field, Input, Modal, Select } from '@/components/ui'
import { getTargetHuntAuthority, saveTargetHuntAuthority, type TargetHuntAuthority } from '@/lib/targetHuntAuthorityApi'
import { getAllTargetAssets, type TargetAsset } from '@/lib/targetAssetApi'
import { listCredentialProfiles } from '@/lib/credentialApi'
import { listRequestCollections } from '@/lib/requestCollectionApi'

export function TargetHuntPermissions({targetId}: {targetId: string}) {
  const [saved,setSaved] = useState<TargetHuntAuthority | null>(null)
  const [draft,setDraft] = useState<TargetHuntAuthority | null>(null)
  const [open,setOpen] = useState(false)
  const [busy,setBusy] = useState(false)
  const [error,setError] = useState('')
  const [notice,setNotice] = useState('')
  const [targets,setTargets] = useState<TargetAsset[]>([])
  const [source,setSource] = useState(targetId)
  const [inputs,setInputs] = useState<{profiles:Array<{id:string;name:string}>;collections:Array<{id:string;name:string}>}>({profiles:[],collections:[]})
  const [inputError,setInputError] = useState('')
  useEffect(() => {
    let current = true
    getTargetHuntAuthority(targetId).then(value => {if(current) {setSaved(value);setError('')}})
      .catch(cause => {if(current) setError(cause.message)})
    return () => {current=false}
  },[targetId])
  useEffect(() => {
    if (!open) return
    let current=true
    setInputs({profiles:[],collections:[]});setInputError('')
    Promise.all([listCredentialProfiles({target_kind:'network',target_id:source}),listRequestCollections(source)])
      .then(([profiles,collections]) => {if(current) setInputs({profiles:profiles.profiles || [],collections:collections.collections || []})})
      .catch(cause => {if(current) setInputError(cause.message)})
    return () => {current=false}
  },[open,source])
  async function edit() {
    setOpen(true);setBusy(true);setError('');setNotice('');setDraft(null)
    try {
      const [permissions,assets] = await Promise.all([getTargetHuntAuthority(targetId),getAllTargetAssets()])
      setSaved(permissions);setDraft(permissions);setTargets(assets)
    } catch(cause) {setError(cause instanceof Error ? cause.message : 'Could not load permissions')}
    finally {setBusy(false)}
  }
  function toggle(field:'credential_profile_ids'|'collection_ids',id:string) {
    if(draft) setDraft({...draft,[field]:draft[field].includes(id) ? draft[field].filter(value => value!==id) : [...draft[field],id]})
  }
  async function save() {
    if(!draft) return
    setBusy(true);setError('')
    try {
      const {target_id,revision,recorded_by,updated_at,...permissions}=draft
      void target_id; void recorded_by; void updated_at
      const value=await saveTargetHuntAuthority(targetId,{...permissions,
        ssh_host_keys:permissions.ssh_host_keys.map(({port,fingerprint})=>({port,fingerprint})),
        expected_revision:revision})
      setSaved(value);setOpen(false);setNotice('Hunt permissions saved. Changes apply to subsequent actions, including current Hunts.')
    } catch(cause) {setError(cause instanceof Error ? cause.message : 'Could not save permissions')}
    finally {setBusy(false)}
  }
  return <>
    <Card className="mb-4 flex flex-wrap items-center justify-between gap-4 p-4">
      <div className="flex items-start gap-3"><div><h2 className="text-sm font-semibold text-gray-100">Hunt permissions</h2><p className="mt-0.5 text-xs text-gray-400">{saved?.metadata_changes ? 'Hunt can manage target metadata and instructions.' : 'Delegate target changes and selected inputs once.'} Sharing and SSH trust stay under your control.</p>{notice && <p role="status" className="mt-2 text-xs text-emerald-300">{notice}</p>}</div></div>
      <Button size="sm" variant="secondary" onClick={() => void edit()}><Settings2 className="h-4 w-4" />Edit Hunt permissions</Button>
    </Card>
    {!open && error && <p role="alert" className="mb-4 text-sm text-amber-300">{error}</p>}
    <Modal open={open} title="Hunt permissions" size="xl" onClose={() => {if(!busy) setOpen(false)}} footer={<div className="flex justify-end gap-2"><Button variant="secondary" disabled={busy} onClick={() => setOpen(false)}>Cancel</Button><Button loading={busy} disabled={!draft} onClick={() => void save()}>Save permissions</Button></div>}>
      {error && <p role="alert" className="mb-4 text-sm text-red-300">{error}</p>}
      {draft && <div className="space-y-6">
        <label className="flex items-start gap-3 rounded-lg border border-gray-700 bg-gray-800/30 p-4"><input className="mt-1 accent-blue-500" type="checkbox" checked={draft.metadata_changes} onChange={event => setDraft({...draft,metadata_changes:event.target.checked})} /><span><strong className="text-sm font-medium text-gray-100">Let Hunt manage targets and instructions</strong><span className="mt-1 block text-xs leading-5 text-gray-400">Enabled by default. Create targets, rename this asset, and create, edit, or remove its skill. Turn off to prevent these edits; network testing and input sharing have separate permissions.</span></span></label>
        <section><h3 className="mb-2 flex items-center gap-2 text-sm font-medium text-gray-100"><KeyRound className="h-4 w-4 text-blue-300" />Reuse selected inputs</h3><p className="mb-3 text-xs leading-5 text-gray-400">Choose a source target, then approve specific inputs for this asset. Credential sharing is consumed once; revoke the resulting grant in Credentials. Removing a collection here stops future replay, including queued work.</p><Field label="Source target"><Select value={source} onChange={event => setSource(event.target.value)}>{targets.map(target => <option key={target.id} value={target.id}>{target.name || target.locator}</option>)}</Select></Field>
          {inputError && <p role="alert" className="mt-2 text-xs text-amber-300">{inputError}</p>}
          <div className="mt-3 grid gap-3 sm:grid-cols-2">{([{field:'credential_profile_ids',label:'Credential profiles',items:inputs.profiles},{field:'collection_ids',label:'Request collections',items:inputs.collections}] as const).map(section => <div key={section.field} className="rounded-lg border border-gray-800 p-3"><h4 className="mb-2 text-xs font-medium text-gray-400">{section.label}</h4>{section.items.length ? section.items.map(item => <label key={item.id} className="mb-2 flex items-center gap-2 text-sm text-gray-200"><input type="checkbox" className="accent-blue-500" checked={draft[section.field].includes(item.id)} onChange={() => toggle(section.field,item.id)} />{item.name}</label>) : <p className="text-xs text-gray-500">No available inputs on this target.</p>}{draft[section.field].filter(id => !section.items.some(item => item.id === id)).map(id => <button key={id} onClick={() => toggle(section.field,id)} className="mt-2 flex items-center gap-2 rounded-md bg-blue-500/10 px-2 py-1 text-xs text-blue-200" aria-label={`Remove approval for ${id}`}>{id.slice(0,8)}…<X className="h-3 w-3" /></button>)}</div>)}</div>
        </section>
        <section className="border-t border-gray-800 pt-4"><h3 className="text-sm font-medium text-gray-100">SSH host trust</h3><p className="mt-1 text-xs leading-5 text-gray-400">Save a fingerprint verified through a trusted channel. A key observed by Hunt is a discovery result until you trust it.</p><div className="mt-3 space-y-2">{draft.ssh_host_keys.map((key,index) => <div key={index} className="flex items-end gap-2"><Field label="SSH port"><Input aria-label={`SSH port ${index+1}`} type="number" min={1} max={65535} value={key.port} onChange={event => setDraft({...draft,ssh_host_keys:draft.ssh_host_keys.map((item,i) => i===index ? {...item,port:Number(event.target.value)} : item)})} className="w-24" /></Field><div className="min-w-0 flex-1"><Field label="Verified fingerprint"><Input aria-label={`SSH fingerprint ${index+1}`} value={key.fingerprint} placeholder="SHA256:…" onChange={event => setDraft({...draft,ssh_host_keys:draft.ssh_host_keys.map((item,i) => i===index ? {...item,fingerprint:event.target.value} : item)})} /></Field></div><Button variant="ghost" aria-label={`Remove SSH key ${index+1}`} onClick={() => setDraft({...draft,ssh_host_keys:draft.ssh_host_keys.filter((_,i) => i!==index)})}><X className="h-4 w-4" /></Button></div>)}</div><Button className="mt-3" variant="secondary" size="sm" onClick={() => setDraft({...draft,ssh_host_keys:[...draft.ssh_host_keys,{port:22,fingerprint:''}]})}><Plus className="mr-1 h-3.5 w-3.5" />Add SSH host key</Button>
          <label className="mt-4 flex items-start gap-2 text-sm text-gray-300"><input type="checkbox" className="mt-1 accent-blue-500" checked={draft.ssh_trust_first_contact} onChange={event => setDraft({...draft,ssh_trust_first_contact:event.target.checked})} /><span>Allow first-contact SSH trust<span className="mt-1 block text-xs leading-5 text-amber-200/80">Hunt may authenticate to an unverified host key. A server impersonator present on first contact could receive an SSH password. Use only when you trust this network path.</span></span></label>
        </section>
      </div>}
    </Modal>
  </>
}
