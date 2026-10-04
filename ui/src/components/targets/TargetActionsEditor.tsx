'use client'

import {useEffect,useState} from 'react'
import Link from '@/components/WorkspaceLink'
import {ListChecks, Plus, Pencil, Trash2, Terminal, Play} from 'lucide-react'
import {Button, Card, Field, Input, Modal, Select, Textarea} from '@/components/ui'
import {getTargetActions, saveTargetAction, deleteTargetAction, type TargetAction, type TargetActions} from '@/lib/targetActionsApi'
import {API_URL} from '@/lib/apiConfig'

export function TargetActionsEditor({targetId}:{targetId:string}) {
  const [saved,setSaved] = useState<TargetActions|null>(null)
  const [error,setError] = useState('')
  const [open,setOpen] = useState(false)
  const [busy,setBusy] = useState(false)
  const [editing,setEditing] = useState<TargetAction|null>(null)
  const [name,setName] = useState('')
  const [instructions,setInstructions] = useState('')
  const [command,setCommand] = useState('')
  // Empty means the credential profile's saved port, or 22: only an explicit choice is saved.
  const [port,setPort] = useState('')
  const [mode,setMode] = useState<'ssh'|'capabilities'>('ssh')
  const [draft,setDraft] = useState('')
  // An SSH step's other settings (cwd, timeout_seconds, max_output_bytes, ...) are kept as saved;
  // the SSH form edits only the command and port.
  const [sshInput,setSshInput] = useState<Record<string,unknown>>({})
  const [parameters,setParameters] = useState('{}')
  const [capabilities,setCapabilities] = useState<string[]>([])
  useEffect(() => {
    const controller = new AbortController()
    getTargetActions(targetId,controller.signal).then(setSaved).catch(cause => {if (!controller.signal.aborted) setError(cause.message)})
    return () => controller.abort()
  },[targetId])
  async function edit(action?:TargetAction) {
    setError('');setBusy(true)
    try {
      const current = await getTargetActions(targetId);setSaved(current)
      // Edit what is saved now, not the copy shown before reloading: another writer (a Hunt) may
      // have changed it, and saving stale content under the fresh revision would overwrite that.
      const shownId = action?.id
      const latest = shownId ? current.actions.find(item => item.id === shownId) : undefined
      if (shownId && !latest) throw new Error('This action was deleted since the list was loaded.')
      action = latest
      setEditing(action || null);setName(action?.name || '');setInstructions(action?.instructions || '')
      setParameters(JSON.stringify(action?.parameters || {},null,2))
      const ssh = !action || (action.steps.length===1 && action.steps[0].capability==='ssh.exec' && !Object.keys(action.parameters).length)
      setMode(ssh ? 'ssh':'capabilities')
      setCommand(ssh && action ? String(action.steps[0].input.command || ''):'')
      setPort(ssh && action && action.steps[0].input.port !== undefined ? String(action.steps[0].input.port) : '')
      setSshInput(ssh && action ? {...action.steps[0].input} : {})
      setDraft(JSON.stringify(action?.steps || [{capability:'ports.discover',input:{profile:'top_100'}}],null,2))
      setOpen(true)
      const response = await fetch(API_URL+'/hunts/contract')
      if (response.ok) {
        const contract = await response.json()
        const manifest = contract.tool_calls || []
        if (Array.isArray(manifest)) setCapabilities(manifest.map((item:{name:string}|string)=>typeof item==='string'?item:item.name))
      }
    } catch(cause) {setError(cause instanceof Error ? cause.message:'Could not load saved actions')}
    finally {setBusy(false)}
  }
  async function save() {
    if (!saved) return
    setBusy(true);setError('')
    try {
      const {port:_previousPort, ...kept} = sshInput
      const next = mode==='ssh' ? [{capability:'ssh.exec',input:{...kept,command,...(port.trim()?{port:Number(port)}:{})}}] : JSON.parse(draft)
      const current = await saveTargetAction(targetId,saved.revision,{name,instructions,steps:next,parameters:mode==='ssh'?{}:JSON.parse(parameters)},editing?.id)
      setSaved(current);setOpen(false)
    } catch(cause) {setError(cause instanceof Error ? cause.message:'Could not save action')}
    finally {setBusy(false)}
  }
  async function remove(action:TargetAction) {
    if (!saved) return
    setBusy(true);setError('')
    try {setSaved(await deleteTargetAction(targetId,saved.revision,action.id))}
    catch(cause) {setError(cause instanceof Error ? cause.message:'Could not delete action')}
    finally {setBusy(false)}
  }
  function addCapability(capability:string) {
    try {setDraft(JSON.stringify([...JSON.parse(draft),{capability,input:{}}],null,2));setError('')}
    catch {setError('Correct the steps JSON before adding another capability.')}
  }
  return <Card className="mb-6 border-violet-500/20 bg-linear-to-br from-violet-500/5 via-gray-900 to-gray-900 p-5">
    <div className="flex flex-wrap items-start justify-between gap-4"><div className="flex gap-3"><div className="rounded-xl bg-violet-500/10 p-2.5 text-violet-300"><ListChecks className="h-5 w-5" aria-hidden="true" /></div><div><h2 className="font-semibold text-white">Saved Hunt actions</h2><p className="mt-1 text-sm text-gray-400">Reusable checks and commands. Hunt sees these when it starts and can keep them up to date.</p></div></div><Button variant="secondary" onClick={()=>void edit()} disabled={busy}><Plus className="h-4 w-4" />Add action</Button></div>
    {error && <p role="alert" className="mt-4 text-sm text-red-300">{error}</p>}
    {saved?.actions.length ? <div className="mt-4 grid gap-3 md:grid-cols-2">{saved.actions.map(action=><div key={action.id} className="rounded-xl border border-gray-800 bg-gray-950/40 p-4"><div className="flex items-start justify-between gap-2"><h3 className="font-medium text-gray-100">{action.name}</h3><span className="text-xs text-gray-500">v{action.revision}</span></div><p className="mt-2 line-clamp-2 text-sm text-gray-400">{action.instructions || 'Run these saved steps against this target.'}</p><div className="mt-3 flex flex-wrap gap-1">{action.steps.map((step,index)=><code key={index} className="rounded bg-violet-500/10 px-2 py-1 text-xs text-violet-200">{step.capability}</code>)}</div><div className="mt-4 flex flex-wrap items-center gap-2"><Link href={`/hunt?target=${encodeURIComponent(targetId)}&objective=${encodeURIComponent('Run saved target action "'+action.name+'" ('+action.id+'). Read it using targets.actions.read and execute its steps through the Hunt capability runtime.')}`} className="inline-flex items-center gap-1.5 text-sm text-blue-300"><Play className="h-3.5 w-3.5" />Start Hunt</Link><Button size="sm" variant="ghost" disabled={busy} onClick={()=>void edit(action)} aria-label={'Edit '+action.name}><Pencil className="h-3.5 w-3.5" /></Button><Button size="sm" variant="ghost" disabled={busy} onClick={()=>void remove(action)} aria-label={'Delete '+action.name}><Trash2 className="h-3.5 w-3.5" /></Button></div></div>)}</div> : <p className="mt-4 rounded-lg border border-dashed border-gray-700 p-4 text-sm text-gray-500">Save “Check router uptime”, “Discover TV ports”, or a repeatable API investigation.</p>}
    <Modal open={open} title={editing ? 'Edit saved action':'Create saved action'} size="xl" onClose={()=>{if (!busy) setOpen(false)}} footer={<div className="flex justify-end gap-2"><Button variant="secondary" disabled={busy} onClick={()=>setOpen(false)}>Cancel</Button><Button loading={busy} disabled={!saved || !name.trim() || (mode==='ssh' && !command.trim())} onClick={()=>void save()}>Save action</Button></div>}>
      <div className="space-y-4"><Field label="Action name"><Input value={name} maxLength={120} onChange={event=>setName(event.target.value)} placeholder="Check router uptime" /></Field><Field label="When and how to use it"><Textarea rows={3} value={instructions} maxLength={4000} onChange={event=>setInstructions(event.target.value)} placeholder="Explain the goal, success signal, and any follow-up checks." /></Field><div className="flex gap-2"><Button variant={mode==='ssh'?'secondary':'ghost'} onClick={()=>setMode('ssh')}><Terminal className="h-4 w-4" />SSH command</Button><Button variant={mode==='capabilities'?'secondary':'ghost'} onClick={()=>setMode('capabilities')}>Capability steps</Button></div>
        {mode==='ssh' ? <><Field label="Remote command"><Textarea mono rows={5} value={command} onChange={event=>setCommand(event.target.value)} placeholder="uptime && uname -a" /></Field><Field label="SSH port"><Input type="number" min={1} max={65535} value={port} placeholder="Profile / 22" onChange={event=>setPort(event.target.value)} /></Field><p className="text-xs text-gray-400">Uses the SSH identity selected for the Hunt. Store passwords and keys in Credentials.</p></> : <><Field label="Steps" hint="Each step names a canonical capability and its typed input. Hunt executes and records each call separately."><Textarea mono rows={12} value={draft} onChange={event=>setDraft(event.target.value)} /></Field>{capabilities.length>0 && <Field label="Available capability names"><Select value="" onChange={event=>addCapability(event.target.value)}><option value="">Add a capability…</option>{capabilities.map(item=><option key={item}>{item}</option>)}</Select></Field>}<Field label="Parameters (JSON)" hint={'Optional typed values, e.g. {"port":{"type":"integer","default":22}}. Reference a whole input value with {"$parameter":"port"}.'}><Textarea mono rows={4} value={parameters} onChange={event=>setParameters(event.target.value)} /></Field></>}
        {error && <p role="alert" className="text-sm text-red-300">{error}</p>}
      </div>
    </Modal>
  </Card>
}
