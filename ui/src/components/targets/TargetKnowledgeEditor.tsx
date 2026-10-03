'use client'
import {useState} from 'react'
import {Button,Field,Modal,Textarea} from '@/components/ui'
import {deleteTargetSkill,getTargetSkill,saveTargetSkill,type TargetSkillState} from '@/lib/targetSkillApi'

export function TargetKnowledgeEditor({targetId,onChanged}:{targetId:string;onChanged?:()=>void}) {
  const [open,setOpen] = useState(false)
  const [saved,setSaved] = useState<TargetSkillState|null>(null)
  const [text,setText] = useState('')
  const [busy,setBusy] = useState(false)
  const [error,setError] = useState('')
  async function edit() {
    setOpen(true);setBusy(true);setError('')
    try {const state=await getTargetSkill(targetId);setSaved(state);setText(state.knowledge?.methodology || '')}
    catch(cause){setError(cause instanceof Error?cause.message:'Could not load knowledge')}
    finally{setBusy(false)}
  }
  async function save(remove=false) {
    if (!saved) return
    setBusy(true);setError('')
    try {
      if(remove) await deleteTargetSkill(targetId,saved.revision,'knowledge')
      else await saveTargetSkill(targetId,saved,'Learned target knowledge',text,'knowledge')
      setOpen(false);onChanged?.()
    } catch(cause){setError(cause instanceof Error?cause.message:'Could not save knowledge')}
    finally{setBusy(false)}
  }
  return <><Button size="sm" variant="ghost" onClick={()=>void edit()}>Edit learned knowledge</Button><Modal open={open} title="Learned target knowledge" size="xl" onClose={()=>{if(!busy)setOpen(false)}} footer={<div className="flex w-full justify-between gap-2">{saved?.knowledge && <Button variant="danger" disabled={busy} onClick={()=>void save(true)}>Delete knowledge</Button>}<div className="ml-auto flex gap-2"><Button variant="secondary" disabled={busy} onClick={()=>setOpen(false)}>Cancel</Button><Button loading={busy} disabled={!saved || !text.trim() || text.length>saved.max_characters} onClick={()=>void save()}>Save knowledge</Button></div></div>}><div className="space-y-4"><p className="text-sm text-gray-400">Correct stale observations and keep useful discoveries for the next Hunt. This is advisory context; it grants no testing or credential authority.</p><Field label="Observations and unfinished leads"><Textarea mono rows={14} value={text} disabled={busy} onChange={event=>setText(event.target.value)} placeholder="Known services, useful evidence, and leads to continue…" /></Field>{error && <p role="alert" className="text-sm text-red-300">{error}</p>}</div></Modal></>
}

