'use client'
import {useEffect,useRef,useState} from 'react'
import {Terminal, Square, Save} from 'lucide-react'
import {Button,Card,Field,Input,Textarea} from '@/components/ui'
import {API_URL,getApiErrorMessage} from '@/lib/apiConfig'
import {createSseDecoder} from '@/lib/sshEvents.mjs'
import {getHuntV2,type HuntV2} from '@/lib/huntV2'
import {getTargetActions,saveTargetAction} from '@/lib/targetActionsApi'

type Output = {stdout?:string;stderr?:string;session_id?:string;connection_closed?:boolean;exit_status?:number|null;execution_uncertain?:boolean;status?:string}
export function HuntSshConsole({hunt,onChanged}:{hunt:HuntV2;onChanged:(hunt:HuntV2)=>void}) {
  const [command,setCommand] = useState('')
  const [port,setPort] = useState('')
  const [timeout,setTimeoutValue] = useState('30')
  const [session,setSession] = useState<string|null>(null)
  const [output,setOutput] = useState<Output>({})
  const [actionId,setActionId] = useState<string|null>(null)
  const [busy,setBusy] = useState(false)
  const [error,setError] = useState('')
  const [notice,setNotice] = useState('')
  const controller = useRef<AbortController|null>(null)
  useEffect(()=>{setSession(null);setOutput({});setActionId(null);setError('');return ()=>controller.current?.abort()},[hunt.hunt_id])
  const open = ['active','awaiting_planner'].includes(hunt.status)
  const enabled = Boolean(hunt.capabilities?.some(item=>item.name==='ssh.exec')) && open
  async function run() {
    setBusy(true);setError('');setNotice('');setOutput({});setActionId(null)
    const abort = new AbortController();controller.current=abort
    let terminal = false
    try {
      const response = await fetch(API_URL+'/hunts/'+hunt.hunt_id+'/ssh/exec',{method:'POST',signal:abort.signal,
        headers:{'Content-Type':'application/json'},body:JSON.stringify({idempotency_key:'ui-ssh-'+crypto.randomUUID(),
          input:{command,timeout_seconds:Number(timeout),...(session?{session_id:session}:{}),...(port?{port:Number(port)}:{})}})})
      if (!response.ok) throw new Error(await getApiErrorMessage(response,'Could not start SSH command'))
      if (!response.body || !response.headers.get('content-type')?.includes('text/event-stream')) throw new Error('The server did not return SSH output')
      const reader = response.body.getReader(), text = new TextDecoder()
      const events = createSseDecoder((name:string,value:Record<string,unknown>)=>{
        if (name==='accepted') setActionId(String(value.action_id))
        if (name==='output') {
          const next=value as Output;setOutput(next)
          if (next.session_id) setSession(next.connection_closed?null:next.session_id)
        }
        if (name==='error') {terminal=true;setError(String(value.detail));setSession(null)}
        if (name==='result') {
          terminal=true
          const result=value.result as {typed_output?:{records?:Output[]};error?:string}|undefined
          const final=result?.typed_output?.records?.find(item=>'stdout' in item || 'stderr' in item)
          if (final) {setOutput(final);setSession(final.connection_closed?null:final.session_id || null)}
          else {setSession(null);setError(result?.error || 'No SSH output was returned. Inspect the action outcome.')}
          void getHuntV2(hunt.hunt_id).then(onChanged)
        }
      })
      while (true) {const part=await reader.read();if(part.done)break;events.push(text.decode(part.value,{stream:true}))}
      events.push(text.decode());events.finish()
      if (!terminal) throw new Error('Connection ended before the command result. Inspect the action before running another command.')
    } catch(cause) {setError(cause instanceof Error?cause.message:'SSH stream failed');setSession(null)}
    finally {setBusy(false);controller.current=null}
  }
  async function cancel() {
    if (!actionId) return
    try {
      const response=await fetch(API_URL+'/hunts/'+hunt.hunt_id+'/ssh/actions/'+actionId+'/cancel',{method:'POST'})
      if (!response.ok) throw new Error(await getApiErrorMessage(response,'Could not cancel SSH command'))
      setNotice('Cancellation requested. Remote process termination may remain uncertain.')
    } catch(cause) {setError(cause instanceof Error?cause.message:'Could not cancel')}
  }
  async function save() {
    try {
      const saved=await getTargetActions(hunt.target_id)
      await saveTargetAction(hunt.target_id,saved.revision,{name:command.split('\n')[0].slice(0,120),
        instructions:'Saved from Hunt '+hunt.hunt_id,parameters:{},steps:[{capability:'ssh.exec',input:{command,...(port?{port:Number(port)}:{})}}]})
      setNotice('Command saved as a reusable target action.')
    } catch(cause) {setError(cause instanceof Error?cause.message:'Could not save command')}
  }
  return <Card className="space-y-4 border-emerald-500/20 bg-gray-900 p-5"><div className="flex items-center justify-between gap-3"><h2 className="flex items-center gap-2 font-medium text-white"><Terminal className="h-4 w-4 text-emerald-300" />Live SSH</h2><span className="text-xs text-gray-500">{session?'Reusing authenticated connection':'Connect on first command'}</span></div>
    <p className="text-sm text-gray-400">Run commands with this Hunt’s selected stored SSH identity. Output appears as it arrives.</p>
    <Field label="Remote command"><Textarea mono rows={3} value={command} disabled={busy} onChange={event=>setCommand(event.target.value)} placeholder="uname -a && uptime" /></Field>
    <div className="flex flex-wrap items-end gap-3"><Field label="Port"><Input className="w-32" type="number" min={1} max={65535} value={port} disabled={busy || Boolean(session)} placeholder="Profile / 22" onChange={event=>setPort(event.target.value)} /></Field><Field label="Timeout (seconds)"><Input className="w-32" type="number" min={1} max={300} value={timeout} disabled={busy} onChange={event=>setTimeoutValue(event.target.value)} /></Field><Button loading={busy} disabled={!enabled || !command.trim()} onClick={()=>void run()}>Run command</Button>{busy && <Button variant="danger" disabled={!actionId} onClick={()=>void cancel()}><Square className="h-4 w-4" />Cancel</Button>}<Button variant="ghost" disabled={busy || !command.trim()} onClick={()=>void save()}><Save className="h-4 w-4" />Save action</Button></div>
    {!enabled && <p className="text-xs text-amber-200">{open?'Select an SSH identity with ssh.exec permission when starting an authorized Hunt.':'This Hunt has ended. Start a new Hunt to run SSH commands.'}</p>}
    {(busy || output.stdout || output.stderr || output.exit_status!==undefined) && <div className="rounded-xl border border-gray-800 bg-black/60 p-4"><pre aria-label="SSH stdout" className="max-h-96 overflow-auto whitespace-pre-wrap break-words font-mono text-xs leading-6 text-emerald-200">{output.stdout}</pre>{output.stderr && <pre aria-label="SSH stderr" className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap break-words font-mono text-xs text-amber-200">{output.stderr}</pre>}<p role="status" className="mt-3 text-xs text-gray-500">{busy?'Running…':output.exit_status!==undefined?'Exit status: '+String(output.exit_status):output.status}{output.execution_uncertain?' · Execution uncertain':''}</p></div>}
    {error && <p role="alert" className="text-sm text-red-300">{error}</p>}{notice && <p role="status" className="text-xs text-blue-200">{notice}</p>}
  </Card>
}
