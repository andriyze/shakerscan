'use client'

import { useMemo, useState } from 'react'
import { AlertCircle, CheckCircle2, Globe, Lock, Network, Radar, Server, ShieldCheck } from 'lucide-react'
import Link from '@/components/WorkspaceLink'
import { Button, Field, Input, Modal, Select, Textarea } from '@/components/ui'
import { createHostTarget, createWebTarget, startTargetDiscovery } from '@/lib/targetAssetApi'
import { featureEnabled } from '@/lib/workspaceCapabilities'
import { parsePortList, parseTargetLines } from '@/lib/targetInventoryModel.mjs'

type Outcome = { input: string; id?: string; state: 'created' | 'existing' | 'failed'; notes: string[] }

const EXAMPLES = 'example.com\nhttps://app.example.com:8443\n192.168.1.20\nprinter.local:9100'

export function AddTargetsDialog({ open, onClose, onAdded }: { open: boolean; onClose: () => void; onAdded: () => void }) {
  const [text, setText] = useState('')
  const [name, setName] = useState('')
  const [environment, setEnvironment] = useState('production')
  const [ports, setPorts] = useState('')
  const [webOff, setWebOff] = useState<Set<string>>(new Set())
  const [webOn, setWebOn] = useState<Set<string>>(new Set())
  const [authorized, setAuthorized] = useState(false)
  const [approvedBy, setApprovedBy] = useState('operator')
  const [discover, setDiscover] = useState(true)
  const [busy, setBusy] = useState(false)
  const [outcomes, setOutcomes] = useState<Outcome[] | null>(null)
  const devices = featureEnabled('devices')

  const parsed = useMemo(() => parseTargetLines(text), [text])
  const valid = parsed.entries.filter(entry => entry.ok)
  const invalid = parsed.entries.filter(entry => !entry.ok)
  const extraPorts = parsePortList(ports)
  const single = parsed.entries.length === 1
  const wantsWeb = (entry: (typeof valid)[number]) => webOn.has(entry.input) || (entry.webDefault && !webOff.has(entry.input))
  const toggleWeb = (entry: (typeof valid)[number]) => {
    const on = !wantsWeb(entry)
    setWebOn(current => { const next = new Set(current); if (on) next.add(entry.input); else next.delete(entry.input); return next })
    setWebOff(current => { const next = new Set(current); if (on) next.delete(entry.input); else next.add(entry.input); return next })
  }

  function reset() {
    setText(''); setName(''); setPorts(''); setWebOff(new Set()); setWebOn(new Set()); setAuthorized(false); setOutcomes(null)
  }
  function close() {
    if (busy) return
    if (outcomes?.some(outcome => outcome.state !== 'failed')) onAdded()
    reset(); onClose()
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault()
    if (!valid.length || invalid.length || extraPorts.error || busy) return
    setBusy(true)
    const results: Outcome[] = []
    for (const entry of valid) {
      const notes: string[] = []
      const hints = [...new Set([...(entry.port ? [entry.port] : []), ...extraPorts.ports])]
      try {
        const host = await createHostTarget({
          locator: entry.host, name: single && name.trim() ? name.trim() : undefined, environment,
          approvedBy: authorized ? approvedBy.trim() || 'operator' : undefined, portHints: hints,
        })
        if (authorized) notes.push('Authorized for testing')
        let webCreated = false
        if (wantsWeb(entry)) {
          try {
            const web = await createWebTarget(entry.webUrl, environment)
            webCreated = web.status !== 'already_exists'
            const label = entry.scheme ? web.url : `${String(web.url || entry.webUrl).replace(/^https?:\/\//, '')} — HTTP/HTTPS detected on first scan`
            notes.push(webCreated ? `Web app ${label}` : `Web app ${label} was already tracked`)
          } catch (cause) {
            notes.push(`Web app not added: ${cause instanceof Error ? cause.message : 'request failed'}`)
          }
        }
        if (authorized && discover && devices) {
          try {
            await startTargetDiscovery(host.id, hints)
            notes.push('Discovering open ports and web services')
          } catch (cause) {
            notes.push(`Discovery not started: ${cause instanceof Error ? cause.message : 'request failed'}`)
          }
        }
        // Honest outcome: new when the host or its web app was new, otherwise already present.
        results.push({ input: entry.input, id: host.id, state: host.status === 'created' || webCreated ? 'created' : 'existing', notes })
      } catch (cause) {
        results.push({ input: entry.input, state: 'failed', notes: [cause instanceof Error ? cause.message : 'Could not add this target'] })
      }
    }
    setOutcomes(results)
    setBusy(false)
  }

  const footer = outcomes
    ? <div className="flex w-full justify-end gap-2">
        {outcomes.some(outcome => outcome.state === 'failed') && <Button variant="secondary" onClick={() => {
          const failed = outcomes.filter(outcome => outcome.state === 'failed').map(outcome => outcome.input)
          if (outcomes.some(outcome => outcome.state !== 'failed')) onAdded()
          setOutcomes(null); setText(failed.join('\n'))
        }}>Edit failed</Button>}
        <Button onClick={close}>Done</Button>
      </div>
    : <div className="flex w-full flex-wrap items-center justify-between gap-3">
        <span className="text-xs text-gray-500">{valid.length ? `${valid.length} target${valid.length === 1 ? '' : 's'} ready` : 'One target per line'}{invalid.length ? ` · ${invalid.length} to fix` : ''}</span>
        <div className="flex gap-2"><Button variant="secondary" disabled={busy} onClick={close}>Cancel</Button>
          <Button type="submit" form="add-targets-form" loading={busy} disabled={!valid.length || invalid.length > 0 || Boolean(extraPorts.error) || (authorized && !approvedBy.trim())}>
            Add {valid.length > 1 ? `${valid.length} targets` : 'target'}
          </Button></div>
      </div>

  return <Modal open={open} title="Add targets" size="xl" onClose={close} footer={footer}>
    {outcomes ? <ul className="space-y-2" aria-label="Results">
      {outcomes.map(outcome => <li key={outcome.input} className="flex items-start gap-3 rounded-lg border border-gray-800 bg-gray-900/60 p-3">
        {outcome.state === 'failed' ? <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-red-300" aria-hidden="true" /> : <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-300" aria-hidden="true" />}
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="break-all font-mono text-sm text-gray-100">{outcome.input}</span>
            <span className="text-xs text-gray-500">{outcome.state === 'created' ? 'Added' : outcome.state === 'existing' ? 'Already in your inventory' : 'Not added'}</span>
            {outcome.id && <Link href={`/targets/${outcome.id}/asset`} className="ml-auto text-xs text-blue-300 hover:text-blue-200">Open</Link>}
          </div>
          {outcome.notes.map(note => <p key={note} className={`mt-1 text-xs ${outcome.state === 'failed' ? 'text-red-300' : 'text-gray-400'}`}>{note}</p>)}
        </div>
      </li>)}
    </ul> : <form id="add-targets-form" onSubmit={event => void submit(event)} className="space-y-5">
      <Field label="What do you want to test?" hint="Domains, URLs, IP addresses or hostnames — one per line. Paths are ignored; ports are kept.">
        <Textarea autoFocus rows={single || !text ? 3 : 5} value={text} onChange={event => setText(event.target.value)} placeholder={EXAMPLES}
          className="font-mono text-sm" spellCheck={false} />
      </Field>
      {parsed.entries.length > 0 && <div className="rounded-xl border border-gray-800 bg-gray-950/40">
        <p className="border-b border-gray-800 px-3 py-2 text-[11px] font-medium uppercase tracking-wider text-gray-500">What will be added</p>
        <ul className="max-h-64 divide-y divide-gray-800/70 overflow-y-auto">
          {parsed.entries.map(entry => entry.ok
            ? <li key={entry.input} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-3 py-2.5">
                <span className="flex min-w-0 flex-1 items-center gap-2">
                  {entry.kind === 'domain' ? <Globe className="h-4 w-4 shrink-0 text-blue-300" aria-hidden="true" /> : <Server className="h-4 w-4 shrink-0 text-cyan-300" aria-hidden="true" />}
                  <span className="truncate font-mono text-sm text-gray-100">{entry.host}</span>
                  <span className="text-[11px] text-gray-500">{entry.kind === 'domain' ? 'domain' : entry.kind === 'local' ? 'local host' : 'IP address'}</span>
                </span>
                <label className="flex items-center gap-2 text-xs text-gray-300">
                  <input type="checkbox" className="h-3.5 w-3.5 accent-blue-500" checked={wantsWeb(entry)} onChange={() => toggleWeb(entry)} />
                  {entry.scheme === 'https' ? <Lock className="h-3 w-3 text-emerald-300" aria-hidden="true" /> : <Globe className="h-3 w-3 text-gray-500" aria-hidden="true" />}
                  <span className="font-mono">{entry.webLabel}</span>
                </label>
                {(entry.port || entry.pathIgnored) && <span className="basis-full pl-6 text-[11px] text-gray-500">
                  {entry.port ? `Port ${entry.port} is added to network scan hints. ` : ''}{entry.pathIgnored ? 'The path is ignored: targets are hosts and origins.' : ''}
                </span>}
              </li>
            : <li key={entry.input} className="flex items-center gap-2 px-3 py-2.5 text-sm"><AlertCircle className="h-4 w-4 shrink-0 text-red-300" aria-hidden="true" /><span className="font-mono text-gray-300">{entry.input}</span><span className="text-xs text-red-300">{entry.error}</span></li>)}
        </ul>
        {parsed.truncated && <p className="border-t border-gray-800 px-3 py-2 text-xs text-amber-300">Only the first 50 targets are added at once.</p>}
      </div>}
      <div className="grid gap-4 sm:grid-cols-2">
        {single && <Field label="Display name (optional)"><Input value={name} maxLength={255} onChange={event => setName(event.target.value)} placeholder="Customer portal" /></Field>}
        <Field label="Environment"><Select value={environment} onChange={event => setEnvironment(event.target.value)}>
          <option value="production">Production</option><option value="staging">Staging</option><option value="development">Development</option><option value="lab">Lab</option>
        </Select></Field>
        <Field label="Extra ports to check (optional)" hint={extraPorts.error || 'Network scans prioritize these, e.g. 8080, 8443, 9100.'}>
          <Input value={ports} onChange={event => setPorts(event.target.value)} placeholder="8080, 8443" aria-invalid={Boolean(extraPorts.error)}
            className={extraPorts.error ? 'border-red-500/60' : ''} />
        </Field>
      </div>
      <div className="space-y-3 rounded-xl border border-gray-800 bg-gray-900/50 p-4">
        <label className="flex cursor-pointer items-start gap-3">
          <input type="checkbox" className="mt-0.5 h-4 w-4 accent-blue-500" checked={authorized} onChange={event => setAuthorized(event.target.checked)} />
          <span><span className="flex items-center gap-1.5 text-sm font-medium text-gray-100"><ShieldCheck className="h-4 w-4 text-emerald-300" aria-hidden="true" />I own or am authorized to test {valid.length > 1 ? 'these targets' : 'this target'}</span>
            <span className="mt-0.5 block text-xs leading-5 text-gray-400">Records one standing authorization per host, covering its web apps. Scans and Hunts reuse it without asking again; you can revoke it anytime.</span></span>
        </label>
        {authorized && <div className="grid gap-3 pl-7 sm:grid-cols-2">
          <Field label="Approved by"><Input required value={approvedBy} maxLength={120} onChange={event => setApprovedBy(event.target.value)} /></Field>
          {devices && <label className="flex cursor-pointer items-start gap-2 self-end pb-2 text-sm text-gray-300">
            <input type="checkbox" className="mt-0.5 h-4 w-4 accent-blue-500" checked={discover} onChange={event => setDiscover(event.target.checked)} />
            <span><span className="flex items-center gap-1.5"><Radar className="h-4 w-4 text-cyan-300" aria-hidden="true" />Discover ports &amp; web services now</span>
              <span className="mt-0.5 block text-xs text-gray-500">Finds HTTP/HTTPS on any port and links each web app here.</span></span>
          </label>}
        </div>}
        {!authorized && <p className="flex items-start gap-2 pl-7 text-xs text-gray-500"><Network className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden="true" />Without authorization, only passive checks run. You can authorize later from the target menu.</p>}
      </div>
    </form>}
  </Modal>
}
