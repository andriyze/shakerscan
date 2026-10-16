'use client'
import { useCallback, useEffect, useState } from 'react'
import { Badge, Button, Card, ErrorState, Field, Input, Modal, Select } from '@/components/ui'
import { formatDate } from '@/lib/api'
import {
  StepUpRequired, grantDiscoveredSecret, listDiscoveredSecrets, promoteDiscoveredSecret, revealDiscoveredSecret,
  setDiscoveredSecretExpiry, setDiscoveredSecretState, terminalCommand, ungrantDiscoveredSecret, type DiscoveredSecret,
} from '@/lib/discoveredSecretsApi'

type Dialog =
  | { kind: 'reveal'; secret: DiscoveredSecret; value?: string }
  | { kind: 'grant'; secret: DiscoveredSecret; to: string }
  | { kind: 'promote'; secret: DiscoveredSecret; name: string; authKind: string; header: string }
  | { kind: 'expiry'; secret: DiscoveredSecret; days: string }

const STATE_TONE: Record<DiscoveredSecret['state'], string> = {
  active: 'text-emerald-300', revoked_by_operator: 'text-amber-200', expired: 'text-gray-400', superseded: 'text-gray-400',
}

/** Secrets ShakerScan found on this target. Hunts use them by reference and never see them; this
 *  list never holds a value. Revealing one to a person, granting it to another target and moving it
 *  into a credential profile are explicit decisions (on Enterprise, with the person's step-up).
 *  A web Scan records its secrets on the application origin it ran on, not on the host asset: the
 *  asset page shows one card per origin (`origin`, its URL), each only when it holds any. */
export function TargetDiscoveredSecrets({ targetId, origin, hideWhenEmpty = false }: {
  targetId: string; origin?: string; hideWhenEmpty?: boolean
}) {
  const [rows, setRows] = useState<DiscoveredSecret[] | null>(null)
  const [error, setError] = useState('')
  const [stepUp, setStepUp] = useState('')
  const [dialog, setDialog] = useState<Dialog | null>(null)
  const [busy, setBusy] = useState(false)
  const [refresh, setRefresh] = useState(0)

  useEffect(() => {
    const controller = new AbortController()
    listDiscoveredSecrets(targetId, controller.signal)
      .then(result => { if (!controller.signal.aborted) { setRows(Array.isArray(result.secrets) ? result.secrets : []); setError('') } })
      .catch(cause => { if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Could not load discovered secrets') })
    return () => controller.abort()
  }, [targetId, refresh])

  // 'done', 'step-up' (the terminal command is shown instead) or 'failed' (the error is shown).
  const act = useCallback(async (work: () => Promise<unknown>, command?: string) => {
    setBusy(true); setError(''); setStepUp('')
    try { await work(); setRefresh(value => value + 1); return 'done' as const }
    catch (cause) {
      if (cause instanceof StepUpRequired && command) { setStepUp(command); return 'step-up' as const }
      setError(cause instanceof Error ? cause.message : 'The change was not applied')
      return 'failed' as const
    } finally { setBusy(false) }
  }, [])

  function close() { if (!busy) setDialog(null) }  // closing forgets a revealed value

  async function confirm() {
    if (!dialog) return
    const ref = dialog.secret.ref
    if (dialog.kind === 'reveal') {
      setBusy(true); setError(''); setStepUp('')
      try { const shown = await revealDiscoveredSecret(targetId, ref); setDialog({ ...dialog, value: shown.value }) }
      catch (cause) {
        if (cause instanceof StepUpRequired) { setStepUp(terminalCommand('reveal', targetId, ref)); setDialog(null) }
        else setError(cause instanceof Error ? cause.message : 'Could not reveal the value')
      } finally { setBusy(false) }
      return
    }
    const outcome = dialog.kind === 'grant'
      ? await act(() => grantDiscoveredSecret(targetId, ref, dialog.to.trim()), terminalCommand('grant', targetId, ref))
      : dialog.kind === 'promote'
        ? await act(() => promoteDiscoveredSecret(targetId, ref, { name: dialog.name.trim(), auth_kind: dialog.authKind,
          ...(dialog.header.trim() ? { header_name: dialog.header.trim() } : {}) }), terminalCommand('promote', targetId, ref))
        : await act(() => setDiscoveredSecretExpiry(targetId, ref, Number(dialog.days)))
    if (outcome !== 'failed') setDialog(null)
  }

  const own = (rows || []).filter(row => row.found_on === targetId)
  const granted = (rows || []).filter(row => row.found_on !== targetId)
  if (hideWhenEmpty && !error && !stepUp && !dialog && (!rows || rows.length === 0)) return null
  return <Card className="mb-6 scroll-mt-6" id={origin ? undefined : 'discovered-secrets'}>
    <h2 className="text-lg font-semibold text-white">{origin ? <>Discovered secrets <span className="break-all text-sm font-normal text-gray-400">· {origin}</span></> : 'Discovered secrets'}</h2>
    <p className="mt-1 text-xs text-gray-500">Values ShakerScan found on this target (a configuration file, a response, a Hunt&apos;s output). Hunts use them by reference and never see them; this list never shows a value.</p>
    {stepUp && <div className="mt-3 rounded border border-amber-700 bg-amber-950/40 p-3 text-sm text-amber-100" role="status">
      This decision needs your step-up. Make it in your own terminal: <code className="break-all font-mono text-xs">{stepUp}</code>
    </div>}
    {error ? <div className="mt-3"><ErrorState message={error} /></div> : !rows ? <p className="mt-3 text-sm text-gray-500">Loading…</p>
      : rows.length === 0 ? <p className="mt-3 text-sm text-gray-500">None found yet. A Scan that proves an exposed secret, or a Hunt that withholds one, adds it here.</p>
      : <div className="mt-3 overflow-x-auto"><table className="w-full text-left text-sm">
        <thead className="text-xs uppercase text-gray-500"><tr><th className="py-2 pr-3">Secret</th><th className="py-2 pr-3">Seen</th><th className="py-2 pr-3">Use</th><th className="py-2">Actions</th></tr></thead>
        <tbody className="divide-y divide-gray-800">{[...own, ...granted].map(row => <tr key={row.ref}>
          <td className="py-2 pr-3 align-top">
            <div className="flex flex-wrap items-center gap-2"><Badge className="bg-gray-800 text-gray-200">{row.kind}</Badge><span className="break-all text-gray-200">{row.label || 'unnamed field'}</span><span className="text-xs text-gray-500">{row.length} characters</span></div>
            <div className="mt-1 break-all font-mono text-xs text-gray-500">{row.ref}</div>
            {row.found_on !== targetId && <div className="mt-1 text-xs text-teal-300">Granted from another target ({row.found_on})</div>}
            {row.granted_to.length > 0 && row.found_on === targetId && <div className="mt-1 text-xs text-gray-400">Also usable on {row.granted_to.length} other target{row.granted_to.length === 1 ? '' : 's'}: {row.granted_to.map(other => <button key={other} type="button" className="ml-1 text-blue-300 underline" disabled={busy} onClick={() => void act(() => ungrantDiscoveredSecret(targetId, row.ref, other))} title="Stop this target's Hunts using it">{other.slice(0, 8)} ✕</button>)}</div>}
          </td>
          <td className="py-2 pr-3 align-top text-xs text-gray-400">{row.seen_count}×, last {formatDate(row.last_seen_at)}<div>expires {formatDate(row.expires_at)}</div></td>
          <td className="py-2 pr-3 align-top text-xs"><span className={STATE_TONE[row.state]}>{row.state.replace(/_/g, ' ')}</span><div className="text-gray-400">{row.uses} Hunt use{row.uses === 1 ? '' : 's'}{row.reveals ? ` · revealed ${row.reveals}×` : ''}</div>{row.promoted_profile_id && <div className="text-gray-400">now a credential profile</div>}</td>
          <td className="py-2 align-top">{row.found_on === targetId ? <div className="flex flex-wrap gap-2">
            {row.state === 'active'
              ? <Button variant="secondary" disabled={busy} onClick={() => void act(() => setDiscoveredSecretState(targetId, row.ref, 'revoked_by_operator'))}>Revoke</Button>
              : row.state !== 'superseded' && <Button variant="secondary" disabled={busy} onClick={() => void act(() => setDiscoveredSecretState(targetId, row.ref, 'active'))}>Reactivate</Button>}
            <Button variant="secondary" disabled={busy} onClick={() => setDialog({ kind: 'expiry', secret: row, days: '30' })}>Expiry</Button>
            {row.state !== 'superseded' && <Button variant="secondary" disabled={busy} onClick={() => setDialog({ kind: 'grant', secret: row, to: '' })}>Grant</Button>}
            {row.state !== 'superseded' && <Button variant="secondary" disabled={busy} onClick={() => setDialog({ kind: 'promote', secret: row, name: row.label || 'Discovered secret', authKind: 'bearer_token', header: '' })}>Promote</Button>}
            <Button variant="secondary" disabled={busy} onClick={() => setDialog({ kind: 'reveal', secret: row })}>Reveal</Button>
          </div> : <span className="text-xs text-gray-500">Managed on the target it was found on</span>}</td>
        </tr>)}</tbody></table></div>}
    <Modal open={dialog !== null} title={dialog?.kind === 'reveal' ? 'Reveal the value' : dialog?.kind === 'grant' ? 'Let another target use this secret' : dialog?.kind === 'promote' ? 'Move into a credential profile' : 'Set the expiry'} onClose={close}>{dialog && <div className="space-y-4">
      <p className="break-all font-mono text-xs text-gray-400">{dialog.secret.ref}</p>
      {dialog.kind === 'reveal' && (dialog.value === undefined
        ? <><p className="text-sm text-gray-300">The value is shown to you here and recorded as revealed by you. Close this dialog to hide it again.</p><Button loading={busy} onClick={() => void confirm()}>Reveal</Button></>
        : <><pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all rounded bg-gray-950 p-3 font-mono text-xs text-gray-100" data-testid="revealed-value">{dialog.value}</pre><Button variant="secondary" onClick={close}>Hide</Button></>)}
      {dialog.kind === 'grant' && <><Field label="Other target id"><Input value={dialog.to} placeholder="target id" onChange={event => setDialog({ ...dialog, to: event.target.value })} /></Field><p className="text-xs text-gray-500">Hunts of that target may then send this value by reference, only where they may already go. It never widens their scope.</p><Button disabled={!/^[0-9a-f-]{36}$/i.test(dialog.to.trim())} loading={busy} onClick={() => void confirm()}>Grant</Button></>}
      {dialog.kind === 'promote' && <>
        <Field label="Profile name"><Input value={dialog.name} onChange={event => setDialog({ ...dialog, name: event.target.value })} /></Field>
        <Field label="Credential kind"><Select aria-label="Credential kind" value={dialog.authKind} onChange={event => setDialog({ ...dialog, authKind: event.target.value })}>
          <option value="bearer_token">Bearer token</option><option value="api_key_header">API key header</option><option value="authorization_header">Authorization header</option><option value="cookie">Cookie</option><option value="query_parameter">Query parameter</option>
        </Select></Field>
        {(dialog.authKind === 'api_key_header') && <Field label="Header name"><Input value={dialog.header} placeholder="X-Api-Key" onChange={event => setDialog({ ...dialog, header: event.target.value })} /></Field>}
        <p className="text-xs text-gray-500">The value moves into a new credential profile of this target; the discovered secret is then superseded and Hunts use the profile.</p>
        <Button disabled={!dialog.name.trim()} loading={busy} onClick={() => void confirm()}>Promote</Button>
      </>}
      {dialog.kind === 'expiry' && <><Field label="Days from now (1–365)"><Input type="number" min={1} max={365} value={dialog.days} onChange={event => setDialog({ ...dialog, days: event.target.value })} /></Field><Button disabled={!(Number(dialog.days) >= 1 && Number(dialog.days) <= 365)} loading={busy} onClick={() => void confirm()}>Save</Button></>}
    </div>}</Modal>
  </Card>
}
