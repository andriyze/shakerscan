'use client'

import { useEffect, useState } from 'react'
import { Check, FilePenLine, Sparkles, Trash2 } from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import { Button, Card, Field, Input, Modal, Textarea } from '@/components/ui'
import { targetInstructionState } from '@/lib/targetInstructionState.mjs'
import { deleteTargetSkill, getTargetSkill, saveTargetSkill, type TargetSkillState } from '@/lib/targetSkillApi'

const TEMPLATE = `## About this target
Describe the application or device, its services, and anything Hunt should know.

## How to log in
Name the saved credential profile and explain the login steps and success signal.

## What to test
List the most useful investigation priorities and known endpoints.

## What to skip
Describe exclusions, fragile operations, and actions to avoid.
`

export function TargetSkillPreview({text}: {text: string}) {
  return <div className="space-y-3 wrap-break-word text-sm leading-7 text-gray-300 [&_h1]:text-xl [&_h1]:font-semibold [&_h1]:text-white [&_h2]:mt-5 [&_h2]:text-base [&_h2]:font-semibold [&_h2]:text-white [&_h3]:font-medium [&_h3]:text-white [&_ul]:list-disc [&_ul]:pl-5 [&_ol]:list-decimal [&_ol]:pl-5 [&_code]:rounded [&_code]:bg-gray-800 [&_code]:px-1 [&_pre]:overflow-auto [&_pre]:rounded-lg [&_pre]:bg-gray-950 [&_pre]:p-3 [&_blockquote]:border-l-2 [&_blockquote]:border-blue-500 [&_blockquote]:pl-4">
    <ReactMarkdown skipHtml disallowedElements={['img']} components={{a: ({children,href}) => <a href={href} target="_blank" rel="noopener noreferrer" className="text-blue-300 underline">{children}</a>}}>{text}</ReactMarkdown>
  </div>
}

export function TargetSkillEditor({targetId, targetName, compact = false, hasSkill = false, menuItem = false}: {
  targetId: string; targetName: string; compact?: boolean; hasSkill?: boolean
  /** Render the trigger as a full-width menu entry instead of a button. */
  menuItem?: boolean
}) {
  const [saved, setSaved] = useState<TargetSkillState | null>(null)
  const [open, setOpen] = useState(false)
  const lazy = compact || menuItem
  const [loading, setLoading] = useState(!lazy)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [title, setTitle] = useState('Target instructions')
  const [text, setText] = useState('')
  const [preview, setPreview] = useState(false)
  const [confirmation, setConfirmation] = useState<'discard' | 'delete' | null>(null)
  const [notice, setNotice] = useState('')
  const instructionState = targetInstructionState(saved)
  const dirty = title !== (instructionState.editable?.title || 'Target instructions') || text !== (instructionState.editable?.methodology || '')
  const exists = saved ? instructionState.exists : hasSkill

  useEffect(() => {
    if (lazy) return
    const controller = new AbortController()
    setLoading(true)
    getTargetSkill(targetId, controller.signal).then(result => {if (!controller.signal.aborted) {setSaved(result);setError(null)}})
      .catch(cause => {if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Could not load target instructions')})
      .finally(() => {if (!controller.signal.aborted) setLoading(false)})
    return () => controller.abort()
  }, [targetId, lazy])

  async function edit() {
    setOpen(true);setLoading(true);setError(null);setConfirmation(null);setPreview(false);setNotice('')
    setSaved(null)
    try {
      const result = await getTargetSkill(targetId)
      const editable = targetInstructionState(result).editable
      setSaved(result);setTitle(editable?.title || 'Target instructions');setText(editable?.methodology || '')
    } catch (cause) {setError(cause instanceof Error ? cause.message : 'Could not load target instructions')}
    finally {setLoading(false)}
  }
  function close() {
    if (busy || loading) return
    if (dirty) setConfirmation('discard')
    else setOpen(false)
  }
  async function save() {
    if (!saved) return
    setBusy(true);setError(null)
    try {
      const result = await saveTargetSkill(targetId, saved, title.trim(), text.trim())
      setSaved(result);setTitle(result.skill!.title);setText(result.skill!.methodology)
      setOpen(false);setNotice('Operator instructions saved for future Hunts.')
    } catch (cause) {setError(cause instanceof Error ? cause.message : 'Could not save target instructions')}
    finally {setBusy(false)}
  }
  async function remove() {
    if (!saved) return
    setBusy(true);setError(null)
    try {
      setSaved(await deleteTargetSkill(targetId, saved.revision));setText('');setTitle('Target instructions')
      setOpen(false);setConfirmation(null);setNotice('Instructions removed. Existing Hunt snapshots are retained.')
    } catch (cause) {setError(cause instanceof Error ? cause.message : 'Could not delete target instructions');setConfirmation(null)}
    finally {setBusy(false)}
  }
  const trigger = menuItem
    ? <button type="button" role="menuitem" onClick={() => void edit()} aria-label={`${exists ? 'Edit' : 'Create'} instructions for ${targetName}`} className="flex w-full items-center gap-2.5 rounded-md px-3 py-2 text-left text-sm text-gray-200 hover:bg-gray-800 focus:bg-gray-800 focus:outline-none"><FilePenLine className="h-4 w-4 text-gray-400" aria-hidden="true" />{exists ? 'Edit Hunt instructions' : 'Add Hunt instructions'}</button>
    : <Button size="sm" variant="secondary" onClick={() => void edit()} aria-label={`${exists ? 'Edit' : 'Create'} instructions for ${targetName}`}><FilePenLine className="h-4 w-4" aria-hidden="true" />{compact ? 'Instructions' : exists ? 'Edit instructions' : 'Create instructions'}</Button>

  return <>
    {compact || menuItem ? <span className={menuItem ? 'block' : 'relative inline-flex'} onClick={event => event.stopPropagation()}>{trigger}<span role="status" className="sr-only">{notice}</span></span> : <Card className="relative mb-4 overflow-hidden p-4">
      <div className="flex flex-wrap items-start justify-between gap-4"><div><h2 className="text-sm font-semibold text-gray-100">Target instructions</h2><p className="mt-0.5 max-w-xl text-xs text-gray-400">Give Hunt a head start: how to log in, what matters, and what to skip.</p></div>{trigger}</div>
      {loading ? <p className="mt-4 text-sm text-gray-400" role="status">Loading instructions…</p> : error ? <p className="mt-4 text-sm text-red-300" role="alert">{error}</p> : instructionState.editable ? <div className="mt-4 rounded-lg border border-gray-800 bg-gray-950/40 p-4"><div className="mb-3 flex flex-wrap items-center gap-2"><span className="text-sm font-medium text-gray-200">{instructionState.editable.title}</span><span className="rounded-full bg-blue-500/10 px-2 py-0.5 text-xs text-blue-300">Version {instructionState.editable.version} · {instructionState.advisory ? 'Advisory knowledge' : 'Effective instructions'}</span></div><p className="whitespace-pre-wrap wrap-break-word text-sm leading-6 text-gray-400">{instructionState.editable.methodology.slice(0,300)}{instructionState.editable.methodology.length > 300 ? '…' : ''}</p></div> : <div className="mt-4 grid gap-2 text-xs text-gray-400 sm:grid-cols-3">{['Login steps & success signals','Priorities & known endpoints','Exclusions & fragile actions'].map(item => <div key={item} className="rounded-lg border border-dashed border-gray-700 px-3 py-3">{item}</div>)}</div>}
      <div className="mt-4 flex flex-wrap items-center gap-3 text-xs text-gray-500"><span className="inline-flex items-center gap-1.5"><Sparkles className="h-3.5 w-3.5 text-blue-300" aria-hidden="true" />Instructions and advisory learning are automatically loaded</span>{saved?.skill && <span>Saved {new Date(saved.skill.updated_at).toLocaleString()}</span>}</div><p role="status" className="mt-2 text-xs text-emerald-300">{notice}</p>
    </Card>}
    <Modal open={open} title="Target instructions" size="xl" onClose={close} footer={confirmation ? <div className="flex w-full flex-wrap items-center justify-between gap-3"><p className="text-sm text-gray-300">{confirmation === 'delete' ? 'Remove the effective instructions? Learned knowledge and existing Hunt snapshots are retained.' : 'Discard your unsaved changes?'}</p><div className="flex gap-2"><Button variant="secondary" disabled={busy} onClick={() => setConfirmation(null)}>Keep editing</Button><Button variant="danger" loading={busy} onClick={() => confirmation === 'delete' ? void remove() : (setConfirmation(null),setOpen(false))}>{confirmation === 'delete' ? 'Delete instructions' : 'Discard changes'}</Button></div></div> : <div className="flex w-full flex-wrap items-center justify-between gap-3"><div>{instructionState.exists && <Button variant="ghost" disabled={busy || loading} onClick={() => setConfirmation('delete')}><Trash2 className="h-4 w-4" aria-hidden="true" />Delete</Button>}</div><div className="flex gap-2"><Button variant="secondary" disabled={busy || loading} onClick={close}>Cancel</Button><Button loading={busy} disabled={loading || !saved || !title.trim() || !text.trim() || text.length > saved.max_characters || (!dirty && !instructionState.needsOperatorSave)} onClick={() => void save()}><Check className="h-4 w-4" aria-hidden="true" /> {instructionState.needsOperatorSave ? 'Save as operator instructions' : 'Save instructions'}</Button></div></div>}>
      <div className="space-y-4"><div><p className="break-all text-sm font-medium text-gray-200">{targetName}</p><p className="mt-1 text-sm text-gray-400">Instruction edits made under saved Hunt delegation guide future Hunts immediately. Learned knowledge is included separately as advisory context.</p></div>
        {loading ? <p role="status" className="py-12 text-center text-sm text-gray-400">Loading saved instructions…</p> : <>
          {error && <div role="alert" className="rounded-lg border border-red-500/20 bg-red-500/5 p-3 text-sm text-red-300"><p>{error}</p><Button className="mt-2" size="sm" variant="secondary" disabled={busy} onClick={() => void edit()}>Discard draft and reload</Button></div>}
          {instructionState.advisory && <div data-testid="target-instruction-trust" className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-sm text-amber-200">This learned context is advisory, not operator intent. It is already included in future Hunts without a manual save. {instructionState.operator ? <details className="mt-2"><summary>Current operator instructions (still used by new Hunts)</summary><TargetSkillPreview text={instructionState.operator.methodology} /></details> : <p className="mt-2">New Hunts automatically receive this bounded learning with its provenance.</p>}</div>}
          {saved?.knowledge && <details data-testid="target-learned-knowledge" className="rounded-lg border border-blue-500/20 p-3 text-sm text-blue-200"><summary>Automatically loaded learned knowledge · advisory</summary><p className="mt-2 text-xs text-gray-400">Recorded by {saved.knowledge.written_by || 'unknown source'} · version {saved.knowledge.version}</p><TargetSkillPreview text={saved.knowledge.methodology} /></details>}
          <Field label="Skill title"><Input style={{fontSize:16}} maxLength={120} value={title} disabled={busy} onChange={event => setTitle(event.target.value)} /></Field>
          <div className="flex flex-wrap items-center justify-between gap-2"><div className="inline-flex rounded-lg border border-gray-700 p-1"><Button size="sm" variant={preview ? 'ghost' : 'secondary'} aria-pressed={!preview} onClick={() => setPreview(false)}>Write</Button><Button size="sm" variant={preview ? 'secondary' : 'ghost'} aria-pressed={preview} onClick={() => setPreview(true)}>Preview</Button></div><Button size="sm" variant="ghost" disabled={busy || Boolean(text.trim())} onClick={() => setText(TEMPLATE)}><Sparkles className="h-3.5 w-3.5" aria-hidden="true" />Use starter template</Button></div>
          {preview ? <div aria-label="Instructions preview" className="min-h-72 rounded-xl border border-gray-800 bg-gray-950/50 p-5">{text.trim() ? <TargetSkillPreview text={text} /> : <p className="text-sm text-gray-500">Your instructions will appear here.</p>}</div> : <Field label="Instructions" hint="Markdown supported. Reference saved credentials and collections by name or ID; keep passwords and tokens in their encrypted stores."><Textarea style={{fontSize:16}} mono rows={14} disabled={busy} value={text} onChange={event => setText(event.target.value)} placeholder="Explain how to log in, what to investigate, and what to avoid…" className="resize-y rounded-xl bg-gray-950/50 text-sm leading-7" /></Field>}
          <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-gray-500"><span>{dirty ? 'Unsaved changes' : saved?.skill ? `Saved version ${saved.revision}` : 'No instructions saved yet'}</span><span className={text.length > (saved?.max_characters || Infinity) ? 'text-red-300' : ''}>{text.length.toLocaleString()} / {saved?.max_characters.toLocaleString()} characters</span></div>
          <p className="rounded-lg bg-blue-500/5 p-3 text-xs leading-5 text-gray-400">Saved metadata delegation permits Hunt instruction updates and deletion without another UI save. Learned knowledge never grants testing or credential permissions. Existing Hunt snapshots are retained.</p>
        </>}
      </div>
    </Modal>
  </>
}
