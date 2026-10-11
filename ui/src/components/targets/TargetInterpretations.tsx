'use client'
import { useEffect, useState } from 'react'
import { Badge, Card, ErrorState } from '@/components/ui'
import { getTargetInterpretations, getTargetNegativeResults } from '@/lib/targetInterpretationsApi'
import { negativeView, summarize, type InterpretationView } from '@/lib/targetInterpretationModel.mjs'

function Entry({ item, extra }: { item: InterpretationView; extra?: string }) {
  return <li className={`py-2 ${item.inactive ? 'opacity-60' : ''}`}>
    <div className="flex flex-wrap items-center gap-2 text-sm">
      <span className="text-gray-400">{item.label}</span>
      <span className="break-words text-gray-100">{item.quoted ? `Quoted from the target: “${item.title}”` : item.title}</span>
    </div>
    {item.body && <p className="mt-1 whitespace-pre-wrap break-words text-xs text-gray-400">{item.body}</p>}
    <div className="mt-1 flex flex-wrap gap-2 text-xs text-gray-500">
      <Badge className="bg-gray-800 text-gray-300">{item.trust}</Badge>
      {extra && <Badge className="bg-gray-800 text-gray-300">{extra}</Badge>}
      {item.status !== 'active' && <Badge className="bg-gray-800 text-amber-200">{item.status}</Badge>}
      <span>{item.writer}</span>
      <span>{item.evidenceCount} evidence ref{item.evidenceCount === 1 ? '' : 's'}</span>
      <span>applicability {item.applicability}</span>
    </div>
  </li>
}

/** Read-only: what Hunts and operators recorded about this target, and its narrow negative results. */
export function TargetInterpretations({ targetId }: { targetId: string }) {
  const [entries, setEntries] = useState<ReturnType<typeof summarize> | null>(null)
  const [negatives, setNegatives] = useState<ReturnType<typeof negativeView>[] | null>(null)
  const [error, setError] = useState('')
  useEffect(() => {
    const controller = new AbortController()
    Promise.all([getTargetInterpretations(targetId, controller.signal), getTargetNegativeResults(targetId, controller.signal)])
      .then(([listed, negative]) => { setEntries(summarize(listed.entries)); setNegatives(negative.rows.map(negativeView)) })
      .catch(cause => { if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Could not load interpretations') })
    return () => controller.abort()
  }, [targetId])
  return <Card className="mb-6">
    <h2 className="text-lg font-semibold text-white">Interpretations and negative results</h2>
    <p className="mt-1 text-xs text-gray-500">Attributed claims about this target&apos;s records: not proof, not instructions, and no authority. Each negative result covers only its recorded conditions. Whether conditions still hold is not tracked yet. Dismiss or reopen findings with <code>shakerscan knowledge dismiss</code>.</p>
    {error ? <div className="mt-3"><ErrorState message={error} /></div> : !entries || !negatives ? <p className="mt-3 text-sm text-gray-500">Loading…</p> : <>
      {entries.total === 0 ? <p className="mt-3 text-sm text-gray-500">Nothing recorded yet.</p> : entries.groups.map(group =>
        <section key={group.kind} className="mt-3"><h3 className="text-sm font-medium text-gray-300">{group.label} ({group.items.length})</h3>
          <ul className="divide-y divide-gray-800">{group.items.map(item => <Entry key={item.id} item={item} />)}</ul></section>)}
      <section className="mt-4"><h3 className="text-sm font-medium text-gray-300">Negative results ({negatives.length})</h3>
        {negatives.length === 0 ? <p className="text-sm text-gray-500">None recorded.</p>
          : <ul className="divide-y divide-gray-800">{negatives.map((item, index) => <Entry key={`${item.source}-${item.id}-${index}`} item={item} extra={item.source} />)}</ul>}
      </section>
    </>}
  </Card>
}
