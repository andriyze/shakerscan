'use client'
import { useState } from 'react'
import { Button, Card, ErrorState, Select } from '@/components/ui'
import { getTargetKnowledgeChanges } from '@/lib/targetInterpretationsApi'
import { changesView, SINCE_CHOICES, type ChangesView } from '@/lib/targetChangesModel.mjs'

/** What changed on this target since a point, read on request from records the engine already keeps. */
export function TargetKnowledgeChanges({ targetId }: { targetId: string }) {
  const [since, setSince] = useState<string>(SINCE_CHOICES[0].value)
  const [view, setView] = useState<ChangesView | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  async function load() {
    setLoading(true)
    setError('')
    try {
      setView(changesView(await getTargetKnowledgeChanges(targetId, since)))
    } catch (cause) {
      setView(null)
      setError(cause instanceof Error ? cause.message : 'Could not load what changed')
    } finally {
      setLoading(false)
    }
  }

  return <Card className="mb-6" data-testid="target-changes">
    <h2 className="text-lg font-semibold text-white">What changed</h2>
    <p className="mt-1 text-xs text-gray-500">
      Compares this target&apos;s existing records (scans, the route inventory, earlier requests, discovery) with an earlier
      point and lists the interpretations a change affects. Nothing is sent to the target.
    </p>
    <div className="mt-3 flex flex-wrap items-center gap-2">
      <Select fullWidth={false} aria-label="Compare with" value={since} onChange={(event) => { setSince(event.target.value); setView(null) }}>
        {SINCE_CHOICES.map((choice) => <option key={choice.value} value={choice.value}>Since {choice.label}</option>)}
      </Select>
      <Button variant="secondary" loading={loading} onClick={() => void load()}>See what changed</Button>
    </div>
    <div className="mt-3" aria-live="polite">
      {error && <ErrorState message={error} />}
      {view && !view.resolved && <p className="text-sm text-gray-400">{view.note}</p>}
      {view && view.resolved && <>
        <p className="text-sm text-gray-300">
          Since {view.sinceLabel}{view.sinceAt ? ` (${new Date(view.sinceAt).toLocaleString()})` : ''}
          {view.groups.length === 0 ? ': no change recorded.' : ':'}
        </p>
        {view.groups.map((group) => <section key={group.label} className="mt-3">
          <h3 className="text-sm font-medium text-gray-300">{group.label}</h3>
          <ul className="mt-1 space-y-1 text-xs text-gray-400">
            {group.items.map((item, index) => <li key={index} className="break-words">{item}</li>)}
          </ul>
        </section>)}
        {view.states && <p className="mt-3 text-xs text-gray-500">Active interpretations: {view.states}.</p>}
      </>}
    </div>
    <p className="mt-3 text-xs text-gray-500">
      The same report in a terminal: <code className="font-mono">shakerscan knowledge changes</code>.
    </p>
  </Card>
}
