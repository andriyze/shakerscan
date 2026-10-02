'use client'

import { useEffect, useState } from 'react'
import { Field, Select } from '@/components/ui'
import { getRequestCollection, type RequestCollectionEnvironment } from '@/lib/requestCollectionApi'

export function DeviceCollectionEnvironments({ ids, selected, onChange }: {
  ids: string[]
  selected: Record<string, string | null>
  onChange: (next: Record<string, string | null>) => void
}) {
  const [choices, setChoices] = useState<Array<{id: string; name: string; environments: RequestCollectionEnvironment[]}>>([])
  const [error, setError] = useState<string | null>(null)
  const key = ids.join(',')
  useEffect(() => {
    let cancelled = false
    const current = key ? key.split(',') : []
    setChoices([]); setError(null)
    Promise.all(current.map(async (id) => {
      const detail = await getRequestCollection(id)
      return {id, name: detail.collection.name, environments: detail.environments.filter((item) => item.is_active)}
    })).then((rows) => {if (!cancelled) setChoices(rows)})
      .catch((cause) => {if (!cancelled) setError(cause instanceof Error ? cause.message : 'Could not load shared environments')})
    return () => {cancelled = true}
  }, [key])
  return <div className="mt-3 space-y-3">
    {error && <p role="alert" className="text-xs text-red-300">{error}. Refresh before selecting an environment.</p>}
    {choices.filter((item) => item.environments.length > 0).map((item) => <Field key={item.id} label={`${item.name}: environment`} hint="Uses the same encrypted environment as application scans. Its version is checked again when execution starts.">
      <Select value={selected[item.id] || ''} onChange={(event) => onChange({...selected, [item.id]: event.target.value || null})}>
        <option value="">No separate environment</option>
        {item.environments.map((environment) => <option key={environment.id} value={environment.id}>{environment.name} · {environment.variable_count} variables</option>)}
      </Select>
    </Field>)}
  </div>
}
