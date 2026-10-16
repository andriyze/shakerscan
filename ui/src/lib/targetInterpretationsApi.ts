import { pathSegment } from './apiPath.mjs'
import { API_URL, getApiErrorMessage } from './apiConfig'

/** A target's attributed interpretations (read-only here; Hunts record them, operators review them). */
export interface TargetInterpretation {
  id: string
  kind: string
  negative_state?: string | null
  title: string | null
  body: string
  untrusted_data?: { title?: string; body?: string; notice?: string }
  provenance: string
  written_by: string
  status: string
  trust: string
  evidence_refs: string[]
  applicability?: { state: string }
  created_at?: string | null
}
export interface TargetNegativeResult {
  source: string
  negative_state: string
  server_owned: boolean
  record_ref?: { type: string; id: string }
  [key: string]: unknown
}

async function read<T>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, { cache: 'no-store', signal })
  if (!response.ok) throw new Error(await getApiErrorMessage(response, 'Could not load interpretations'))
  return response.json()
}

export async function getTargetInterpretations(id: string, signal?: AbortSignal) {
  const value = await read<{ interpretations?: unknown; has_more?: boolean }>(
    `/targets/${pathSegment(id)}/interpretations?limit=100`, signal)
  if (!Array.isArray(value.interpretations)) throw new Error('The server returned an invalid interpretation list.')
  return { entries: value.interpretations as TargetInterpretation[], hasMore: Boolean(value.has_more) }
}

export async function getTargetNegativeResults(id: string, signal?: AbortSignal) {
  const value = await read<{ rows?: unknown; has_more?: boolean }>(
    `/targets/${pathSegment(id)}/negative-results`, signal)
  if (!Array.isArray(value.rows)) throw new Error('The server returned an invalid negative-result list.')
  return { rows: value.rows as TargetNegativeResult[], hasMore: Boolean(value.has_more) }
}
