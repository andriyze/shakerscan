// "What we found" for a finding: the observation its evidence already records, in reading order.
// Only fields the server stored are shown; nothing is inferred or un-redacted. Excerpts are the
// server's redacted_excerpt verbatim.

export interface ObservationFact {
  label: string
  value: string
  mono?: boolean
}

export interface ResponsePair {
  control: string
  payload: string
}

export interface ResponseHeader {
  name: string
  value: string
}

export interface FindingObservation {
  facts: ObservationFact[]
  excerpt: string | null
  signatures: string[]
  responsePairs: ResponsePair[]
  signals: string[]
  /** The recorded response's headers, for a finding about a header (sorted by name). */
  responseHeaders: ResponseHeader[]
}

type EvidenceRecord = Record<string, unknown>

function record(value: unknown): EvidenceRecord | null {
  if (!value) return null
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value)
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as EvidenceRecord : null
    } catch {
      return null
    }
  }
  return typeof value === 'object' && !Array.isArray(value) ? value as EvidenceRecord : null
}

function text(value: unknown): string {
  if (typeof value === 'string') return value.trim()
  if (typeof value === 'number' && Number.isFinite(value)) return String(value)
  return ''
}

function strings(value: unknown): string[] {
  if (typeof value === 'string') return value.trim() ? [value.trim()] : []
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string' && item.trim() !== '').map((item) => item.trim()) : []
}

// 'private_key_material' -> 'Private key material'
export function humanizeToken(value: string): string {
  const spaced = value.replace(/[_-]+/g, ' ').replace(/\s+/g, ' ').trim()
  return spaced ? spaced.charAt(0).toUpperCase() + spaced.slice(1) : ''
}

// Fact order follows the reading order of an observation: what was exposed or injected, where and
// how it was requested, what came back, how it was found.
const FACTS: Array<{ keys: string[]; label: string; humanize?: boolean; mono?: boolean }> = [
  { keys: ['header_absent', 'header_name'], label: 'Missing header', mono: true },
  { keys: ['exposure_class'], label: 'Exposed', humanize: true },
  { keys: ['dbms'], label: 'Database' },
  { keys: ['technique'], label: 'Technique', humanize: true },
  { keys: ['request_line'], label: 'Request', mono: true },
  { keys: ['method', 'request_method'], label: 'Method', mono: true },
  { keys: ['field_path', 'param', 'parameter'], label: 'Parameter', mono: true },
  { keys: ['payload'], label: 'Payload', mono: true },
  { keys: ['response_status', 'status_code'], label: 'HTTP status', mono: true },
  { keys: ['content_type'], label: 'Content type', mono: true },
  { keys: ['repetitions'], label: 'Confirmed', },
  { keys: ['matched_url_count'], label: 'Pages matched' },
  { keys: ['discovered_via'], label: 'Found via', humanize: true },
  { keys: ['evidence_type'], label: 'Evidence', humanize: true },
]

export function findingObservation(evidence: unknown): FindingObservation {
  const stored = record(evidence)
  if (!stored) return { facts: [], excerpt: null, signatures: [], responsePairs: [], signals: [], responseHeaders: [] }
  // A header finding carries the scan's recorded response for its origin; its request line,
  // status and header set read as part of the same observation.
  const observed = record(stored.observed_response)
  const data: EvidenceRecord = observed ? { ...observed, ...stored } : stored

  const facts: ObservationFact[] = []
  for (const spec of FACTS) {
    const key = spec.keys.find((candidate) => text(data[candidate]))
    if (!key) continue
    const raw = text(data[key])
    const value = key === 'repetitions'
      ? `${raw} independent ${raw === '1' ? 'repetition' : 'repetitions'}`
      : spec.humanize ? humanizeToken(raw) : raw
    facts.push({ label: spec.label, value, mono: spec.mono })
  }

  const excerpt = text(data.redacted_excerpt) || null
  const signatures = [...strings(data.matched_signature), ...strings(data.database_error_signatures)]
  const responsePairs: ResponsePair[] = Array.isArray(data.response_pairs)
    ? data.response_pairs
        .map((pair) => record(pair))
        .filter((pair): pair is EvidenceRecord => pair !== null)
        .map((pair) => ({ control: text(pair.control_status), payload: text(pair.payload_status) }))
        .filter((pair) => pair.control || pair.payload)
    : []
  const signals = Array.from(new Set([
    ...strings(data.evidence),
    ...strings(data.extraction_evidence),
  ]))

  const headers = record(observed?.observed_headers)
  const responseHeaders = headers
    ? Object.entries(headers)
        .map(([name, value]) => ({ name, value: text(value) }))
        .filter((header) => header.name && header.value)
        .sort((a, b) => a.name.localeCompare(b.name))
    : []

  return { facts, excerpt, signatures, responsePairs, signals, responseHeaders }
}

export function hasObservation(observation: FindingObservation): boolean {
  return observation.facts.length > 0
    || Boolean(observation.excerpt)
    || observation.signatures.length > 0
    || observation.responsePairs.length > 0
    || observation.signals.length > 0
    || observation.responseHeaders.length > 0
}

// The API's latest_retest_verdict falls back to the scan-time verification verdict when no retest
// row exists. Labelling that "latest replay" next to "0 attempts" read as a contradiction: say
// which one it is.
export function verificationSource(input: {
  retestRuns: number
  latestRetestStatus?: string | null
  verificationCount?: number | null
}): 'retest' | 'scan_time' {
  if (input.retestRuns > 0) return 'retest'
  if (input.latestRetestStatus) return 'retest'
  if ((input.verificationCount ?? 0) > 0) return 'retest'
  return 'scan_time'
}

export function hostOf(url: string | null | undefined): string {
  if (!url) return ''
  try {
    return new URL(url).host
  } catch {
    return ''
  }
}

// Path plus query names (never values) so a location is readable without leaking parameters.
export function pathOf(url: string | null | undefined): string {
  if (!url) return ''
  try {
    const parsed = new URL(url)
    const names = Array.from(new Set(Array.from(parsed.searchParams.keys())))
    return `${parsed.pathname || '/'}${names.length ? `?${names.join('&')}` : ''}`
  } catch {
    return url
  }
}
