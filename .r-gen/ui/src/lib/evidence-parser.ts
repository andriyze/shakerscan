/**
 * Evidence Parser - Extracts structured data from finding evidence JSON
 */

export interface ResponseAnomaly {
  before: number
  after: number
  diff: number
  percentChange: number
}

export interface ParsedEvidence {
  // Primary evidence
  url: string
  parameter?: string
  payload?: string
  context?: string  // html, attribute, json, etc.

  // All occurrences
  allUrls: string[]
  allPayloads: string[]
  duplicateCount: number

  // Detection details
  evidenceDetails: string[]
  responseAnomaly?: ResponseAnomaly

  // Remediation
  remediation: string[]

  // HTTP details (if available)
  request?: string
  response?: string
  statusCode?: number

  // Metadata
  tool?: string
  description?: string
}

/**
 * Parse evidence from a finding (handles both string and object)
 */
export function parseEvidence(evidence: string | object | null | undefined): ParsedEvidence {
  if (!evidence) {
    return createEmptyEvidence()
  }

  try {
    const data = typeof evidence === 'string' ? JSON.parse(evidence) : evidence

    // Extract response anomaly from evidence array
    let responseAnomaly: ResponseAnomaly | undefined
    const evidenceArray = data.evidence || []
    for (const e of evidenceArray) {
      if (typeof e === 'string') {
        const match = e.match(/(\d+)\s*->\s*(\d+)/)
        if (match) {
          const before = parseInt(match[1])
          const after = parseInt(match[2])
          const diff = after - before
          responseAnomaly = {
            before,
            after,
            diff,
            percentChange: before > 0 ? Math.round((diff / before) * 100) : 0
          }
          break
        }
      }
    }

    // Extract remediation from tool_metadata
    let remediation: string[] = []
    if (data.tool_metadata && Array.isArray(data.tool_metadata) && data.tool_metadata.length > 0) {
      remediation = data.tool_metadata[0]?.remediation || []
    }

    return {
      url: data.url || '',
      parameter: data.parameter,
      payload: data.payload,
      context: data.context,
      allUrls: data.all_urls || (data.url ? [data.url] : []),
      allPayloads: data.all_payloads || (data.payload ? [data.payload] : []),
      duplicateCount: data.duplicate_count || 1,
      evidenceDetails: evidenceArray.filter((e: any) => typeof e === 'string'),
      responseAnomaly,
      remediation,
      request: data.request,
      response: data.response,
      statusCode: data.status_code,
      tool: data.tool_metadata?.[0]?.tool,
      description: data.tool_metadata?.[0]?.description
    }
  } catch {
    // If parsing fails, try to extract what we can
    if (typeof evidence === 'string') {
      return {
        ...createEmptyEvidence(),
        evidenceDetails: [evidence]
      }
    }
    return createEmptyEvidence()
  }
}

function createEmptyEvidence(): ParsedEvidence {
  return {
    url: '',
    allUrls: [],
    allPayloads: [],
    duplicateCount: 0,
    evidenceDetails: [],
    remediation: []
  }
}

/**
 * Extract endpoint path from full URL
 */
export function extractEndpoint(url: string): string {
  try {
    const urlObj = new URL(url)
    return urlObj.pathname + urlObj.search
  } catch {
    // If URL parsing fails, try to extract path manually
    const match = url.match(/https?:\/\/[^/]+(\/[^?]*)?(\?.*)?/)
    if (match) {
      return (match[1] || '/') + (match[2] || '')
    }
    return url
  }
}

/**
 * Format bytes to human readable
 */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

/**
 * Format response anomaly for display
 */
export function formatAnomaly(anomaly: ResponseAnomaly): string {
  const sign = anomaly.percentChange >= 0 ? '+' : ''
  return `${formatBytes(anomaly.before)} → ${formatBytes(anomaly.after)} (${sign}${anomaly.percentChange}%)`
}

/**
 * Decode URL-encoded payload for display
 */
export function decodePayload(payload: string): string {
  try {
    return decodeURIComponent(payload)
  } catch {
    return payload
  }
}

/**
 * Extract payload from URL query string
 */
export function extractPayloadFromUrl(url: string, parameter?: string): string | null {
  try {
    const urlObj = new URL(url)
    if (parameter) {
      return urlObj.searchParams.get(parameter)
    }
    // If no parameter specified, return the full query string
    return urlObj.search.slice(1) || null
  } catch {
    return null
  }
}
