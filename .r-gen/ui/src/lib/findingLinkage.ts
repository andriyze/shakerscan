type FindingLike = Record<string, unknown>

function evidenceRecord(value: unknown): FindingLike {
  if (!value) return {}
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value)
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
        ? parsed as FindingLike
        : {}
    } catch {
      return {}
    }
  }
  return typeof value === 'object' && !Array.isArray(value)
    ? value as FindingLike
    : {}
}

function normalizedText(value: unknown): string {
  return String(value ?? '').trim().replace(/\s+/g, ' ').toLowerCase()
}

function normalizedUrl(value: unknown): string {
  const raw = String(value ?? '').trim()
  if (!raw) return ''
  try {
    const parsed = new URL(raw)
    parsed.hash = ''
    return parsed.toString().replace(/\/$/, '')
  } catch {
    return raw.replace(/\/$/, '').toLowerCase()
  }
}

export function findingLinkageKeys(finding: FindingLike): string[] {
  const evidence = evidenceRecord(finding.evidence)
  const explicit = [
    finding.id,
    finding.fingerprint,
    finding.source_finding_id,
    evidence.source_finding_id,
    evidence.fingerprint,
  ].map((value) => normalizedText(value)).filter(Boolean).map((value) => `explicit:${value}`)

  const title = normalizedText(finding.title)
  const url = normalizedUrl(finding.url || finding.matched_at || evidence.url)
  const tool = normalizedText(finding.tool || evidence.tool)
  const inferred = title && url
    ? [
        ...(tool ? [`identity:${tool}|${title}|${url}`] : []),
        `identity:${title}|${url}`,
      ]
    : []
  return Array.from(new Set([...explicit, ...inferred]))
}

export function buildFindingLinkageIndex(findings: FindingLike[]): Map<string, FindingLike> {
  const index = new Map<string, FindingLike>()
  for (const finding of findings) {
    for (const key of findingLinkageKeys(finding)) {
      if (!index.has(key)) index.set(key, finding)
    }
  }
  return index
}

export function linkedPersistedFinding(
  finding: FindingLike,
  index: Map<string, FindingLike>,
): FindingLike | null {
  for (const key of findingLinkageKeys(finding)) {
    const match = index.get(key)
    if (match) return match
  }
  return null
}

// A report result was observed by the scan that reported it. Show it with its durable record's
// lifecycle when one is linked, and otherwise as seen when that scan completed: a result read
// on its own carries no last_seen_at, which rendered findings this very run found as
// "never observed".
export function observedReportFinding(
  finding: FindingLike,
  persisted: FindingLike | null,
  observedAt: unknown,
): FindingLike {
  const seenAt = persisted?.last_seen_at || observedAt || null
  return {
    ...finding,
    first_seen_at: persisted?.first_seen_at || finding.first_seen_at || seenAt,
    last_seen_at: seenAt,
    ...(persisted?.status ? { status: persisted.status } : {}),
  }
}
