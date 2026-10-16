// The server's per-class finding brief (finding-detail/v1), parsed defensively and bounded.
// Every string is rendered as plain text; commands are shown and copied, never executed.
type Rec = Record<string, unknown>

export type BriefFact = { label: string; value: string; mono: boolean }
export type BriefCommand = { command: string; expect: string; note: string }
export type BriefSecret = { field: string; category: string; length: number | null; ref: string }
export type BriefCve = { id: string; nvd: string; title: string; affected: string[]; fixedIn: string[]; kev: { dateAdded: string; ransomware: boolean } | null; epss: number | null }
export type BriefSeverity = { severity: string; reason: string; source: string; policy: string; producerSeverity: string; currentRule: { severity: string; reason: string } | null; proofNote: string }
export type RelatedFinding = { id: string; title: string; severity: string; url: string; relation: string }
export type FindingBrief = {
  cls: string
  label: string
  summary: string
  where: BriefFact[]
  observed: BriefFact[]
  expected: string[]
  excerpt: { label: string; text: string } | null
  secrets: BriefSecret[]
  secretRefs: string[]
  pairs: Array<{ control: string; payload: string }>
  cves: BriefCve[]
  context: string[]
  confidence: { level: string; reason: string } | null
  reproduce: BriefCommand | null
  verify: BriefCommand | null
  fix: string[]
  examples: Array<{ label: string; code: string }>
  references: string[]
  severity: BriefSeverity | null
}

function rec(value: unknown): Rec {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Rec : {}
}

function str(value: unknown, max = 1200): string {
  if (typeof value === 'string') return value.slice(0, max)
  return typeof value === 'number' && Number.isFinite(value) ? String(value) : ''
}

function arr(value: unknown, max = 25): unknown[] {
  return Array.isArray(value) ? value.slice(0, max) : []
}

function strs(value: unknown, max = 25, chars = 1200): string[] {
  return arr(value, max).map(item => str(item, chars)).filter(Boolean)
}

function facts(value: unknown): BriefFact[] {
  return arr(value, 30).map(rec).map(item => ({ label: str(item.label, 120), value: str(item.value, 1200), mono: item.mono === true }))
    .filter(item => item.label && item.value)
}

function cmd(value: unknown): BriefCommand | null {
  const item = rec(value)
  const command = str(item.command, 2000)
  return command ? { command, expect: str(item.expect, 400), note: str(item.note, 400) } : null
}

const SECRET_REF = /^secret:\/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

export function parseFindingBrief(value: unknown): FindingBrief | null {
  const raw = rec(value)
  if (raw.schema !== 'finding-detail/v1') return null
  const confidence = rec(raw.confidence)
  const severity = rec(raw.severity)
  const current = rec(severity.current_rule)
  const excerpt = rec(raw.excerpt)
  return {
    cls: str(raw.class, 120),
    label: str(raw.class_label, 200),
    summary: str(raw.summary, 1500),
    where: facts(raw.where),
    observed: facts(raw.observed),
    expected: strs(raw.expected, 6, 600),
    excerpt: str(excerpt.text, 1500) ? { label: str(excerpt.label, 120) || 'Response excerpt', text: str(excerpt.text, 1500) } : null,
    secrets: arr(raw.secrets, 50).map(rec).map(item => ({
      field: str(item.field, 120), category: str(item.category, 60),
      length: typeof item.length === 'number' ? item.length : null,
      ref: SECRET_REF.test(str(item.ref, 60)) ? str(item.ref, 60) : '',
    })).filter(item => item.field || item.category),
    secretRefs: strs(raw.secret_refs, 20, 60).filter(ref => SECRET_REF.test(ref)),
    pairs: arr(raw.pairs, 6).map(rec).map(item => ({ control: str(item.control, 40), payload: str(item.payload, 40) })).filter(item => item.control || item.payload),
    cves: arr(raw.cves, 3).map(rec).map(item => {
      const kev = rec(item.known_exploited)
      const epss = rec(item.epss)
      return {
        id: str(item.id, 30), nvd: /^https:\/\/nvd\.nist\.gov\//.test(str(item.nvd, 200)) ? str(item.nvd, 200) : '',
        title: str(item.title, 200), affected: strs(item.affected, 6, 200), fixedIn: strs(item.fixed_in, 6, 200),
        kev: Object.keys(kev).length ? { dateAdded: str(kev.date_added, 10), ransomware: kev.ransomware === true } : null,
        epss: typeof epss.score === 'number' ? epss.score : null,
      }
    }).filter(item => /^CVE-\d{4}-\d{4,}$/.test(item.id)),
    context: strs(raw.context, 8, 800),
    confidence: str(confidence.level, 20) ? { level: str(confidence.level, 20), reason: str(confidence.reason, 800) } : null,
    reproduce: cmd(raw.reproduce),
    verify: cmd(raw.verify),
    fix: strs(raw.fix, 10, 800),
    examples: arr(raw.examples, 6).map(rec).map(item => ({ label: str(item.label, 60), code: str(item.code, 2000) })).filter(item => item.label && item.code),
    references: strs(raw.references, 5, 300).filter(link => /^https?:\/\//i.test(link)),
    severity: str(severity.severity, 20) ? {
      severity: str(severity.severity, 20), reason: str(severity.reason, 1200), source: str(severity.source, 30),
      policy: str(severity.policy, 400), producerSeverity: str(severity.producer_severity, 20),
      currentRule: str(current.severity, 20) ? { severity: str(current.severity, 20), reason: str(current.reason, 1200) } : null,
      proofNote: str(severity.proof_note, 300),
    } : null,
  }
}

export function parseRelatedFindings(value: unknown): RelatedFinding[] {
  return arr(value, 8).map(rec).map(item => ({
    id: str(item.id, 80), title: str(item.title, 200), severity: str(item.severity, 20), url: str(item.url, 400), relation: str(item.relation, 80),
  })).filter(item => /^[0-9a-f-]{36}$/i.test(item.id) && item.title)
}

// One line for the page header: "Why medium: <first sentence of the reason>".
export function severityLine(brief: FindingBrief | null): string {
  const reason = brief?.severity?.reason || ''
  if (!reason) return ''
  const first = reason.match(/^.*?[.!?](?=\s|$)/)?.[0] || reason
  return first.length > 220 ? `${first.slice(0, 217)}…` : first
}

export function secretLink(targetId: string | undefined, ref: string): string {
  return targetId && SECRET_REF.test(ref) ? `/targets/${encodeURIComponent(targetId)}/asset#discovered-secrets` : ''
}

// Query values the server replaced with a redaction marker. Shown masked, never as the literal marker.
const REDACTED_VALUE = /^(?:<redacted>|\[redacted\]|redacted|\*{3,}|•+)$/i

// A stored URL with redacted query values: `display` masks only those values (••• ),
// `usable` drops them (`q=`) so a copied or opened URL reaches the same endpoint.
export function maskedUrl(url: string): { display: string; usable: string; masked: boolean } {
  let parsed: URL
  try { parsed = new URL(url) } catch { return { display: url, usable: url, masked: false } }
  let masked = false
  const shown: string[] = []
  const usable = new URL(parsed.toString())
  usable.search = ''
  for (const [name, value] of parsed.searchParams) {
    if (REDACTED_VALUE.test(value.trim())) {
      masked = true
      shown.push(`${name}=•••`)
      usable.searchParams.append(name, '')
    } else {
      shown.push(`${name}=${value}`)
      usable.searchParams.append(name, value)
    }
  }
  if (!masked) return { display: url, usable: url, masked: false }
  const base = `${parsed.origin}${parsed.pathname}`
  return { display: `${base}?${shown.join('&')}`, usable: usable.toString(), masked: true }
}

// "Potential SQL injection" once a deterministic proof verified it reads as the proven issue.
export function displayTitle(title: string, proofVerified: boolean): string {
  if (!proofVerified) return title
  const stripped = title.replace(/^(?:potential|possible|suspected)\s+/i, '')
  return stripped === title ? title : stripped.charAt(0).toUpperCase() + stripped.slice(1)
}
