// Bounded presentation of fields the server retained. Target text remains plain text;
// template classification and severity rationale never create a proof verdict.
type RecordValue = Record<string, unknown>
export type DetailFact = { label: string; value: string }
export type DetailGroup = { title: string; facts: DetailFact[] }
export type DetailEvidence = { groups: DetailGroup[]; severityReason: string | null }

function record(value: unknown): RecordValue {
  if (typeof value === 'string' && value.length <= 2_000_000) {
    try { return record(JSON.parse(value)) } catch { return {} }
  }
  return value && typeof value === 'object' && !Array.isArray(value) ? value as RecordValue : {}
}

function text(value: unknown, max = 600): string {
  if (typeof value === 'string') return value.trim().slice(0, max)
  return typeof value === 'number' && Number.isFinite(value) ? String(value) : ''
}

function list(value: unknown, max = 25): string {
  return Array.isArray(value) ? value.slice(0, max).map(item => text(item, 300)).filter(Boolean).join(', ') : ''
}

function facts(source: RecordValue, fields: Array<[string, string]>): DetailFact[] {
  return fields.map(([key, label]) => ({ label, value: text(source[key]) })).filter(item => item.value)
}

export function findingDetailEvidence(value: unknown): DetailEvidence {
  const stored = record(value)
  const groups: DetailGroup[] = []
  const add = (title: string, entries: DetailFact[]) => { if (entries.length) groups.push({ title, facts: entries }) }
  const trust = record(stored.trust)
  add('TLS observation', [
    ...facts(stored, [['requested_host', 'Requested host'], ['pinned_address', 'Connected address'],
      ['protocol', 'Negotiated protocol']]),
    // A weak-cipher finding stores the weak suite it is about as `cipher` and the suite a normal
    // handshake negotiates as `negotiated_cipher`; the weak suite is not what was negotiated.
    { label: 'Negotiated cipher', value: text(stored.negotiated_cipher) || text(stored.cipher) },
    { label: 'Weak suites accepted', value: list(stored.weak_ciphers_supported, 12) },
    ...facts(stored, [['chain_status', 'Chain capture']]),
    ...facts(trust, [['result', 'Chain trust'], ['failure', 'Verifier reason'],
      ['error_code', 'Verifier code'], ['error', 'Verifier message']]),
    { label: 'Protocols observed', value: list(stored.supported_protocols, 6) },
    { label: 'Other origins serving this certificate', value: list(stored.same_certificate_origins, 10) },
  ].filter(item => item.value))
  const cert = record(stored.certificate)
  add('Certificate presented', [
    ...facts(cert, [['subject', 'Subject'], ['issuer', 'Issuer'], ['serial_hex', 'Serial'],
      ['not_before', 'Valid from'], ['not_after', 'Valid until'], ['days_remaining', 'Days remaining'],
      ['public_key_type', 'Public key'], ['public_key_bits', 'Key bits'],
      ['signature_hash', 'Signature hash'], ['sha256', 'SHA-256']]),
    { label: 'DNS names (up to 25)', value: list(cert.dns_names) },
    { label: 'IP addresses (up to 25)', value: list(cert.ip_addresses) },
    { label: 'DNS names recorded', value: text(cert.dns_name_count) },
    { label: 'Issuer locations recorded', value: list(cert.aia_ca_issuers, 3) },
  ].filter(item => item.value))
  if (Array.isArray(stored.chain)) stored.chain.slice(0, 6).forEach((entry, index) => {
    add(`Presented chain certificate ${index + 1}`, facts(record(entry), [
      ['subject', 'Subject'], ['issuer', 'Issuer'], ['not_before', 'Valid from'],
      ['not_after', 'Valid until'], ['sha256', 'SHA-256'], ['parse_status', 'Parse status'],
    ]))
  })
  add('Template metadata', [
    ...facts(stored, [['template_id', 'Template'], ['template_description', 'Description'],
      ['cvss_score', 'Template CVSS'], ['cvss_metrics', 'CVSS vector'], ['epss_score', 'EPSS'],
      ['epss_percentile', 'EPSS percentile']]),
    { label: 'CVE identifiers', value: list(stored.cve_ids, 5) },
    { label: 'CWE identifiers', value: list(stored.cwe_ids, 5) },
  ].filter(item => item.value))
  const basis = record(stored.severity_basis)
  return { groups, severityReason: basis.schema === 'severity-basis/v1' ? text(basis.reason, 1200) || null : null }
}

export function hasDetailEvidence(value: DetailEvidence): boolean {
  return value.groups.length > 0 || Boolean(value.severityReason)
}
