'use client'

import { Info, Network, ShieldCheck } from 'lucide-react'
import type { ReactNode } from 'react'


function text(value: any): string {
  return typeof value === 'string' ? value.trim() : ''
}


function values(value: any): string[] {
  return Array.isArray(value)
    ? value.map((item) => text(item)).filter(Boolean)
    : []
}


function displayDate(value: any): string {
  const raw = text(value)
  if (!raw) return 'Not published'
  const parsed = new Date(raw)
  if (Number.isNaN(parsed.getTime())) return raw
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(parsed)
}


function eventDate(events: any, names: string[]): string {
  if (!Array.isArray(events)) return ''
  const wanted = names.map((item) => item.toLowerCase())
  const row = events.find((item) => {
    const action = text(item?.action).toLowerCase()
    return wanted.some((name) => action.includes(name))
  })
  return text(row?.date)
}


function compactFingerprint(value: any): string {
  const raw = text(value)
  if (raw.length <= 28) return raw
  return `${raw.slice(0, 14)}…${raw.slice(-12)}`
}


function Field({ label, children, mono = false }: {
  label: string
  children: ReactNode
  mono?: boolean
}) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-950/50 p-3">
      <div className="text-xs font-medium uppercase tracking-wide text-gray-500">{label}</div>
      <div className={`mt-1 break-words text-sm text-gray-200 ${mono ? 'font-mono' : ''}`}>
        {children || <span className="text-gray-500">Not observed</span>}
      </div>
    </div>
  )
}


function scopeLabel(scope: string): { label: string; tone: string } {
  if (scope === 'likely_related') {
    return { label: 'Same registered domain', tone: 'border-blue-500/30 bg-blue-500/10 text-blue-200' }
  }
  return { label: 'Unverified association', tone: 'border-gray-700 bg-gray-800/70 text-gray-300' }
}


export default function InfrastructureIntelligenceSection({ infrastructure }: { infrastructure: any }) {
  if (!infrastructure || typeof infrastructure !== 'object' || Array.isArray(infrastructure)) return null

  const registration = infrastructure.registration && typeof infrastructure.registration === 'object'
    ? infrastructure.registration
    : null
  const registrar = registration?.registrar && typeof registration.registrar === 'object'
    ? registration.registrar
    : null
  const dns = infrastructure.dns && typeof infrastructure.dns === 'object'
    ? infrastructure.dns
    : {}
  const dnsAddresses = dns.addresses && typeof dns.addresses === 'object' ? dns.addresses : {}
  const addresses = Array.isArray(infrastructure.addresses)
    ? infrastructure.addresses.filter((item: any) => item && typeof item === 'object')
    : []
  const canonicalHost = text(infrastructure.canonical_host)
  const related = Array.isArray(infrastructure.related_names)
    ? infrastructure.related_names.filter((item: any) => {
      const name = text(item?.name).toLowerCase().replace(/^\*\./, '')
      return name && name !== canonicalHost.toLowerCase()
    })
    : []
  const nameservers = values(dns.nameservers).length
    ? values(dns.nameservers)
    : values(registration?.nameservers)
  const createdAt = eventDate(registration?.events, ['registration', 'registered'])
  const expiresAt = eventDate(registration?.events, ['expiration', 'expiry'])
  const updatedAt = eventDate(registration?.events, ['last changed', 'last update', 'updated'])
  const certificate = infrastructure.certificate && typeof infrastructure.certificate === 'object'
    ? infrastructure.certificate
    : null
  const recordMetadata = dns.record_metadata && typeof dns.record_metadata === 'object'
    ? Object.entries(dns.record_metadata).filter(([, item]: [string, any]) => item && typeof item === 'object')
    : []
  const errors = values(infrastructure.errors)

  return (
    <section className="mb-8 overflow-hidden rounded-lg border border-cyan-500/20 bg-gray-800/50 backdrop-blur-lg" aria-labelledby="target-infrastructure-heading">
      <div className="border-b border-cyan-500/15 bg-cyan-500/5 p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-cyan-200">
              <Network className="h-5 w-5" aria-hidden="true" />
              <h2 id="target-infrastructure-heading" className="text-2xl font-bold text-white">Target infrastructure</h2>
            </div>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-gray-300">
              Registration, DNS, certificate, and network relationships observed for this target.
              These facts provide investigation context; they are not vulnerability findings.
            </p>
          </div>
          <div className="inline-flex items-center gap-2 rounded-full border border-cyan-500/30 bg-cyan-500/10 px-3 py-1.5 text-xs font-semibold text-cyan-100">
            <ShieldCheck className="h-4 w-4" aria-hidden="true" />
            Informational only · does not affect score or grade
          </div>
        </div>
      </div>

      <div className="space-y-7 p-6">
        <div>
          <h3 className="text-sm font-semibold text-gray-200">Domain registration</h3>
          <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <Field label="Registered domain" mono>{text(infrastructure.registration_domain) || 'Not published'}</Field>
            <Field label="Registrar">{text(registrar?.name) || text(registrar?.handle) || 'Not published'}</Field>
            <Field label="Registered">{displayDate(createdAt)}</Field>
            <Field label="Expires">{displayDate(expiresAt)}</Field>
          </div>
          {(updatedAt || nameservers.length > 0 || registration?.dnssec_signed !== undefined) && (
            <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {updatedAt && <Field label="Registration updated">{displayDate(updatedAt)}</Field>}
              {nameservers.length > 0 && <Field label="Authoritative nameservers" mono>{nameservers.join(', ')}</Field>}
              {registration?.dnssec_signed !== undefined && (
                <Field label="RDAP DNSSEC delegation">{registration.dnssec_signed ? 'Signed' : 'Not reported as signed'}</Field>
              )}
            </div>
          )}
          {!registration && (
            <p className="mt-3 text-xs text-gray-500">Registration data was unavailable or redacted by the authoritative RDAP service.</p>
          )}
        </div>

        <div>
          <h3 className="text-sm font-semibold text-gray-200">Resolved network</h3>
          <div className="mt-3 space-y-3">
            {addresses.length > 0 ? addresses.map((row: any) => {
              const network = row.network && typeof row.network === 'object' ? row.network : {}
              const asn = row.asn && typeof row.asn === 'object' ? row.asn : {}
              const networkEntities = Array.isArray(network.entities) ? network.entities : []
              const owner = networkEntities.find((item: any) => text(item?.name))
              const cidrs = values(network.cidrs)
              const ptrNames = values(row.ptr_names)
              return (
                <div key={text(row.address)} className="rounded-lg border border-gray-800 bg-gray-950/45 p-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-mono text-sm font-semibold text-white">{text(row.address)}</span>
                    <span className="rounded-full border border-gray-700 px-2 py-0.5 text-xs text-gray-400">Bound target address</span>
                  </div>
                  <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                    <Field label="ASN">{text(asn.asn) ? `AS${text(asn.asn)}` : 'Not observed'}</Field>
                    <Field label="Network / provider">{text(asn.name) || text(owner?.name) || text(network.name) || 'Not published'}</Field>
                    <Field label="Allocated prefix" mono>{text(asn.prefix) || cidrs.join(', ') || 'Not published'}</Field>
                    <Field label="Country / registry">{[text(network.country) || text(asn.country), text(asn.registry)].filter(Boolean).join(' · ') || 'Not published'}</Field>
                  </div>
                  {ptrNames.length > 0 && (
                    <p className="mt-3 text-xs text-gray-400">
                      PTR name{ptrNames.length === 1 ? '' : 's'}: <span className="font-mono text-gray-300">{ptrNames.join(', ')}</span>
                    </p>
                  )}
                </div>
              )
            }) : (
              <div className="rounded-lg border border-dashed border-gray-700 p-4 text-sm text-gray-500">
                No address ownership context was returned. Frozen scan addresses: {[...values(dnsAddresses.A), ...values(dnsAddresses.AAAA)].join(', ') || 'none recorded'}.
              </div>
            )}
          </div>
        </div>

        <div className="grid gap-6 lg:grid-cols-2">
          <div>
            <h3 className="text-sm font-semibold text-gray-200">DNS topology</h3>
            <div className="mt-3 space-y-2 text-sm text-gray-300">
              {values(dns.cname).length > 0 && <p><span className="text-gray-500">CNAME:</span> <span className="font-mono">{values(dns.cname).join(', ')}</span></p>}
              {nameservers.length > 0 && <p><span className="text-gray-500">NS:</span> <span className="font-mono">{nameservers.join(', ')}</span></p>}
              {dns.soa?.primary_nameserver && <p><span className="text-gray-500">SOA:</span> <span className="font-mono">{text(dns.soa.primary_nameserver)}</span></p>}
              {recordMetadata.length > 0 && (
                <details className="rounded border border-gray-800 bg-gray-950/40 p-3">
                  <summary className="cursor-pointer text-xs font-medium text-gray-300">Record TTL and answer details</summary>
                  <div className="mt-3 grid gap-2 sm:grid-cols-2">
                    {recordMetadata.slice(0, 20).map(([label, item]: [string, any]) => (
                      <div key={label} className="font-mono text-xs text-gray-400">
                        {text(item.type) || label}: {item.answer_count ?? 0} answer{item.answer_count === 1 ? '' : 's'} · TTL {item.ttl ?? 'unknown'}
                      </div>
                    ))}
                  </div>
                </details>
              )}
              {!values(dns.cname).length && !nameservers.length && !dns.soa && !recordMetadata.length && (
                <p className="text-gray-500">No DNS topology details were returned.</p>
              )}
            </div>
          </div>

          <div>
            <h3 className="text-sm font-semibold text-gray-200">Certificate identity</h3>
            {certificate ? (
              <div className="mt-3 space-y-2 text-sm text-gray-300">
                <p><span className="text-gray-500">Subject:</span> {text(certificate.subject) || text(certificate.subject_dn) || 'Not published'}</p>
                <p><span className="text-gray-500">Issuer:</span> {text(certificate.issuer) || 'Not published'}</p>
                <p><span className="text-gray-500">Valid until:</span> {displayDate(certificate.not_after)}</p>
                {certificate.fingerprints?.sha256 && (
                  <p title={text(certificate.fingerprints.sha256)}><span className="text-gray-500">SHA-256:</span> <span className="font-mono">{compactFingerprint(certificate.fingerprints.sha256)}</span></p>
                )}
                {Array.isArray(certificate.sans) && (
                  <p><span className="text-gray-500">Certificate names:</span> {certificate.sans.length}</p>
                )}
              </div>
            ) : (
              <p className="mt-3 text-sm text-gray-500">No parsed HTTPS certificate was observed.</p>
            )}
          </div>
        </div>

        {related.length > 0 && (
          <div>
            <div className="flex items-center gap-2">
              <Info className="h-4 w-4 text-blue-300" aria-hidden="true" />
              <h3 className="text-sm font-semibold text-gray-200">Associated names</h3>
            </div>
            <p className="mt-2 text-xs leading-5 text-gray-400">
              These names came from PTR or certificate records. They are leads only, do not prove common ownership,
              are not automatically in scope, and were not scanned.
            </p>
            <div className="mt-3 flex flex-wrap gap-2">
              {related.slice(0, 50).map((item: any, index: number) => {
                const scope = scopeLabel(text(item.scope))
                return (
                  <div key={`${text(item.name)}-${text(item.source)}-${index}`} className="rounded-lg border border-gray-800 bg-gray-950/45 px-3 py-2">
                    <div className="font-mono text-xs text-gray-200">{text(item.name)}</div>
                    <div className="mt-1 flex items-center gap-2">
                      <span className={`rounded-full border px-2 py-0.5 text-[10px] ${scope.tone}`}>{scope.label}</span>
                      <span className="text-[10px] text-gray-500">{text(item.source).replaceAll('_', ' ')}</span>
                    </div>
                  </div>
                )
              })}
            </div>
            {related.length > 50 && <p className="mt-2 text-xs text-gray-500">Showing 50 of {related.length} associated names.</p>}
          </div>
        )}

        {(errors.length > 0 || values(infrastructure.limitations).length > 0) && (
          <details className="rounded-lg border border-gray-800 bg-gray-950/40 p-4">
            <summary className="cursor-pointer text-sm font-medium text-gray-300">Collection notes and limitations</summary>
            <ul className="mt-3 list-disc space-y-1 pl-5 text-xs leading-5 text-gray-500">
              {values(infrastructure.limitations).map((item) => <li key={item}>{item}</li>)}
              {errors.map((item) => <li key={item}>Unavailable source: {item.replaceAll('_', ' ')}</li>)}
            </ul>
          </details>
        )}
      </div>
    </section>
  )
}
