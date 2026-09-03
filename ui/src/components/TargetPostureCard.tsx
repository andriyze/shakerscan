'use client'

import Link from 'next/link'
import type { ReactElement } from 'react'

import { Card } from '@/components/ui'
import { formatDate, type TargetPosture, type TargetPostureSection } from '@/lib/api'

// The results page for one run also shows what earlier runs established about the target, because
// fast profiles skip some checks. Every section states where its facts came from: this run, an
// earlier run (with a link), or nothing yet. Absence is stated, never implied.

type SectionKey = keyof TargetPosture['sections']

const SECTION_TITLES: Record<SectionKey, string> = {
  http_headers: 'Security headers',
  tls: 'TLS',
  dns: 'DNS',
  network: 'Network and hosting',
}

const NOT_EXAMINED_HINT: Record<SectionKey, string> = {
  http_headers: 'No completed scan has observed an application response for this target yet.',
  tls: 'No completed scan has examined TLS for this target. Plain-HTTP targets have no TLS posture; for HTTPS targets a balanced or thorough profile enumerates protocols and ciphers.',
  dns: 'No completed scan has resolved DNS records for this target yet.',
  network: 'No completed scan has recorded addresses or registration for this target. Internal hosts often have none.',
}

function humanHeader(key: string): string {
  return key.replaceAll('_', '-')
}

function Provenance({ section, currentScanId }: { section: TargetPostureSection | null; currentScanId: string }) {
  if (!section) {
    return <span className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-400">not examined yet</span>
  }
  if (section.scan_id === currentScanId) {
    return <span className="rounded bg-blue-500/10 px-2 py-0.5 text-xs text-blue-200">observed in this scan</span>
  }
  return (
    <Link
      href={`/scans/${section.scan_id}`}
      className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-300 hover:text-white"
      title="This run did not observe this section; showing the newest observation from another scan"
    >
      from another scan{section.observed_at ? ` · ${formatDate(section.observed_at)}` : ''}
    </Link>
  )
}

function Facts({ items }: { items: Array<[string, string | number | boolean | null | undefined]> }) {
  const rows = items.filter(([, value]) => value !== null && value !== undefined && value !== '')
  if (rows.length === 0) return null
  return (
    <dl className="mt-2 grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 text-xs">
      {rows.map(([label, value]) => (
        <div key={label} className="contents">
          <dt className="text-gray-500">{label}</dt>
          <dd className="min-w-0 truncate text-gray-200" title={String(value)}>{String(value)}</dd>
        </div>
      ))}
    </dl>
  )
}

function HeadersBody({ payload }: { payload: Record<string, any> }) {
  const present = Object.entries(payload.present || {}) as Array<[string, string]>
  const missing: string[] = payload.missing || []
  const cookies: Array<Record<string, any>> = payload.cookies || []
  const weakCookies = cookies.filter((cookie) => !cookie.secure || !cookie.httponly)
  return (
    <div className="mt-2 space-y-2 text-xs">
      {missing.length > 0 && (
        <p className="text-amber-200">
          Missing: <span className="font-mono">{missing.join(', ')}</span>
        </p>
      )}
      {present.length > 0 ? (
        <ul className="space-y-0.5">
          {present.map(([key, value]) => (
            <li key={key} className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-2">
              <span className="font-mono text-gray-400">{humanHeader(key)}</span>
              <span className="min-w-0 truncate text-gray-200" title={value}>{value}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-gray-500">No security headers were present.</p>
      )}
      {payload.csp?.issues?.length > 0 && (
        <p className="text-amber-200/90">CSP issues: {payload.csp.issues.join('; ')}</p>
      )}
      {cookies.length > 0 && (
        <p className="text-gray-400">
          {cookies.length} cookie{cookies.length === 1 ? '' : 's'}
          {weakCookies.length > 0 ? `, ${weakCookies.length} without Secure or HttpOnly` : ', all Secure and HttpOnly'}
        </p>
      )}
    </div>
  )
}

function TlsBody({ payload }: { payload: Record<string, any> }) {
  const cert = payload.certificate || {}
  const protocols: string[] = payload.protocols || []
  const weak: string[] = payload.weak || []
  return (
    <div className="mt-2 space-y-2 text-xs">
      <Facts items={[
        ['Grade', payload.grade],
        ['Protocols', protocols.join(', ')],
        ['Certificate', cert.subject],
        ['Issuer', cert.issuer],
        ['Expires', cert.not_after ? formatDate(cert.not_after) : null],
        ['Key', [cert.key_algorithm, cert.key_bits ? `${cert.key_bits} bits` : null].filter(Boolean).join(' ')],
        ['Signature', cert.signature_algorithm],
        ['OCSP stapling', payload.ocsp_stapled === true ? 'yes' : payload.ocsp_stapled === false ? 'no' : null],
      ]} />
      {weak.length > 0 ? (
        <p className="text-amber-200">Weaknesses: {weak.join('; ')}</p>
      ) : protocols.length > 0 ? (
        <p className="text-gray-500">No weak protocol or cipher was reported.</p>
      ) : null}
      {cert.self_signed === true && <p className="text-amber-200">Certificate is self-signed.</p>}
      {cert.expired === true && <p className="text-red-300">Certificate has expired.</p>}
    </div>
  )
}

function DnsBody({ payload }: { payload: Record<string, any> }) {
  const records = Object.entries(payload.records || {}) as Array<[string, string[]]>
  const flags: Array<[string, string | null]> = [
    ['DNSSEC', payload.dnssec || null],
    ['DMARC', payload.dmarc_present ? 'present' : 'absent'],
    ['MTA-STS', payload.mta_sts_enabled ? 'enabled' : 'not enabled'],
    ['TLS-RPT', payload.tls_rpt_present ? 'present' : 'absent'],
    ['CAA', payload.caa_present ? 'present' : 'absent'],
  ]
  return (
    <div className="mt-2 space-y-2 text-xs">
      <ul className="space-y-0.5">
        {records.map(([name, values]) => (
          <li key={name} className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-2">
            <span className="font-mono uppercase text-gray-400">{name.replace(/^(host|root)_/, '')}</span>
            <span className="min-w-0 truncate text-gray-200" title={values.join(', ')}>{values.join(', ')}</span>
          </li>
        ))}
      </ul>
      <p className="text-gray-400">{flags.map(([label, value]) => `${label} ${value}`).join(' · ')}</p>
    </div>
  )
}

function NetworkBody({ payload }: { payload: Record<string, any> }) {
  const addresses: Array<Record<string, any>> = payload.addresses || []
  const registration = payload.registration || null
  return (
    <div className="mt-2 space-y-2 text-xs">
      {addresses.length > 0 && (
        <ul className="space-y-0.5">
          {addresses.map((address, index) => (
            <li key={`${address.ip || index}`} className="text-gray-200">
              <span className="font-mono">{address.ip}</span>
              {[address.asn, address.organization, address.country, address.provider].filter(Boolean).length > 0 && (
                <span className="text-gray-400"> · {[address.asn, address.organization, address.country, address.provider].filter(Boolean).join(' · ')}</span>
              )}
            </li>
          ))}
        </ul>
      )}
      {registration && (
        <Facts items={[
          ['Domain', registration.domain],
          ['Registrar', registration.registrar],
          ['Registered', registration.created ? formatDate(registration.created) : null],
          ['Expires', registration.expires ? formatDate(registration.expires) : null],
        ]} />
      )}
      {payload.related_names_count > 0 && (
        <p className="text-gray-500">{payload.related_names_count} related name{payload.related_names_count === 1 ? '' : 's'} on the same certificate or registration.</p>
      )}
      <p className="text-gray-600">Informational only; never scored.</p>
    </div>
  )
}

const BODIES: Record<SectionKey, (props: { payload: Record<string, any> }) => ReactElement> = {
  http_headers: HeadersBody,
  tls: TlsBody,
  dns: DnsBody,
  network: NetworkBody,
}

export function TargetPostureCard({
  posture,
  currentScanId,
  targetId,
  loading,
  error,
}: {
  posture: TargetPosture | null
  currentScanId: string
  targetId: string
  loading: boolean
  error: string | null
}) {
  const keys = Object.keys(SECTION_TITLES) as SectionKey[]
  const fromThisRun = posture ? keys.filter((key) => posture.sections[key]?.scan_id === currentScanId).length : 0
  const fromEarlier = posture ? keys.filter((key) => posture.sections[key] && posture.sections[key]!.scan_id !== currentScanId).length : 0
  return (
    <Card className="mb-6 p-4" data-testid="target-posture">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-gray-200">Target posture</h2>
          <p className="mt-1 text-xs text-gray-500">
            What is known about this target&apos;s headers, TLS, DNS, and network. Sections this run did not observe show the newest observation from another scan.
            {posture && (fromThisRun > 0 || fromEarlier > 0) && (
              <> {fromThisRun} observed in this run, {fromEarlier} carried from other scans.</>
            )}
          </p>
        </div>
        <Link href={`/targets/${targetId}/graph`} className="text-xs text-blue-300 hover:text-blue-200">
          Open target
        </Link>
      </div>
      {loading ? (
        <p className="mt-3 text-sm text-gray-500">Loading target posture…</p>
      ) : error ? (
        <p role="alert" className="mt-3 text-sm text-amber-300">{error}</p>
      ) : (
        <div className="mt-3 grid gap-3 md:grid-cols-2">
          {keys.map((key) => {
            const section = posture?.sections[key] ?? null
            const Body = BODIES[key]
            return (
              <section key={key} className="rounded-lg border border-gray-800 bg-gray-950/50 p-3" aria-label={SECTION_TITLES[key]}>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <h3 className="text-sm font-medium text-gray-200">{SECTION_TITLES[key]}</h3>
                  <Provenance section={section} currentScanId={currentScanId} />
                </div>
                {section ? (
                  <Body payload={section.payload} />
                ) : (
                  <p className="mt-2 text-xs leading-5 text-gray-500">{NOT_EXAMINED_HINT[key]}</p>
                )}
              </section>
            )
          })}
        </div>
      )}
    </Card>
  )
}
