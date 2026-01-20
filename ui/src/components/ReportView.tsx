'use client'

import React, { useState } from 'react'
import ExportPDFButton from '@/components/ExportPDFButton'
import ComplianceSection from '@/components/ComplianceSection'
import RemediationSummary from '@/components/RemediationSummary'
import FindingActions from '@/components/FindingActions'
import FindingCard from '@/components/FindingCard'

type RemediationStatus = 'open' | 'in_progress' | 'remediated' | 'false_positive' | 'accepted_risk'

type RemediationData = {
  finding_id: string
  status: RemediationStatus
  notes?: string
}

type Props = {
  scan: any
  shareControls?: React.ReactNode
  isAuthenticated?: boolean
  remediations?: RemediationData[]
  enableRemediationTracking?: boolean
}

function getSeverityPill(severity?: string) {
  const s = (severity || '').toLowerCase()
  return s === 'critical'
    ? 'bg-red-900 text-red-200'
    : s === 'high'
    ? 'bg-orange-900 text-orange-200'
    : s === 'medium'
    ? 'bg-yellow-900 text-yellow-200'
    : s === 'low'
    ? 'bg-blue-900 text-blue-200'
    : 'bg-slate-700 text-slate-300'
}

function getSeverityBorderClass(severity?: string) {
  const s = (severity || '').toLowerCase()
  return s === 'critical'
    ? 'border-red-500'
    : s === 'high'
    ? 'border-orange-500'
    : s === 'medium'
    ? 'border-yellow-500'
    : s === 'low'
    ? 'border-blue-500'
    : 'border-slate-500'
}

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
}

function sortBySeverity(findings: any[]): any[] {
  return [...findings].sort((a, b) => {
    const severityA = SEVERITY_ORDER[(a.severity || 'info').toLowerCase()] ?? 5
    const severityB = SEVERITY_ORDER[(b.severity || 'info').toLowerCase()] ?? 5
    return severityA - severityB
  })
}

function getGradeColor(grade?: string) {
  switch (grade) {
    case 'A': case 'A+': return 'text-green-500'
    case 'B': return 'text-lime-500'
    case 'C': return 'text-yellow-500'
    case 'D': return 'text-orange-500'
    case 'F': return 'text-red-500'
    default: return 'text-gray-500'
  }
}

function renderGenericEvidence(evidence: any): string {
  if (!evidence) return ''
  if (typeof evidence === 'string') return evidence
  const preferredFields = ['url', 'description', 'message', 'issue', 'path', 'parameter', 'payload', 'matched_at', 'note']
  for (const field of preferredFields) {
    if (evidence[field] && typeof evidence[field] === 'string') {
      return evidence[field]
    }
  }
  try {
    const json = JSON.stringify(evidence, null, 2)
    return json.length > 300 ? json.slice(0, 300) + '...' : json
  } catch {
    return String(evidence)
  }
}

function renderFindingEvidence(finding: any) {
  const evidence = finding.evidence || finding.description
  const text = renderGenericEvidence(evidence)
  if (!text) return null
  return <p className="text-gray-300 text-sm mt-1 whitespace-pre-wrap break-words">{text}</p>
}

export default function ReportView({ scan, shareControls, isAuthenticated, remediations = [], enableRemediationTracking = false }: Props) {
  const [remediationData, setRemediationData] = useState<RemediationData[]>(remediations)
  const scanData = scan.result || scan.results || {}
  const input = scanData.input || {}
  const dns = scanData.dns || {}
  const tls = scanData.tls || {}
  const http = scanData.http || {}
  const discovery = scanData.discovery || {}
  const server_versions = discovery.server_versions || {}
  const rawFindings = scanData.findings || []
  const findings = sortBySeverity(rawFindings)
  const result = scanData.result || {}
  const js_dependencies = scanData.js_dependencies || {}
  const js_secrets = scanData.js_secrets || {}
  const cicd_exposure = scanData.cicd_exposure || {}
  const package_exposure = scanData.package_exposure || {}
  const cloud_buckets = scanData.cloud_buckets || {}
  const backup_files = scanData.backup_files || {}
  const delta = scanData.delta || {}
  const ssh = scanData.ssh || {}
  const noise_reduction_stats = scanData.noise_reduction_stats || {}
  const network_scan = scanData.network_scan || {}
  const network_services = scanData.network_services || {}
  const active_checks = scanData.active_checks || {}
  const access_control = scanData.access_control || {}
  const cloud_ssrf = scanData.cloud_ssrf || {}
  const kubernetes_exposure = scanData.kubernetes_exposure || {}
  const container_registry = scanData.container_registry || {}
  const scan_metadata = scanData.scan_metadata || {}
  const coverage = scanData.coverage || {}
  const smart_coverage = scanData.smart_coverage || {}
  const ai_logs = scanData.ai_logs || null
  const ai_summary = ai_logs?.summary || null
  const ai_executive = ai_summary?.executive_summary || null

  const [expandedAI, setExpandedAI] = useState<Set<string>>(new Set())
  const [severityFilter, setSeverityFilter] = useState<Set<string>>(new Set(['critical', 'high', 'medium', 'low', 'info']))

  const toggleAIDetails = (id: string) => {
    setExpandedAI(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  const toggleSeverityFilter = (severity: string) => {
    setSeverityFilter(prev => {
      const next = new Set(prev)
      next.has(severity) ? next.delete(severity) : next.add(severity)
      return next
    })
  }

  const filteredFindings = findings.filter((f: any) => severityFilter.has(f.severity?.toLowerCase() || 'info'))

  const handleDownloadJson = () => {
    const dataStr = JSON.stringify(scanData, null, 2)
    const blob = new Blob([dataStr], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `scan-${input.normalized_host || 'result'}-${new Date().toISOString().slice(0,10)}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  return (
    <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Scan Summary */}
      <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
        <div className="flex justify-between items-start mb-4">
          <div>
            <h1 className="text-3xl font-bold mb-2">
              {scan.url || scan.target_url || input.target || 'Unknown Target'}
            </h1>
            <p className="text-gray-400">
              Scanned on {new Date(scan.created_at).toLocaleDateString()} at {new Date(scan.created_at).toLocaleTimeString()}
            </p>
            {input.normalized_host && (
              <p className="text-sm text-gray-500 mt-1">
                Host: {input.normalized_host} | Port: {input.port || 443} | Scheme: {input.scheme || 'https'}
              </p>
            )}
          </div>
          <div className="text-right flex flex-col items-end gap-2">
            <div className="flex items-center gap-2 no-print">
              {shareControls}
              <ExportPDFButton />
              {isAuthenticated && (
                <button onClick={handleDownloadJson} className="px-3 py-2 rounded border border-blue-500/60 text-blue-300 text-sm hover:bg-blue-500/10">
                  Download JSON
                </button>
              )}
            </div>
            {(scan.grade || result.grade) && (
              <div className={`text-5xl font-bold ${getGradeColor(scan.grade || result.grade)}`}>
                {scan.grade || result.grade}
              </div>
            )}
            {(scan.score !== null || result.score !== null) && (
              <div className="text-xl text-gray-400">Score: {scan.score || result.score}/100</div>
            )}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mt-6">
          <div className="bg-gray-700/50 rounded-lg p-4">
            <h3 className="text-sm text-gray-400 mb-1">Status</h3>
            <p className="text-lg font-semibold capitalize">{scan.status}</p>
          </div>
          <div className="bg-gray-700/50 rounded-lg p-4">
            <h3 className="text-sm text-gray-400 mb-1">Scan Type</h3>
            <p className="text-lg font-semibold capitalize">{scan.scan_type || 'Standard'}</p>
          </div>
          <div className="bg-gray-700/50 rounded-lg p-4">
            <h3 className="text-sm text-gray-400 mb-1">Scan Mode</h3>
            <p className="text-lg font-semibold capitalize">
              {scan.options?.quick ? 'Quick' : 'Thorough'}
              {scan.options?.active && ' + Active'}
            </p>
          </div>
          <div className="bg-gray-700/50 rounded-lg p-4">
            <h3 className="text-sm text-gray-400 mb-1">Issues Found</h3>
            <p className="text-lg font-semibold">{Array.isArray(findings) ? findings.length : 0}</p>
          </div>
        </div>
      </div>

      {/* Compliance */}
      {result?.compliance && <ComplianceSection compliance={result.compliance} />}

      {/* Remediation Summary */}
      {enableRemediationTracking && findings.length > 0 && (
        <RemediationSummary remediations={remediationData} totalFindings={findings.length} />
      )}

      {/* WAF Detection */}
      {discovery.waf_detection?.detected && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">WAF Detection</h2>
          <div className="bg-yellow-900/20 border border-yellow-500/40 rounded-lg p-4">
            <div className="flex items-center gap-3">
              <svg className="w-6 h-6 text-yellow-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              <div>
                <span className="text-yellow-400 font-medium text-lg">
                  {discovery.waf_detection.product || 'Web Application Firewall Detected'}
                </span>
                {discovery.waf_detection.confidence && (
                  <span className="ml-2 text-gray-400 text-sm">
                    ({discovery.waf_detection.confidence}% confidence)
                  </span>
                )}
              </div>
            </div>
            {discovery.waf_detection.reason && (
              <p className="text-gray-400 text-sm mt-2">{discovery.waf_detection.reason}</p>
            )}
          </div>
        </div>
      )}

      {/* DNS */}
      {dns && Object.keys(dns).length > 0 && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">DNS Configuration</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {dns.a && <div><h3 className="text-sm text-gray-400 mb-1">A Records</h3><p className="font-mono text-sm">{Array.isArray(dns.a) ? dns.a.join(', ') : dns.a}</p></div>}
            {dns.aaaa && <div><h3 className="text-sm text-gray-400 mb-1">AAAA Records</h3><p className="font-mono text-sm">{Array.isArray(dns.aaaa) ? dns.aaaa.join(', ') : dns.aaaa}</p></div>}
            {dns.mx && <div><h3 className="text-sm text-gray-400 mb-1">MX Records</h3><p className="font-mono text-xs">{Array.isArray(dns.mx) ? dns.mx.map((r: any) => typeof r === 'string' ? r : r.exchange).join(', ') : dns.mx}</p></div>}
            {dns.spf && <div><h3 className="text-sm text-gray-400 mb-1">SPF Record</h3><p className="font-mono text-xs break-all">{dns.spf}</p></div>}
            {dns.dmarc?.record && <div><h3 className="text-sm text-gray-400 mb-1">DMARC Record</h3><p className="font-mono text-xs break-all">{dns.dmarc.record}</p></div>}
            {dns.dkim && <div><h3 className="text-sm text-gray-400 mb-1">DKIM</h3><p className={`text-sm ${dns.dkim.found ? 'text-green-400' : 'text-gray-500'}`}>{dns.dkim.found ? `Found (${dns.dkim.selectors_found?.join(', ') || 'selectors detected'})` : 'Not detected'}</p></div>}
            {dns.caa && <div><h3 className="text-sm text-gray-400 mb-1">CAA Records</h3><p className="font-mono text-xs">{Array.isArray(dns.caa) ? dns.caa.map((r: any) => typeof r === 'string' ? r : `${r.flags || 0} ${r.tag} ${r.value}`).join('; ') : (dns.caa.records ? dns.caa.records.join('; ') : 'Not configured')}</p></div>}
            {dns.dnssec && <div><h3 className="text-sm text-gray-400 mb-1">DNSSEC</h3><p className={`capitalize ${dns.dnssec.status === 'secure' ? 'text-green-400' : 'text-orange-400'}`}>{dns.dnssec.status || 'Not configured'}</p></div>}
            {dns.mta_sts !== undefined && <div><h3 className="text-sm text-gray-400 mb-1">MTA-STS</h3><p className={`text-sm ${dns.mta_sts?.enabled || dns.mta_sts === true ? 'text-green-400' : 'text-gray-500'}`}>{dns.mta_sts?.enabled || dns.mta_sts === true ? 'Enabled' : 'Not configured'}</p></div>}
            {dns.tls_rpt !== undefined && <div><h3 className="text-sm text-gray-400 mb-1">TLS-RPT</h3><p className={`text-sm ${dns.tls_rpt?.enabled || dns.tls_rpt === true ? 'text-green-400' : 'text-gray-500'}`}>{dns.tls_rpt?.enabled || dns.tls_rpt === true ? 'Enabled' : 'Not configured'}</p></div>}
            {dns.zone_transfer !== undefined && <div><h3 className="text-sm text-gray-400 mb-1">Zone Transfer</h3><p className={`text-sm ${dns.zone_transfer?.vulnerable ? 'text-red-400' : 'text-green-400'}`}>{dns.zone_transfer?.vulnerable ? 'Vulnerable!' : 'Protected'}</p></div>}
          </div>
        </div>
      )}

      {/* TLS */}
      {tls && (tls.certificate || tls.cipher_suites || tls.sslyze || tls.testssl || tls.nmap) && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">TLS/SSL Configuration</h2>
          {tls.certificate && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-4">
              <div className="bg-gray-900 rounded-lg p-4">
                <h4 className="text-sm text-gray-400 mb-1">Subject</h4>
                <p className="font-mono text-sm text-white">{tls.certificate.subject?.replace('CN = ', '') || '—'}</p>
              </div>
              <div className="bg-gray-900 rounded-lg p-4">
                <h4 className="text-sm text-gray-400 mb-1">Issuer</h4>
                <p className="font-mono text-sm text-white">
                  {(() => {
                    const issuer = tls.certificate.issuer || ''
                    // Try to extract CN from various formats
                    const cnMatch = issuer.match(/CN\s*=\s*([^,]+)/i)
                    if (cnMatch) return cnMatch[1].trim()
                    // Try O (Organization) as fallback
                    const oMatch = issuer.match(/O\s*=\s*([^,]+)/i)
                    if (oMatch) return oMatch[1].trim()
                    return issuer || '—'
                  })()}
                </p>
              </div>
              <div className="bg-gray-900 rounded-lg p-4">
                <h4 className="text-sm text-gray-400 mb-1">Validity Period</h4>
                {tls.certificate.not_before && tls.certificate.not_after ? (
                  <p className="font-mono text-sm text-white">
                    {new Date(tls.certificate.not_before).toLocaleDateString()} - {new Date(tls.certificate.not_after).toLocaleDateString()}
                  </p>
                ) : (
                  <p className="font-mono text-sm text-white">—</p>
                )}
              </div>
              <div className="bg-gray-900 rounded-lg p-4">
                <h4 className="text-sm text-gray-400 mb-1">Expires In</h4>
                <p className={`text-lg font-bold ${
                  tls.certificate.days_remaining === null || tls.certificate.days_remaining === undefined
                    ? 'text-gray-400'
                    : tls.certificate.days_remaining < 14
                    ? 'text-red-500'
                    : tls.certificate.days_remaining < 30
                    ? 'text-orange-500'
                    : 'text-green-400'
                }`}>
                  {tls.certificate.days_remaining !== null && tls.certificate.days_remaining !== undefined
                    ? `${tls.certificate.days_remaining} days`
                    : '—'}
                </p>
              </div>
              <div className="bg-gray-900 rounded-lg p-4">
                <h4 className="text-sm text-gray-400 mb-1">Key</h4>
                <p className="font-mono text-sm text-white">
                  {tls.certificate.key_algo?.replace('Encryption', '').replace('rsaE', 'RSA E') || '—'} {tls.certificate.key_size ? `${tls.certificate.key_size}-bit` : ''}
                </p>
              </div>
              <div className="bg-gray-900 rounded-lg p-4">
                <h4 className="text-sm text-gray-400 mb-1">Signature</h4>
                <p className="font-mono text-sm text-white">{tls.certificate.sig_algo || '—'}</p>
              </div>
            </div>
          )}

          {/* TLS Versions */}
          {tls.sslyze?.tls_versions && Object.keys(tls.sslyze.tls_versions).length > 0 && (
            <div className="mb-4">
              <h3 className="text-sm font-semibold text-gray-400 mb-2">Protocol Support</h3>
              <div className="flex flex-wrap gap-2">
                {Object.entries(tls.sslyze.tls_versions).map(([version, supported]: [string, any]) => (
                  <span key={version} className={`px-3 py-1 rounded text-sm font-mono ${
                    supported
                      ? (version.includes('1.3') || version.includes('1.2'))
                        ? 'bg-green-900 text-green-200'
                        : 'bg-yellow-900 text-yellow-200'
                      : 'bg-gray-700 text-gray-400'
                  }`}>
                    {version}: {supported ? '✓' : '✗'}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Cipher Suites - prefer nmap data (has grades), fallback to sslyze */}
          {(tls.nmap?.ciphers_by_protocol || tls.sslyze?.cipher_suites) && (
            <div className="mb-4">
              <h3 className="text-sm font-semibold text-gray-400 mb-2">Cipher Suites</h3>
              <div className="space-y-3">
                {/* Use nmap data if available (has grades and security info) */}
                {tls.nmap?.ciphers_by_protocol && Object.keys(tls.nmap.ciphers_by_protocol).length > 0 ? (
                  Object.entries(tls.nmap.ciphers_by_protocol)
                    .filter(([, ciphers]: [string, any]) => Array.isArray(ciphers) && ciphers.length > 0)
                    .map(([protocol, ciphers]: [string, any]) => (
                      <div key={protocol} className="bg-gray-900 rounded-lg p-3">
                        <div className="flex items-center justify-between mb-2">
                          <h4 className="text-xs font-mono text-blue-400">{protocol}</h4>
                          <span className="text-xs text-gray-500">{ciphers.length} cipher{ciphers.length !== 1 ? 's' : ''}</span>
                        </div>
                        <div className="space-y-1.5">
                          {ciphers.map((cipher: any, i: number) => (
                            <div key={i} className="flex items-center gap-2 text-xs">
                              {/* Grade badge */}
                              <span className={`px-1.5 py-0.5 rounded font-bold min-w-[24px] text-center ${
                                cipher.grade === 'A' ? 'bg-green-900 text-green-200' :
                                cipher.grade === 'B' ? 'bg-lime-900 text-lime-200' :
                                cipher.grade === 'C' ? 'bg-yellow-900 text-yellow-200' :
                                cipher.grade === 'D' ? 'bg-orange-900 text-orange-200' :
                                cipher.grade === 'F' ? 'bg-red-900 text-red-200' :
                                'bg-gray-700 text-gray-300'
                              }`}>
                                {cipher.grade || '?'}
                              </span>
                              {/* Security indicator */}
                              <span className={`${
                                cipher.insecure ? 'text-red-400' :
                                cipher.weak ? 'text-yellow-400' :
                                cipher.secure ? 'text-green-400' :
                                'text-gray-400'
                              }`}>
                                {cipher.insecure ? '✗' : cipher.weak ? '!' : cipher.secure ? '✓' : '—'}
                              </span>
                              {/* Cipher name */}
                              <span className="font-mono text-gray-300 truncate" title={cipher.name}>
                                {cipher.name?.length > 45 ? cipher.name.substring(0, 45) + '...' : cipher.name}
                              </span>
                              {/* Reason tooltip */}
                              {cipher.reason && (
                                <span className="text-gray-500 truncate hidden sm:inline" title={cipher.reason}>
                                  ({cipher.reason.length > 30 ? cipher.reason.substring(0, 30) + '...' : cipher.reason})
                                </span>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    ))
                ) : (
                  /* Fallback to sslyze data (string names only) */
                  tls.sslyze?.cipher_suites && Object.keys(tls.sslyze.cipher_suites).length > 0 && (
                    Object.entries(tls.sslyze.cipher_suites)
                      .filter(([, ciphers]: [string, any]) => Array.isArray(ciphers) && ciphers.length > 0)
                      .map(([protocol, ciphers]: [string, any]) => (
                        <div key={protocol} className="bg-gray-900 rounded-lg p-3">
                          <h4 className="text-xs font-mono text-blue-400 mb-2">{protocol}</h4>
                          <div className="flex flex-wrap gap-1">
                            {ciphers.slice(0, 8).map((cipher: string, i: number) => (
                              <span key={i} className={`px-2 py-0.5 text-xs rounded font-mono ${
                                cipher.includes('CHACHA') || cipher.includes('GCM')
                                  ? 'bg-green-900/50 text-green-300'
                                  : cipher.includes('CBC')
                                  ? 'bg-yellow-900/50 text-yellow-300'
                                  : 'bg-gray-700 text-gray-300'
                              }`}>
                                {cipher.length > 40 ? cipher.substring(0, 40) + '...' : cipher}
                              </span>
                            ))}
                            {ciphers.length > 8 && (
                              <span className="px-2 py-0.5 text-xs text-gray-500">+{ciphers.length - 8} more</span>
                            )}
                          </div>
                        </div>
                      ))
                  )
                )}
              </div>
            </div>
          )}

          {/* Vulnerabilities */}
          {tls.sslyze?.vulnerabilities && tls.sslyze.vulnerabilities.length > 0 && (
            <div className="mb-4 p-4 bg-red-900/20 border border-red-500/40 rounded-lg">
              <h3 className="text-sm font-semibold text-red-400 mb-2">Vulnerabilities Detected</h3>
              <div className="space-y-1">
                {tls.sslyze.vulnerabilities.map((vuln: string, i: number) => (
                  <div key={i} className="flex items-center gap-2 text-sm text-red-300">
                    <span className="text-red-500">!</span>
                    <span>{vuln}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Weak Indicators from nmap */}
          {tls.nmap?.weak_indicators && tls.nmap.weak_indicators.length > 0 && (
            <div className="mb-4 p-4 bg-yellow-900/20 border border-yellow-500/40 rounded-lg">
              <h3 className="text-sm font-semibold text-yellow-400 mb-2">Configuration Warnings</h3>
              <div className="space-y-1">
                {tls.nmap.weak_indicators.map((indicator: string, i: number) => (
                  <div key={i} className="flex items-center gap-2 text-sm text-yellow-300">
                    <span className="text-yellow-500">!</span>
                    <span>{indicator}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* OCSP and other indicators */}
          <div className="flex flex-wrap items-center gap-3">
            {tls.ocsp && (
              <span className={`px-3 py-1 rounded text-sm ${tls.ocsp.stapled ? 'bg-green-900 text-green-200' : 'bg-yellow-900 text-yellow-200'}`}>
                OCSP Stapling: {tls.ocsp.stapled ? 'Enabled' : 'Not Detected'}
              </span>
            )}
            {tls.testssl?.supports_tls13 !== null && (
              <span className={`px-3 py-1 rounded text-sm ${tls.testssl.supports_tls13 ? 'bg-green-900 text-green-200' : 'bg-yellow-900 text-yellow-200'}`}>
                TLS 1.3: {tls.testssl.supports_tls13 ? 'Supported' : 'Not Supported'}
              </span>
            )}
            {tls.sslyze?.session_resumption?.session_id_resumption !== undefined && (
              <span className={`px-3 py-1 rounded text-sm ${tls.sslyze.session_resumption.session_id_resumption ? 'bg-green-900 text-green-200' : 'bg-gray-700 text-gray-400'}`}>
                Session Resumption: {tls.sslyze.session_resumption.session_id_resumption ? 'Enabled' : 'Disabled'}
              </span>
            )}
          </div>

          {/* Show message if no TLS data */}
          {!tls.certificate?.days_remaining && !tls.sslyze?.tls_versions && !tls.testssl?.supports_tls13 && (
            <p className="text-gray-500 text-sm">No TLS/SSL data available - target may not support HTTPS or scan was limited.</p>
          )}
        </div>
      )}

      {/* Open Ports & Services */}
      {(network_scan.open_ports?.length > 0 || network_scan.services?.length > 0) && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">Open Ports & Services</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
            {network_scan.open_ports?.map((port: any, i: number) => (
              <div key={i} className="bg-gray-900 rounded-lg p-3">
                <div className="flex items-center justify-between mb-1">
                  <span className="font-mono text-lg text-white">{port.port}</span>
                  <span className="px-2 py-0.5 text-xs rounded bg-blue-900 text-blue-200">
                    {port.protocol || 'tcp'}
                  </span>
                </div>
                {port.service && (
                  <p className="text-gray-400 text-sm">{port.service}</p>
                )}
                {port.state && port.state !== 'open' && (
                  <p className="text-yellow-500 text-xs mt-1">{port.state}</p>
                )}
              </div>
            ))}
          </div>
          {network_scan.services?.length > 0 && (
            <div className="mt-4">
              <h3 className="text-sm font-semibold text-gray-400 mb-2">Service Details</h3>
              <div className="space-y-2">
                {network_scan.services.map((svc: any, i: number) => (
                  <div key={i} className="bg-gray-900 rounded-lg p-3 flex items-center justify-between">
                    <div>
                      <span className="text-white font-medium">{svc.name || 'unknown'}</span>
                      {svc.product && <span className="text-gray-400 ml-2">{svc.product}</span>}
                      {svc.version && <span className="px-1.5 py-0.5 bg-blue-900 text-blue-200 text-xs rounded ml-2">v{svc.version}</span>}
                    </div>
                    <span className="text-gray-500 font-mono text-sm">:{svc.port}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          {network_scan.os_detection?.os_match && (
            <div className="mt-4 p-3 bg-gray-900 rounded-lg">
              <h3 className="text-sm font-semibold text-gray-400 mb-1">OS Detection</h3>
              <p className="text-white">{network_scan.os_detection.os_match}</p>
              {network_scan.os_detection.accuracy && (
                <span className="text-gray-500 text-sm">({network_scan.os_detection.accuracy}% confidence)</span>
              )}
            </div>
          )}
        </div>
      )}

      {/* Network Services Exposure */}
      {(network_services.vpn_endpoints?.length > 0 || network_services.remote_desktop?.length > 0 || network_services.database_exposure?.length > 0) && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">Network Services Exposure</h2>
          <div className="space-y-4">
            {network_services.vpn_endpoints?.length > 0 && (
              <div>
                <h3 className="text-sm font-semibold text-gray-400 mb-2">VPN Endpoints</h3>
                <div className="space-y-2">
                  {network_services.vpn_endpoints.map((vpn: any, i: number) => (
                    <div key={i} className="bg-gray-900 rounded-lg p-3 flex items-center justify-between">
                      <span className="text-white">{vpn.type || 'VPN'}</span>
                      <span className="text-gray-400 font-mono text-sm">{vpn.endpoint || vpn.url}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {network_services.remote_desktop?.length > 0 && (
              <div>
                <h3 className="text-sm font-semibold text-orange-400 mb-2">Remote Desktop Services</h3>
                <div className="space-y-2">
                  {network_services.remote_desktop.map((rd: any, i: number) => (
                    <div key={i} className="bg-orange-900/20 border border-orange-500/40 rounded-lg p-3 flex items-center justify-between">
                      <span className="text-orange-300">{rd.type || rd.service || 'RDP/VNC'}</span>
                      <span className="text-gray-400 font-mono text-sm">:{rd.port}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {network_services.database_exposure?.length > 0 && (
              <div>
                <h3 className="text-sm font-semibold text-red-400 mb-2">Database Exposure</h3>
                <div className="space-y-2">
                  {network_services.database_exposure.map((db: any, i: number) => (
                    <div key={i} className="bg-red-900/20 border border-red-500/40 rounded-lg p-3 flex items-center justify-between">
                      <span className="text-red-300">{db.type || db.database || 'Database'}</span>
                      <span className="text-gray-400 font-mono text-sm">:{db.port}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* HTTP Security Headers */}
      {http && http.security_headers && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">HTTP Security Headers</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {[
              { name: 'HSTS', key: 'hsts', critical: true },
              { name: 'X-Frame-Options', key: 'x_frame_options', critical: true },
              { name: 'X-Content-Type-Options', key: 'x_content_type_options', critical: true },
              { name: 'Referrer-Policy', key: 'referrer_policy', critical: false },
              { name: 'Permissions-Policy', key: 'permissions_policy', critical: false },
              { name: 'COOP', key: 'coop', critical: false },
              { name: 'CORP', key: 'corp', critical: false },
            ].map(header => {
              const value = http.security_headers[header.key]
              const isSet = !!value
              return (
                <div key={header.key} className="bg-gray-900 rounded-lg p-3">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-300 text-sm">{header.name}</span>
                    <span className={`px-2 py-1 text-xs rounded ${isSet ? 'bg-green-900 text-green-200' : header.critical ? 'bg-red-900 text-red-200' : 'bg-gray-700 text-gray-400'}`}>
                      {isSet ? (typeof value === 'string' && value.length < 20 ? value : 'Set') : 'Missing'}
                    </span>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* CSP Evaluation */}
      {http?.csp_evaluation?.present && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-2xl font-bold">Content Security Policy</h2>
            <div className="flex items-center gap-3">
              <span className={`text-3xl font-bold ${http.csp_evaluation.grade === 'A' || http.csp_evaluation.grade === 'A+' ? 'text-green-500' : http.csp_evaluation.grade === 'B' ? 'text-lime-500' : http.csp_evaluation.grade === 'C' ? 'text-yellow-500' : http.csp_evaluation.grade === 'D' ? 'text-orange-500' : 'text-red-500'}`}>
                {http.csp_evaluation.grade}
              </span>
              <span className="text-gray-400 text-sm">{http.csp_evaluation.score}/100</span>
            </div>
          </div>

          {http.csp_evaluation.issues?.length > 0 && (
            <div className="mb-6">
              <h3 className="text-sm font-semibold text-gray-400 mb-2">Issues</h3>
              <div className="space-y-2">
                {http.csp_evaluation.issues.map((issue: string, i: number) => (
                  <div key={i} className="flex items-start gap-2 text-sm">
                    <span className="text-yellow-500 mt-0.5">!</span>
                    <span className="text-gray-300">{issue}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {http.csp_evaluation.directives && (
            <div>
              <h3 className="text-sm font-semibold text-gray-400 mb-3">Directives</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {Object.entries(http.csp_evaluation.directives).map(([directive, values]: [string, any]) => (
                  <div key={directive} className="bg-gray-900 rounded-lg p-3">
                    <h4 className="text-xs font-mono text-blue-400 mb-1">{directive}</h4>
                    <div className="flex flex-wrap gap-1">
                      {Array.isArray(values) && values.map((v: string, i: number) => (
                        <span key={i} className={`px-1.5 py-0.5 text-xs rounded font-mono ${v.includes('unsafe') ? 'bg-red-900/50 text-red-300' : v === "'self'" ? 'bg-green-900/50 text-green-300' : v === "'none'" ? 'bg-green-900/50 text-green-300' : 'bg-gray-700 text-gray-300'}`}>
                          {v}
                        </span>
                      ))}
                      {(!Array.isArray(values) || values.length === 0) && (
                        <span className="text-gray-500 text-xs italic">empty</span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Technology Stack */}
      {(discovery.tech?.items?.length > 0 || discovery.tech_stack_guess?.length > 0 || js_dependencies.vulnerable_libraries?.length > 0) && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">Technology Stack</h2>
          {js_dependencies.vulnerable_libraries?.length > 0 && (
            <div className="mb-6 p-4 bg-red-900/20 border border-red-500/40 rounded-lg">
              <h3 className="text-lg font-semibold text-red-400 mb-3">{js_dependencies.vulnerable_libraries.length} Vulnerable Libraries Detected</h3>
              <div className="space-y-3">
                {js_dependencies.vulnerable_libraries.map((lib: any, i: number) => (
                  <div key={i} className={`bg-gray-900/60 rounded-lg p-3 border-l-4 ${getSeverityBorderClass(lib.severity)}`}>
                    <span className="text-white font-medium">{lib.library}</span>
                    {lib.version && <span className="px-2 py-0.5 bg-red-900 text-red-200 text-xs rounded font-mono ml-2">v{lib.version}</span>}
                    {lib.cve && <a href={`https://nvd.nist.gov/vuln/detail/${lib.cve}`} target="_blank" rel="noopener noreferrer" className="text-blue-400 text-xs hover:underline ml-2">{lib.cve}</a>}
                    <p className="text-gray-400 text-sm mt-1">{lib.summary}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
          {discovery.tech?.items?.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {discovery.tech.items.map((tech: any, i: number) => (
                <div key={i} className="bg-gray-900 rounded-lg p-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-white font-medium">{tech.name}</span>
                      {tech.version && <span className="px-1.5 py-0.5 bg-blue-900 text-blue-200 text-xs rounded font-mono">v{tech.version}</span>}
                    </div>
                    <span className={`px-2 py-0.5 text-xs rounded ${tech.confidence >= 75 ? 'bg-green-900/50 text-green-300' : tech.confidence >= 50 ? 'bg-yellow-900/50 text-yellow-300' : 'bg-gray-700 text-gray-400'}`}>
                      {tech.confidence_label || `${tech.confidence}%`}
                    </span>
                  </div>
                  {tech.category && <p className="text-gray-500 text-xs mt-1">{tech.category}</p>}
                </div>
              ))}
            </div>
          ) : discovery.tech_stack_guess?.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {discovery.tech_stack_guess.map((tech: string, i: number) => (
                <span key={i} className="px-3 py-1 bg-blue-500/20 text-blue-400 rounded text-sm">{tech}</span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Discovered API Endpoints */}
      {discovery.browser_api_endpoints?.length > 0 && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">Discovered API Endpoints</h2>
          <div className="space-y-2">
            {discovery.browser_api_endpoints.map((endpoint: any, i: number) => (
              <div key={i} className="bg-gray-900 rounded-lg p-3 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <span className={`px-2 py-0.5 text-xs font-mono rounded ${endpoint.method === 'GET' ? 'bg-green-900 text-green-200' : endpoint.method === 'POST' ? 'bg-blue-900 text-blue-200' : 'bg-gray-700 text-gray-300'}`}>
                    {endpoint.method || 'GET'}
                  </span>
                  <span className="font-mono text-sm text-gray-300">{endpoint.path || endpoint.url}</span>
                </div>
                <div className="flex items-center gap-2">
                  {endpoint.has_auth && <span className="px-2 py-0.5 text-xs bg-yellow-900/50 text-yellow-300 rounded">Auth</span>}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Active Checks Results */}
      {(active_checks.xss || active_checks.sqli || active_checks.endpoints_tested) && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">Active Security Testing</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {active_checks.xss && (
              <div className="bg-gray-900 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-gray-400 mb-2">XSS Testing</h3>
                <div className="space-y-2">
                  {active_checks.xss.targets_tested !== undefined && (
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-400">Targets Tested</span>
                      <span className="text-white">{active_checks.xss.targets_tested}</span>
                    </div>
                  )}
                  {active_checks.xss.reflections_found !== undefined && (
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-400">Reflections Found</span>
                      <span className={active_checks.xss.reflections_found > 0 ? 'text-yellow-400' : 'text-gray-400'}>{active_checks.xss.reflections_found}</span>
                    </div>
                  )}
                  {active_checks.xss.vulnerabilities_found !== undefined && (
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-400">Vulnerabilities</span>
                      <span className={active_checks.xss.vulnerabilities_found > 0 ? 'text-red-400' : 'text-green-400'}>{active_checks.xss.vulnerabilities_found}</span>
                    </div>
                  )}
                </div>
              </div>
            )}
            {active_checks.sqli && (
              <div className="bg-gray-900 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-gray-400 mb-2">SQL Injection Testing</h3>
                <div className="space-y-2">
                  {active_checks.sqli.targets_tested !== undefined && (
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-400">Targets Tested</span>
                      <span className="text-white">{active_checks.sqli.targets_tested}</span>
                    </div>
                  )}
                  {active_checks.sqli.parameters_tested !== undefined && (
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-400">Parameters Tested</span>
                      <span className="text-white">{active_checks.sqli.parameters_tested}</span>
                    </div>
                  )}
                  {active_checks.sqli.vulnerabilities_found !== undefined && (
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-400">Vulnerabilities</span>
                      <span className={active_checks.sqli.vulnerabilities_found > 0 ? 'text-red-400' : 'text-green-400'}>{active_checks.sqli.vulnerabilities_found}</span>
                    </div>
                  )}
                  {active_checks.sqli.dbms_detected && (
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-400">DBMS Detected</span>
                      <span className="text-blue-400">{active_checks.sqli.dbms_detected}</span>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
          {active_checks.endpoints_tested?.length > 0 && (
            <div className="mt-4">
              <h3 className="text-sm font-semibold text-gray-400 mb-2">Endpoints Tested ({active_checks.endpoints_tested.length})</h3>
              <div className="max-h-32 overflow-y-auto bg-gray-900 rounded-lg p-3">
                {active_checks.endpoints_tested.slice(0, 20).map((ep: string, i: number) => (
                  <div key={i} className="text-xs font-mono text-gray-400 py-0.5 truncate">{ep}</div>
                ))}
                {active_checks.endpoints_tested.length > 20 && (
                  <div className="text-xs text-gray-500 mt-1">+{active_checks.endpoints_tested.length - 20} more</div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Access Control Testing */}
      {(access_control.forced_browsing || access_control.mass_assignment || access_control.bola_idor) && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">Access Control Testing</h2>
          <div className="space-y-4">
            {access_control.forced_browsing && (
              <div className="bg-gray-900 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-gray-400 mb-2">Forced Browsing</h3>
                {access_control.forced_browsing.paths_tested !== undefined && (
                  <p className="text-sm text-gray-400">Paths tested: <span className="text-white">{access_control.forced_browsing.paths_tested}</span></p>
                )}
                {access_control.forced_browsing.findings?.length > 0 && (
                  <div className="mt-2 space-y-1">
                    {access_control.forced_browsing.findings.map((f: any, i: number) => (
                      <div key={i} className="text-sm text-yellow-400">{f.path || f.url || f}</div>
                    ))}
                  </div>
                )}
              </div>
            )}
            {access_control.bola_idor && (
              <div className="bg-gray-900 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-gray-400 mb-2">BOLA/IDOR Testing</h3>
                {access_control.bola_idor.endpoints_tested !== undefined && (
                  <p className="text-sm text-gray-400">Endpoints tested: <span className="text-white">{access_control.bola_idor.endpoints_tested}</span></p>
                )}
                {access_control.bola_idor.vulnerable_endpoints?.length > 0 && (
                  <div className="mt-2">
                    <p className="text-sm text-red-400">Vulnerable endpoints found:</p>
                    {access_control.bola_idor.vulnerable_endpoints.map((ep: any, i: number) => (
                      <div key={i} className="text-sm text-red-300 font-mono mt-1">{ep.path || ep.url || ep}</div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Cloud & Infrastructure Exposure */}
      {(cloud_buckets.findings?.length > 0 || cloud_ssrf.vulnerable || kubernetes_exposure.findings?.length > 0 || container_registry.exposed || cicd_exposure.findings?.length > 0) && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">Cloud & Infrastructure Exposure</h2>
          <div className="space-y-4">
            {cloud_buckets.findings?.length > 0 && (
              <div className="bg-red-900/20 border border-red-500/40 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-red-400 mb-2">Cloud Storage Buckets</h3>
                <div className="space-y-2">
                  {cloud_buckets.findings.map((bucket: any, i: number) => (
                    <div key={i} className="text-sm">
                      <span className="text-red-300">{bucket.url || bucket.bucket}</span>
                      {bucket.permissions && <span className="text-gray-400 ml-2">({bucket.permissions})</span>}
                    </div>
                  ))}
                </div>
              </div>
            )}
            {cloud_ssrf.vulnerable && (
              <div className="bg-red-900/20 border border-red-500/40 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-red-400 mb-2">Cloud SSRF</h3>
                <p className="text-red-300 text-sm">SSRF to cloud metadata endpoint detected</p>
                {cloud_ssrf.endpoint && <p className="text-gray-400 text-xs mt-1 font-mono">{cloud_ssrf.endpoint}</p>}
              </div>
            )}
            {kubernetes_exposure.findings?.length > 0 && (
              <div className="bg-red-900/20 border border-red-500/40 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-red-400 mb-2">Kubernetes Exposure</h3>
                <div className="space-y-2">
                  {kubernetes_exposure.findings.map((k8s: any, i: number) => (
                    <div key={i} className="text-sm text-red-300">{k8s.description || k8s.type || k8s}</div>
                  ))}
                </div>
              </div>
            )}
            {container_registry.exposed && (
              <div className="bg-orange-900/20 border border-orange-500/40 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-orange-400 mb-2">Container Registry</h3>
                <p className="text-orange-300 text-sm">Exposed container registry detected</p>
                {container_registry.url && <p className="text-gray-400 text-xs mt-1 font-mono">{container_registry.url}</p>}
              </div>
            )}
            {cicd_exposure.findings?.length > 0 && (
              <div className="bg-orange-900/20 border border-orange-500/40 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-orange-400 mb-2">CI/CD Exposure</h3>
                <div className="space-y-2">
                  {cicd_exposure.findings.map((ci: any, i: number) => (
                    <div key={i} className="text-sm text-orange-300">{ci.type || ci.description || ci}</div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Findings */}
      {Array.isArray(findings) && findings.length > 0 && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">Key Findings</h2>
          <div className="flex flex-wrap items-center gap-2 mb-4">
            <span className="text-gray-500 text-xs mr-2">Filter:</span>
            {(['critical', 'high', 'medium', 'low', 'info'] as const).map(severity => {
              const count = findings.filter((f: any) => (f.severity?.toLowerCase() || 'info') === severity).length
              if (count === 0) return null
              const isActive = severityFilter.has(severity)
              return (
                <button key={severity} onClick={() => toggleSeverityFilter(severity)} className={`px-2 py-1 rounded text-xs font-medium transition-all ${isActive ? severity === 'critical' ? 'bg-red-600 text-white' : severity === 'high' ? 'bg-orange-600 text-white' : severity === 'medium' ? 'bg-yellow-600 text-black' : severity === 'low' ? 'bg-blue-600 text-white' : 'bg-slate-600 text-white' : 'bg-gray-700/50 text-gray-500 line-through'}`}>
                  {severity} ({count})
                </button>
              )
            })}
          </div>
          <p className="text-gray-400 text-sm mb-4">Showing {filteredFindings.length} of {findings.length} finding(s)</p>
          <div className="space-y-4">
            {filteredFindings.slice(0, 50).map((finding: any, idx: number) => {
              const findingId = finding.id || `finding-${idx}`
              const remediation = remediationData.find(r => r.finding_id === findingId)
              return (
                <div key={idx}>
                  <FindingCard finding={finding} />
                  {enableRemediationTracking && (
                    <div className="mt-2 ml-4 pl-4 border-l-2 border-gray-700">
                      <FindingActions
                        scanId={scan.id}
                        findingId={findingId}
                        currentStatus={remediation?.status || 'open'}
                        currentNotes={remediation?.notes || ''}
                        onStatusChange={(newStatus, notes) => {
                          setRemediationData(prev => {
                            const existing = prev.find(r => r.finding_id === findingId)
                            if (existing) return prev.map(r => r.finding_id === findingId ? { ...r, status: newStatus, notes } : r)
                            return [...prev, { finding_id: findingId, status: newStatus, notes }]
                          })
                        }}
                      />
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Discovery */}
      {discovery.katana_sample?.length > 0 && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">Discovery</h2>
          <div className="max-h-48 overflow-y-auto bg-gray-700/30 rounded p-3">
            {discovery.katana_sample.map((url: string, i: number) => (
              <div key={i} className="text-xs font-mono text-gray-300 py-1">{url}</div>
            ))}
          </div>
        </div>
      )}

      {/* Exposed Secrets */}
      {js_secrets.vulnerable && js_secrets.secrets_found?.length > 0 && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">Exposed Secrets</h2>
          <div className="space-y-3">
            {js_secrets.secrets_found.map((secret: any, i: number) => (
              <div key={i} className="bg-gray-900 rounded-lg p-4 border-l-4 border-yellow-500">
                <span className="text-yellow-400 font-medium">{secret.type}</span>
                <p className="text-gray-500 text-xs mt-1">Found in: <code className="text-gray-400">{secret.file}</code></p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Smart Scan Coverage */}
      {(smart_coverage.endpoints || smart_coverage.parameters || smart_coverage.nuclei_templates) && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">Smart Scan Coverage</h2>

          {/* Coverage Progress Bars */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
            {/* Endpoint Coverage */}
            {smart_coverage.endpoints && (
              <div className="bg-gray-900 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-sm font-semibold text-gray-400">Endpoint Coverage</h3>
                  <span className="text-lg font-bold text-white">
                    {Math.round((smart_coverage.endpoints.coverage || 0) * 100)}%
                  </span>
                </div>
                <div className="w-full bg-gray-700 rounded-full h-2 mb-2">
                  <div
                    className="bg-blue-500 h-2 rounded-full transition-all"
                    style={{ width: `${Math.min((smart_coverage.endpoints.coverage || 0) * 100, 100)}%` }}
                  />
                </div>
                <p className="text-xs text-gray-500">
                  {smart_coverage.endpoints.tested || 0} tested / {smart_coverage.endpoints.discovered || 0} discovered
                </p>
              </div>
            )}

            {/* Parameter Coverage */}
            {smart_coverage.parameters && (
              <div className="bg-gray-900 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-sm font-semibold text-gray-400">Parameter Coverage</h3>
                  <span className="text-lg font-bold text-white">
                    {Math.round((smart_coverage.parameters.coverage || 0) * 100)}%
                  </span>
                </div>
                <div className="w-full bg-gray-700 rounded-full h-2 mb-2">
                  <div
                    className="bg-green-500 h-2 rounded-full transition-all"
                    style={{ width: `${Math.min((smart_coverage.parameters.coverage || 0) * 100, 100)}%` }}
                  />
                </div>
                <p className="text-xs text-gray-500">
                  {smart_coverage.parameters.tested || 0} tested / {smart_coverage.parameters.discovered || 0} discovered
                </p>
              </div>
            )}

            {/* Nuclei Template Hit Rate */}
            {smart_coverage.nuclei_templates && (
              <div className="bg-gray-900 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-sm font-semibold text-gray-400">Template Hit Rate</h3>
                  <span className="text-lg font-bold text-white">
                    {Math.round((smart_coverage.nuclei_templates.hit_rate || 0) * 100)}%
                  </span>
                </div>
                <div className="w-full bg-gray-700 rounded-full h-2 mb-2">
                  <div
                    className={`h-2 rounded-full transition-all ${
                      (smart_coverage.nuclei_templates.hit_rate || 0) > 0.1 ? 'bg-red-500' :
                      (smart_coverage.nuclei_templates.hit_rate || 0) > 0.05 ? 'bg-yellow-500' : 'bg-green-500'
                    }`}
                    style={{ width: `${Math.min((smart_coverage.nuclei_templates.hit_rate || 0) * 100, 100)}%` }}
                  />
                </div>
                <p className="text-xs text-gray-500">
                  {smart_coverage.nuclei_templates.matched || 0} matched / {smart_coverage.nuclei_templates.run || 0} run
                </p>
              </div>
            )}
          </div>

          {/* Breakdown by Method and Location */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
            {/* Endpoints by Method */}
            {smart_coverage.endpoints?.by_method && Object.keys(smart_coverage.endpoints.by_method).length > 0 && (
              <div className="bg-gray-900 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-gray-400 mb-3">Endpoints by Method</h3>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(smart_coverage.endpoints.by_method).map(([method, count]: [string, any]) => (
                    <span
                      key={method}
                      className={`px-2 py-1 text-xs font-mono rounded ${
                        method === 'GET' ? 'bg-green-900/50 text-green-300' :
                        method === 'POST' ? 'bg-blue-900/50 text-blue-300' :
                        method === 'PUT' ? 'bg-yellow-900/50 text-yellow-300' :
                        method === 'DELETE' ? 'bg-red-900/50 text-red-300' :
                        method === 'PATCH' ? 'bg-purple-900/50 text-purple-300' :
                        'bg-gray-700 text-gray-300'
                      }`}
                    >
                      {method}: {count}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Parameters by Location */}
            {smart_coverage.parameters?.by_location && Object.keys(smart_coverage.parameters.by_location).length > 0 && (
              <div className="bg-gray-900 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-gray-400 mb-3">Parameters by Location</h3>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(smart_coverage.parameters.by_location).map(([location, count]: [string, any]) => (
                    <span
                      key={location}
                      className={`px-2 py-1 text-xs font-mono rounded ${
                        location === 'query' ? 'bg-blue-900/50 text-blue-300' :
                        location === 'body' ? 'bg-purple-900/50 text-purple-300' :
                        location === 'path' ? 'bg-green-900/50 text-green-300' :
                        location === 'header' ? 'bg-yellow-900/50 text-yellow-300' :
                        'bg-gray-700 text-gray-300'
                      }`}
                    >
                      {location}: {count}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Nuclei Categories */}
          {smart_coverage.nuclei_templates?.by_category && Object.keys(smart_coverage.nuclei_templates.by_category).length > 0 && (
            <div className="mb-6">
              <h3 className="text-sm font-semibold text-gray-400 mb-3">Templates by Category</h3>
              <div className="flex flex-wrap gap-2">
                {Object.entries(smart_coverage.nuclei_templates.by_category)
                  .sort(([, a]: [string, any], [, b]: [string, any]) => b - a)
                  .slice(0, 12)
                  .map(([category, count]: [string, any]) => (
                    <span key={category} className="px-2 py-1 bg-gray-900 text-gray-300 text-xs rounded">
                      {category}: {count}
                    </span>
                  ))}
                {Object.keys(smart_coverage.nuclei_templates.by_category).length > 12 && (
                  <span className="px-2 py-1 text-gray-500 text-xs">
                    +{Object.keys(smart_coverage.nuclei_templates.by_category).length - 12} more
                  </span>
                )}
              </div>
            </div>
          )}

          {/* Auth States and Discovery Sources */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Auth States Tested */}
            {smart_coverage.auth_states_tested?.length > 0 && (
              <div className="bg-gray-900 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-gray-400 mb-2">Auth States Tested</h3>
                <div className="flex flex-wrap gap-2">
                  {smart_coverage.auth_states_tested.map((state: string, i: number) => (
                    <span key={i} className="px-2 py-1 bg-yellow-900/30 text-yellow-400 rounded text-xs">
                      {state}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Discovery Sources */}
            {smart_coverage.discovery_sources?.length > 0 && (
              <div className="bg-gray-900 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-gray-400 mb-2">Discovery Sources</h3>
                <div className="flex flex-wrap gap-2">
                  {smart_coverage.discovery_sources.map((source: string, i: number) => (
                    <span key={i} className="px-2 py-1 bg-blue-900/30 text-blue-400 rounded text-xs">
                      {source}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Scan Metadata & Coverage */}
      {(scan_metadata.completed_at || scan_metadata.scanner_version || coverage.modules_completed || Object.keys(scan_metadata).length > 2) && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">Scan Metadata</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {scan_metadata.scanner_version && (
              <div className="bg-gray-900 rounded-lg p-3">
                <h3 className="text-sm text-gray-400 mb-1">Scanner Version</h3>
                <p className="text-white font-mono text-sm">{scan_metadata.scanner_version}</p>
              </div>
            )}
            {scan_metadata.completed_at && (
              <div className="bg-gray-900 rounded-lg p-3">
                <h3 className="text-sm text-gray-400 mb-1">Completed At</h3>
                <p className="text-white text-sm">{new Date(scan_metadata.completed_at).toLocaleString()}</p>
              </div>
            )}
            {scan_metadata.duration_seconds !== undefined && (
              <div className="bg-gray-900 rounded-lg p-3">
                <h3 className="text-sm text-gray-400 mb-1">Duration</h3>
                <p className="text-white text-sm">
                  {scan_metadata.duration_seconds < 60
                    ? `${scan_metadata.duration_seconds}s`
                    : scan_metadata.duration_seconds < 3600
                    ? `${Math.floor(scan_metadata.duration_seconds / 60)}m ${scan_metadata.duration_seconds % 60}s`
                    : `${Math.floor(scan_metadata.duration_seconds / 3600)}h ${Math.floor((scan_metadata.duration_seconds % 3600) / 60)}m`}
                </p>
              </div>
            )}
            {coverage.coverage_percentage !== undefined && (
              <div className="bg-gray-900 rounded-lg p-3">
                <h3 className="text-sm text-gray-400 mb-1">Coverage</h3>
                <p className="text-white text-lg font-bold">{coverage.coverage_percentage}%</p>
              </div>
            )}
          </div>
          {coverage.modules_completed?.length > 0 && (
            <div className="mt-4">
              <h3 className="text-sm font-semibold text-gray-400 mb-2">Modules Completed</h3>
              <div className="flex flex-wrap gap-2">
                {coverage.modules_completed.map((mod: string, i: number) => (
                  <span key={i} className="px-2 py-1 bg-green-900/30 text-green-400 rounded text-xs">{mod}</span>
                ))}
              </div>
            </div>
          )}
          {scan_metadata.checks_skipped?.length > 0 && (
            <div className="mt-4">
              <h3 className="text-sm font-semibold text-gray-400 mb-2">Checks Skipped</h3>
              <div className="space-y-1">
                {scan_metadata.checks_skipped.map((skip: any, i: number) => (
                  <div key={i} className="text-sm text-gray-500">
                    <span className="text-gray-400">{typeof skip === 'string' ? skip : skip.name}</span>
                    {skip.reason && <span className="ml-2 text-gray-600">({skip.reason})</span>}
                  </div>
                ))}
              </div>
            </div>
          )}
          {scan_metadata.options && Object.keys(scan_metadata.options).length > 0 && (
            <div className="mt-4">
              <h3 className="text-sm font-semibold text-gray-400 mb-2">Scan Options</h3>
              <div className="bg-gray-900 rounded-lg p-3">
                <pre className="text-xs text-gray-400 overflow-x-auto">{JSON.stringify(scan_metadata.options, null, 2)}</pre>
              </div>
            </div>
          )}
        </div>
      )}
    </main>
  )
}
