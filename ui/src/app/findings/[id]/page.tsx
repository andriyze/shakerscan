'use client'

import { useEffect, useMemo, useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { useParams } from 'next/navigation'
import FindingCard from '@/components/FindingCard'
import { formatDate, getFinding, getSeverityBg, type Finding } from '@/lib/api'
import { formatAnomaly, parseEvidence } from '@/lib/evidence-parser'

function StatusBadge({ status }: { status: Finding['status'] }) {
  const styles: Record<string, string> = {
    active: 'bg-yellow-500/20 text-yellow-400',
    resolved: 'bg-green-500/20 text-green-400',
    false_positive: 'bg-gray-500/20 text-gray-400',
    accepted_risk: 'bg-purple-500/20 text-purple-400'
  }

  return (
    <span className={`px-2 py-0.5 text-xs font-medium rounded ${styles[status] || styles.active}`}>
      {status.replace('_', ' ')}
    </span>
  )
}

function SectionCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
      <h2 className="text-sm font-medium text-gray-400 mb-3">{title}</h2>
      {children}
    </div>
  )
}

function InfoItem({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="text-xs text-gray-500">{label}</p>
      <div className="text-sm text-gray-200 mt-1">{children}</div>
    </div>
  )
}

function CopyButton({ text, label }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch (err) {
      console.error('Failed to copy:', err)
    }
  }

  return (
    <button
      onClick={handleCopy}
      className="p-1 rounded hover:bg-gray-800 transition-colors"
      title={label || 'Copy'}
      type="button"
    >
      {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5 text-gray-400" />}
    </button>
  )
}

export default function FindingDetailPage() {
  const params = useParams()
  const findingId = params.id as string
  const [finding, setFinding] = useState<Finding | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    async function fetchFinding() {
      try {
        const data = await getFinding(findingId)
        setFinding(data)
        setError(null)
      } catch (err) {
        setError('Failed to load finding details')
      } finally {
        setLoading(false)
      }
    }

    fetchFinding()
  }, [findingId])

  const evidence = useMemo(() => parseEvidence(finding?.evidence), [finding?.evidence])
  const primaryUrl = finding?.url || evidence.url || finding?.target_url || ''
  const request = finding?.request || evidence.request
  const response = finding?.response || evidence.response
  const statusCode = evidence.statusCode
  const responseAnomaly = evidence.responseAnomaly
  const summaryDescription = finding?.description || evidence.description || ''
  const rawEvidence =
    finding?.evidence && typeof finding.evidence === 'string'
      ? finding.evidence
      : finding?.evidence
      ? JSON.stringify(finding.evidence, null, 2)
      : ''

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
      </div>
    )
  }

  if (error || !finding) {
    return (
      <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4 text-red-400">
        {error || 'Finding not found'}
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <a href="/findings" className="text-gray-400 hover:text-white">
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
          </svg>
        </a>
        <h1 className="text-2xl font-bold text-white">Finding Detail</h1>
      </div>

      <SectionCard title="Overview">
        <div className="flex flex-col gap-4">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <span className={`px-2 py-0.5 text-xs font-medium rounded ${getSeverityBg(finding.severity)}`}>
                  {finding.severity}
                </span>
                <StatusBadge status={finding.status} />
                {finding.cvss_score !== undefined && (
                  <span className="px-2 py-0.5 rounded bg-gray-800 text-gray-200 text-xs">
                    CVSS {finding.cvss_score}
                  </span>
                )}
                {finding.tool && (
                  <span className="px-2 py-0.5 rounded bg-gray-800 text-gray-300 text-xs">
                    {finding.tool}
                  </span>
                )}
              </div>
              <h2 className="text-xl font-semibold text-white mt-2 break-words">{finding.title}</h2>
              {summaryDescription && (
                <p className="text-sm text-gray-300 mt-2 whitespace-pre-wrap">{summaryDescription}</p>
              )}
              <div className="flex flex-wrap gap-2 mt-3 text-xs text-gray-400">
                {finding.cwe && (
                  <a
                    href={`https://cwe.mitre.org/data/definitions/${finding.cwe.replace('CWE-', '')}.html`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-blue-400 hover:text-blue-300"
                  >
                    {finding.cwe}{finding.cwe_name ? `: ${finding.cwe_name}` : ''}
                  </a>
                )}
                {finding.owasp && <span>{finding.owasp}</span>}
              </div>
            </div>

            <div className="space-y-2 text-xs text-gray-400">
              <div className="flex items-center gap-2">
                <span>Finding ID:</span>
                <code className="text-gray-300 break-all">{finding.id}</code>
                <CopyButton text={finding.id} label="Copy finding ID" />
              </div>
              {finding.scan_id && (
                <div className="flex items-center gap-2">
                  <span>Scan ID:</span>
                  <code className="text-gray-300 break-all">{finding.scan_id}</code>
                  <CopyButton text={finding.scan_id} label="Copy scan ID" />
                </div>
              )}
              {finding.target_id && (
                <div className="flex items-center gap-2">
                  <span>Target ID:</span>
                  <code className="text-gray-300 break-all">{finding.target_id}</code>
                  <CopyButton text={finding.target_id} label="Copy target ID" />
                </div>
              )}
              {finding.fingerprint && (
                <div className="flex items-center gap-2">
                  <span>Fingerprint:</span>
                  <code className="text-gray-300 break-all">{finding.fingerprint}</code>
                  <CopyButton text={finding.fingerprint} label="Copy fingerprint" />
                </div>
              )}
            </div>
          </div>

          {finding.notes && (
            <div className="bg-gray-800/60 rounded-lg p-3">
              <p className="text-xs text-gray-400 mb-1">Analyst notes</p>
              <p className="text-sm text-gray-200 whitespace-pre-wrap">{finding.notes}</p>
            </div>
          )}
        </div>
      </SectionCard>

      <FindingCard finding={finding} defaultExpanded />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <SectionCard title="Tracking">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <InfoItem label="Status">
              <StatusBadge status={finding.status} />
            </InfoItem>
            <InfoItem label="First seen">{formatDate(finding.first_seen_at)}</InfoItem>
            <InfoItem label="Last seen">{formatDate(finding.last_seen_at)}</InfoItem>
            {finding.resolved_at && (
              <InfoItem label="Resolved at">{formatDate(finding.resolved_at)}</InfoItem>
            )}
            {finding.resurfaced_count !== undefined && (
              <InfoItem label="Resurfaced count">{finding.resurfaced_count}</InfoItem>
            )}
            {finding.created_at && <InfoItem label="Created">{formatDate(finding.created_at)}</InfoItem>}
            {finding.updated_at && <InfoItem label="Updated">{formatDate(finding.updated_at)}</InfoItem>}
          </div>
        </SectionCard>

        <SectionCard title="Target and Scan">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <InfoItem label="Target">
              {finding.target_name ? (
                <div className="space-y-1">
                  <div className="text-white">{finding.target_name}</div>
                  {finding.target_url && (
                    <div className="text-xs text-gray-400 break-all">{finding.target_url}</div>
                  )}
                </div>
              ) : (
                <span className="text-gray-400 text-sm">{finding.target_url || 'Unknown target'}</span>
              )}
            </InfoItem>
            <InfoItem label="Scan">
              {finding.scan_id ? (
                <div className="flex items-center gap-2">
                  <a href={`/scans/${finding.scan_id}`} className="text-blue-400 hover:text-blue-300 break-all">
                    {finding.scan_id}
                  </a>
                  <CopyButton text={finding.scan_id} label="Copy scan ID" />
                </div>
              ) : (
                <span className="text-gray-400 text-sm">Not available</span>
              )}
            </InfoItem>
            {finding.target_id && (
              <InfoItem label="Target ID">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs break-all">{finding.target_id}</span>
                  <CopyButton text={finding.target_id} label="Copy target ID" />
                </div>
              </InfoItem>
            )}
          </div>
        </SectionCard>
      </div>

      <SectionCard title="Evidence Summary">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <InfoItem label="Primary URL">
            {primaryUrl ? (
              <div className="flex items-center gap-2">
                <code className="text-xs text-blue-300 break-all">{primaryUrl}</code>
                <CopyButton text={primaryUrl} label="Copy URL" />
              </div>
            ) : (
              <span className="text-gray-400 text-sm">Not provided</span>
            )}
          </InfoItem>
          {evidence.duplicateCount > 0 && (
            <InfoItem label="Occurrences">{evidence.duplicateCount}</InfoItem>
          )}
          {evidence.allUrls.length > 0 && (
            <InfoItem label="Affected URLs">{evidence.allUrls.length}</InfoItem>
          )}
          {evidence.allPayloads.length > 0 && (
            <InfoItem label="Payloads">{evidence.allPayloads.length}</InfoItem>
          )}
          {evidence.parameter && (
            <InfoItem label="Parameter">
              <code className="text-xs text-purple-300">{evidence.parameter}</code>
            </InfoItem>
          )}
          {evidence.payload && (
            <InfoItem label="Payload">
              <code className="text-xs text-yellow-300 break-all">{evidence.payload}</code>
            </InfoItem>
          )}
          {evidence.context && (
            <InfoItem label="Context">
              <span className="text-xs text-green-300">{evidence.context}</span>
            </InfoItem>
          )}
          {statusCode && (
            <InfoItem label="Status Code">
              <span className="text-xs text-gray-200">{statusCode}</span>
            </InfoItem>
          )}
          {responseAnomaly && (
            <InfoItem label="Response anomaly">
              <span className="text-xs text-yellow-300">{formatAnomaly(responseAnomaly)}</span>
            </InfoItem>
          )}
        </div>
        {evidence.evidenceDetails.length > 0 && (
          <div className="mt-4 space-y-2">
            <p className="text-xs text-gray-500">Evidence signals</p>
            <ul className="space-y-1 text-sm text-gray-300">
              {evidence.evidenceDetails.map((detail, idx) => (
                <li key={idx} className="flex items-start gap-2">
                  <span className="text-yellow-400 mt-0.5">•</span>
                  <span className="break-words">{detail}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </SectionCard>

      <SectionCard title="AI Analysis">
        {finding.ai_verdict || finding.ai_rationale || finding.ai_recommendations ? (
          <div className="space-y-3">
            {finding.ai_verdict && (
              <div className="flex items-center gap-2">
                <span
                  className={`px-2 py-0.5 rounded text-xs font-medium ${
                    finding.ai_verdict === 'true_positive'
                      ? 'bg-red-900/50 text-red-300'
                      : finding.ai_verdict === 'false_positive'
                      ? 'bg-green-900/50 text-green-300'
                      : 'bg-yellow-900/50 text-yellow-300'
                  }`}
                >
                  AI: {finding.ai_verdict.replace('_', ' ')}
                </span>
                {typeof finding.ai_confidence === 'number' && (
                  <span className="text-xs text-gray-400">
                    {finding.ai_confidence > 1
                      ? `${Math.round(finding.ai_confidence)}% confidence`
                      : `${Math.round(finding.ai_confidence * 100)}% confidence`}
                  </span>
                )}
              </div>
            )}
            {finding.ai_rationale && (
              <div>
                <p className="text-xs text-gray-500 mb-1">Rationale</p>
                <p className="text-sm text-gray-300 whitespace-pre-wrap">{finding.ai_rationale}</p>
              </div>
            )}
            {finding.ai_recommendations && (
              <div>
                <p className="text-xs text-gray-500 mb-1">Recommendations</p>
                {Array.isArray(finding.ai_recommendations) ? (
                  <ul className="space-y-1 text-sm text-gray-300 list-disc list-inside">
                    {finding.ai_recommendations.map((rec, idx) => (
                      <li key={idx}>{rec}</li>
                    ))}
                  </ul>
                ) : (
                  <pre className="text-xs text-gray-300 whitespace-pre-wrap break-words">
                    {JSON.stringify(finding.ai_recommendations, null, 2)}
                  </pre>
                )}
              </div>
            )}
          </div>
        ) : (
          <p className="text-sm text-gray-500">No AI analysis available.</p>
        )}
      </SectionCard>

      {(request || response) && (
        <SectionCard title="HTTP Request/Response">
          <div className="space-y-3">
            {request && (
              <details className="bg-gray-800/60 rounded-lg p-3">
                <summary className="cursor-pointer text-sm text-gray-300">Request</summary>
                <pre className="mt-2 text-xs text-gray-300 whitespace-pre-wrap break-words">{request}</pre>
              </details>
            )}
            {response && (
              <details className="bg-gray-800/60 rounded-lg p-3">
                <summary className="cursor-pointer text-sm text-gray-300">Response</summary>
                <pre className="mt-2 text-xs text-gray-300 whitespace-pre-wrap break-words">{response}</pre>
              </details>
            )}
          </div>
        </SectionCard>
      )}

      {rawEvidence && (
        <SectionCard title="Raw Evidence">
          <pre className="text-xs text-gray-300 whitespace-pre-wrap break-words">{rawEvidence}</pre>
        </SectionCard>
      )}
    </div>
  )
}
