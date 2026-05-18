'use client'

import React, { useState } from 'react'
import { ChevronDown, ChevronRight, Copy, Check, ExternalLink, AlertTriangle, Shield, Bug, Zap } from 'lucide-react'
import { parseEvidence, extractEndpoint, formatAnomaly, decodePayload, type ParsedEvidence } from '@/lib/evidence-parser'

interface Finding {
  id?: string
  title: string
  description?: string
  severity: string
  cvss_score?: number
  tool?: string
  cwe?: string
  cwe_name?: string
  owasp?: string
  evidence?: string | object
  ai_verdict?: string
  ai_confidence?: number
  ai_rationale?: string
  ai_recommendations?: string[] | Record<string, unknown> | null
}

interface FindingCardProps {
  finding: Finding
  defaultExpanded?: boolean
}

function getSeverityConfig(severity: string) {
  const s = (severity || 'info').toLowerCase()
  switch (s) {
    case 'critical':
      return { bg: 'bg-red-900/80', text: 'text-red-200', border: 'border-red-500', icon: AlertTriangle }
    case 'high':
      return { bg: 'bg-orange-900/80', text: 'text-orange-200', border: 'border-orange-500', icon: AlertTriangle }
    case 'medium':
      return { bg: 'bg-yellow-900/80', text: 'text-yellow-200', border: 'border-yellow-500', icon: Shield }
    case 'low':
      return { bg: 'bg-blue-900/80', text: 'text-blue-200', border: 'border-blue-500', icon: Bug }
    default:
      return { bg: 'bg-slate-700', text: 'text-slate-300', border: 'border-slate-500', icon: Zap }
  }
}

function CopyButton({ text, label }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async (e: React.MouseEvent) => {
    e.stopPropagation()
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
      className="p-1.5 rounded hover:bg-gray-700 transition-colors group"
      title={label || 'Copy to clipboard'}
    >
      {copied ? (
        <Check className="w-4 h-4 text-green-400" />
      ) : (
        <Copy className="w-4 h-4 text-gray-400 group-hover:text-white" />
      )}
    </button>
  )
}

function CollapsibleSection({
  title,
  count,
  children,
  defaultOpen = false
}: {
  title: string
  count?: number
  children: React.ReactNode
  defaultOpen?: boolean
}) {
  const [isOpen, setIsOpen] = useState(defaultOpen)

  return (
    <div className="border-t border-gray-700/50">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between py-3 px-1 hover:bg-gray-800/30 transition-colors"
      >
        <div className="flex items-center gap-2">
          {isOpen ? (
            <ChevronDown className="w-4 h-4 text-gray-400" />
          ) : (
            <ChevronRight className="w-4 h-4 text-gray-400" />
          )}
          <span className="text-sm font-medium text-gray-300">{title}</span>
          {count !== undefined && (
            <span className="px-2 py-0.5 text-xs rounded-full bg-gray-700 text-gray-300">
              {count}
            </span>
          )}
        </div>
      </button>
      {isOpen && <div className="pb-3 px-1">{children}</div>}
    </div>
  )
}

function UrlList({ urls, parameter }: { urls: string[]; parameter?: string }) {
  const [showAll, setShowAll] = useState(false)
  const displayUrls = showAll ? urls : urls.slice(0, 5)

  return (
    <div className="space-y-2">
      {displayUrls.map((url, i) => {
        const endpoint = extractEndpoint(url)
        return (
          <div key={i} className="bg-gray-900/60 rounded p-2 flex items-start justify-between gap-2">
            <div className="flex-1 min-w-0">
              <code className="text-xs text-blue-300 break-all">{endpoint}</code>
            </div>
            <div className="flex items-center gap-1 shrink-0">
              <CopyButton text={url} label="Copy full URL" />
              <a
                href={url}
                target="_blank"
                rel="noopener noreferrer"
                className="p-1.5 rounded hover:bg-gray-700 transition-colors"
                title="Open in new tab"
                onClick={(e) => e.stopPropagation()}
              >
                <ExternalLink className="w-4 h-4 text-gray-400 hover:text-white" />
              </a>
            </div>
          </div>
        )
      })}
      {urls.length > 5 && !showAll && (
        <button
          onClick={() => setShowAll(true)}
          className="text-sm text-blue-400 hover:text-blue-300"
        >
          Show all {urls.length} URLs
        </button>
      )}
      {showAll && urls.length > 5 && (
        <button
          onClick={() => setShowAll(false)}
          className="text-sm text-blue-400 hover:text-blue-300"
        >
          Show less
        </button>
      )}
    </div>
  )
}

function PayloadList({ payloads }: { payloads: string[] }) {
  const [showAll, setShowAll] = useState(false)
  const displayPayloads = showAll ? payloads : payloads.slice(0, 5)

  return (
    <div className="space-y-2">
      {displayPayloads.map((payload, i) => {
        const decoded = decodePayload(payload)
        return (
          <div key={i} className="bg-gray-900/60 rounded p-2 flex items-start justify-between gap-2">
            <code className="text-xs text-yellow-300 break-all flex-1">{decoded}</code>
            <CopyButton text={decoded} label="Copy payload" />
          </div>
        )
      })}
      {payloads.length > 5 && !showAll && (
        <button
          onClick={() => setShowAll(true)}
          className="text-sm text-blue-400 hover:text-blue-300"
        >
          Show all {payloads.length} payloads
        </button>
      )}
    </div>
  )
}

function RemediationList({ steps }: { steps: string[] }) {
  return (
    <div className="space-y-2">
      {steps.map((step, i) => (
        <div key={i} className="flex items-start gap-3 text-sm">
          <div className="w-5 h-5 rounded border border-gray-600 flex items-center justify-center shrink-0 mt-0.5">
            <span className="text-xs text-gray-500">{i + 1}</span>
          </div>
          <span className="text-gray-300">{step}</span>
        </div>
      ))}
    </div>
  )
}

export default function FindingCard({ finding, defaultExpanded = false }: FindingCardProps) {
  const [isExpanded, setIsExpanded] = useState(defaultExpanded)
  const severityConfig = getSeverityConfig(finding.severity)
  const SeverityIcon = severityConfig.icon
  const evidence = parseEvidence(finding.evidence)

  // Extract title without occurrence count for cleaner display
  const titleMatch = finding.title?.match(/^(.+?)\s*\(\d+\s*occurrences?\)$/i)
  const cleanTitle = titleMatch ? titleMatch[1] : finding.title

  const hasUrls = evidence.allUrls.length > 0
  const hasPayloads = evidence.allPayloads.length > 0
  const hasRemediation = evidence.remediation.length > 0
  const hasAnomaly = evidence.responseAnomaly !== undefined
  const hasDescription = finding.description && typeof finding.description === 'string' && finding.description.length > 0

  return (
    <div className={`bg-gray-900/60 rounded-lg border-l-4 ${severityConfig.border} overflow-hidden`}>
      {/* Header */}
      <div className="p-4">
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            {/* Severity + Title */}
            <div className="flex items-center gap-3 mb-2">
              <span className={`px-2.5 py-1 text-xs font-semibold rounded flex items-center gap-1.5 ${severityConfig.bg} ${severityConfig.text}`}>
                <SeverityIcon className="w-3.5 h-3.5" />
                {finding.severity?.toUpperCase()}
              </span>
              <h3 className="text-white font-semibold truncate">{cleanTitle}</h3>
            </div>

            {/* CWE + OWASP */}
            <div className="flex flex-wrap items-center gap-2 text-sm mb-3">
              {finding.cwe && (
                <a
                  href={`https://cwe.mitre.org/data/definitions/${finding.cwe.replace('CWE-', '')}.html`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-400 hover:text-blue-300 hover:underline"
                >
                  {finding.cwe}{finding.cwe_name ? `: ${finding.cwe_name}` : ''}
                </a>
              )}
              {finding.owasp && (
                <span className="text-gray-400">{finding.owasp}</span>
              )}
              {finding.cvss_score !== undefined && finding.cvss_score > 0 && (
                <span className="px-2 py-0.5 rounded bg-gray-700 text-gray-300 text-xs">
                  CVSS: {finding.cvss_score}
                </span>
              )}
            </div>

            {/* Evidence badges */}
            <div className="flex flex-wrap items-center gap-3 text-sm">
              {evidence.parameter && (
                <div className="flex items-center gap-1.5">
                  <span className="text-gray-500">Parameter:</span>
                  <code className="px-2 py-0.5 rounded bg-purple-900/50 text-purple-300 text-xs font-mono">
                    {evidence.parameter}
                  </code>
                </div>
              )}
              {evidence.url && (
                <div className="flex items-center gap-1.5">
                  <span className="text-gray-500">Endpoint:</span>
                  <code className="text-gray-400 text-xs truncate max-w-[300px]">
                    {extractEndpoint(evidence.url)}
                  </code>
                </div>
              )}
              {hasAnomaly && evidence.responseAnomaly && (
                <div className="flex items-center gap-1.5">
                  <span className="text-gray-500">Response:</span>
                  <span className={`text-xs ${evidence.responseAnomaly.percentChange > 100 ? 'text-red-400' : 'text-yellow-400'}`}>
                    {formatAnomaly(evidence.responseAnomaly)}
                  </span>
                </div>
              )}
              {evidence.context && (
                <div className="flex items-center gap-1.5">
                  <span className="text-gray-500">Context:</span>
                  <span className="px-2 py-0.5 rounded bg-green-900/50 text-green-300 text-xs">
                    {evidence.context}
                  </span>
                </div>
              )}
            </div>

            {/* Evidence details */}
            {evidence.evidenceDetails.length > 0 && (
              <div className="mt-3 text-sm text-gray-400">
                {evidence.evidenceDetails.map((detail, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <Zap className="w-3 h-3 text-yellow-500" />
                    <span>{detail}</span>
                  </div>
                ))}
              </div>
            )}

            {/* AI Verdict */}
            {finding.ai_verdict && (
              <div className="mt-3 flex items-center gap-2">
                <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                  finding.ai_verdict === 'true_positive' ? 'bg-red-900/50 text-red-300' :
                  finding.ai_verdict === 'false_positive' ? 'bg-green-900/50 text-green-300' :
                  'bg-yellow-900/50 text-yellow-300'
                }`}>
                  AI: {finding.ai_verdict.replace('_', ' ')}
                </span>
                {finding.ai_confidence && (
                  <span className="text-xs text-gray-400">
                    {Math.round(finding.ai_confidence * 100)}% confidence
                  </span>
                )}
              </div>
            )}
          </div>

          {/* Tool badge and expand button */}
          <div className="flex flex-col items-end gap-2 shrink-0">
            {finding.tool && (
              <span className="px-2 py-1 text-xs rounded bg-gray-800 text-gray-400">
                {finding.tool}
              </span>
            )}
            <button
              onClick={() => setIsExpanded(!isExpanded)}
              className="flex items-center gap-1 px-2 py-1 text-xs rounded bg-blue-900/50 text-blue-300 hover:bg-blue-800/50 transition-colors"
            >
              {isExpanded ? (
                <>
                  <ChevronDown className="w-3 h-3" />
                  Collapse
                </>
              ) : (
                <>
                  <ChevronRight className="w-3 h-3" />
                  Details
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Expanded details section */}
      {isExpanded && (
        <div className="px-4 pb-4 border-t border-gray-700/50 mt-2 pt-4">
          {/* Description */}
          {hasDescription && (
            <div className="mb-4">
              <h4 className="text-sm font-medium text-gray-400 mb-2">Description</h4>
              <p className="text-sm text-gray-300 whitespace-pre-wrap">{finding.description}</p>
            </div>
          )}

          {/* Evidence as JSON if available and not parsed */}
          {finding.evidence && typeof finding.evidence === 'object' && !hasUrls && !hasPayloads && (
            <div className="mb-4">
              <h4 className="text-sm font-medium text-gray-400 mb-2">Evidence</h4>
              <pre className="text-xs text-gray-300 bg-gray-800 rounded p-3 overflow-x-auto whitespace-pre-wrap">
                {JSON.stringify(finding.evidence, null, 2)}
              </pre>
            </div>
          )}

          {(finding.ai_rationale || finding.ai_recommendations) && (
            <div className="mb-4">
              <h4 className="text-sm font-medium text-gray-400 mb-2">AI Analysis</h4>
              {finding.ai_rationale && (
                <p className="text-sm text-gray-300 whitespace-pre-wrap">{finding.ai_rationale}</p>
              )}
              {Array.isArray(finding.ai_recommendations) && finding.ai_recommendations.length > 0 && (
                <ul className="mt-2 space-y-1 text-sm text-gray-300">
                  {finding.ai_recommendations.map((item, i) => (
                    <li key={String(item)} className="flex gap-2">
                      <span className="text-gray-500">{i + 1}.</span>
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              )}
              {finding.ai_recommendations && !Array.isArray(finding.ai_recommendations) && (
                <pre className="mt-2 text-xs text-gray-300 bg-gray-800 rounded p-3 overflow-x-auto whitespace-pre-wrap">
                  {JSON.stringify(finding.ai_recommendations, null, 2)}
                </pre>
              )}
            </div>
          )}

          {/* Vulnerable URLs */}
          {hasUrls && (
            <CollapsibleSection
              title="Vulnerable URLs"
              count={evidence.allUrls.length}
              defaultOpen={true}
            >
              <UrlList urls={evidence.allUrls} parameter={evidence.parameter} />
            </CollapsibleSection>
          )}

          {/* Working Payloads */}
          {hasPayloads && (
            <CollapsibleSection
              title="Working Payloads"
              count={evidence.allPayloads.length}
              defaultOpen={true}
            >
              <PayloadList payloads={evidence.allPayloads} />
            </CollapsibleSection>
          )}

          {/* Remediation Steps */}
          {hasRemediation && (
            <CollapsibleSection
              title="Remediation Steps"
              count={evidence.remediation.length}
              defaultOpen={true}
            >
              <RemediationList steps={evidence.remediation} />
            </CollapsibleSection>
          )}

          {/* Link to database finding if it has a UUID */}
          {finding.id && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(finding.id) && (
            <div className="mt-4 pt-3 border-t border-gray-700/50">
              <a
                href={`/findings/${finding.id}`}
                className="inline-flex items-center gap-1.5 text-sm text-blue-400 hover:text-blue-300"
              >
                <ExternalLink className="w-4 h-4" />
                View in Findings Database
              </a>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
