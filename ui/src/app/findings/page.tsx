'use client'

import { useEffect, useState } from 'react'
import { getFindings, updateFinding, getSeverityBg, formatDate, type Finding } from '@/lib/api'

export default function FindingsPage() {
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [severityFilter, setSeverityFilter] = useState<string>('')
  const [statusFilter, setStatusFilter] = useState<string>('active')
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)

  useEffect(() => {
    fetchFindings()
  }, [severityFilter, statusFilter])

  async function fetchFindings() {
    try {
      setLoading(true)
      const data = await getFindings({
        severity: severityFilter || undefined,
        status: statusFilter || undefined,
        limit: 200
      })
      setFindings(data.findings || [])
    } catch (err) {
      console.error('Failed to fetch findings:', err)
    } finally {
      setLoading(false)
    }
  }

  async function handleStatusChange(findingId: string, newStatus: string, scanId?: string) {
    try {
      await updateFinding(findingId, newStatus, undefined, scanId)
      await fetchFindings()
      setSelectedFinding(null)
    } catch (err) {
      console.error('Failed to update finding:', err)
    }
  }

  // Count by severity
  const severityCounts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1
    return acc
  }, {} as Record<string, number>)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Findings</h1>
        <p className="text-gray-400 mt-1">Vulnerability findings across all scans</p>
      </div>

      {/* Severity Summary */}
      <div className="flex gap-2 flex-wrap">
        {['critical', 'high', 'medium', 'low', 'info'].map((sev) => (
          <button
            key={sev}
            onClick={() => setSeverityFilter(severityFilter === sev ? '' : sev)}
            className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
              severityFilter === sev
                ? getSeverityBg(sev)
                : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
            }`}
          >
            {sev}: {severityCounts[sev] || 0}
          </button>
        ))}
      </div>

      {/* Status Filter */}
      <div className="flex gap-2">
        {['active', 'resolved', 'false_positive', 'accepted_risk'].map((status) => (
          <button
            key={status}
            onClick={() => setStatusFilter(statusFilter === status ? '' : status)}
            className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${
              statusFilter === status
                ? 'bg-blue-600 text-white'
                : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
            }`}
          >
            {status.replace('_', ' ')}
          </button>
        ))}
      </div>

      {/* Findings List */}
      <div className="bg-gray-900 rounded-lg border border-gray-800">
        {loading ? (
          <div className="flex items-center justify-center h-32">
            <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-500"></div>
          </div>
        ) : findings.length === 0 ? (
          <div className="p-8 text-center text-gray-500">
            No findings found matching your filters.
          </div>
        ) : (
          <div className="divide-y divide-gray-800">
            {findings.map((finding) => (
              <div
                key={finding.id}
                className="p-4 hover:bg-gray-800/50 transition-colors cursor-pointer"
                onClick={() => setSelectedFinding(finding)}
              >
                <div className="flex items-start gap-3">
                  <span className={`px-2 py-0.5 text-xs font-medium rounded shrink-0 ${getSeverityBg(finding.severity)}`}>
                    {finding.severity}
                  </span>
                  <div className="flex-1 min-w-0">
                    <h3 className="text-sm font-medium text-white">{finding.title}</h3>
                    <div className="flex items-center gap-4 mt-1 text-xs text-gray-500">
                      {finding.tool && <span>Tool: {finding.tool}</span>}
                      {finding.cwe && <span>CWE: {finding.cwe}</span>}
                      {finding.cvss_score && <span>CVSS: {finding.cvss_score}</span>}
                      <span>First seen: {formatDate(finding.first_seen_at)}</span>
                    </div>
                    {finding.url && (
                      <p className="text-xs text-gray-600 truncate mt-1">{finding.url}</p>
                    )}
                  </div>
                  <StatusBadge status={finding.status} />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Finding Detail Modal */}
      {selectedFinding && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 rounded-lg border border-gray-800 max-w-2xl w-full max-h-[80vh] overflow-auto">
            <div className="p-4 border-b border-gray-800 flex items-center justify-between">
              <h2 className="font-medium text-white">Finding Details</h2>
              <div className="flex items-center gap-3">
                <a
                  href={`/findings/${selectedFinding.id}`}
                  className="text-xs text-blue-400 hover:text-blue-300"
                >
                  Open full view
                </a>
                <button
                  onClick={() => setSelectedFinding(null)}
                  className="text-gray-400 hover:text-white"
                >
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
            </div>
            <div className="p-4 space-y-4">
              <div className="flex items-center gap-2">
                <span className={`px-2 py-0.5 text-xs font-medium rounded ${getSeverityBg(selectedFinding.severity)}`}>
                  {selectedFinding.severity}
                </span>
                <StatusBadge status={selectedFinding.status} />
              </div>
              <h3 className="text-lg font-medium text-white">{selectedFinding.title}</h3>
              {selectedFinding.description && (
                <p className="text-sm text-gray-400">{selectedFinding.description}</p>
              )}
              <div className="grid grid-cols-2 gap-4 text-sm">
                {selectedFinding.tool && (
                  <div>
                    <span className="text-gray-500">Tool:</span>
                    <span className="ml-2 text-white">{selectedFinding.tool}</span>
                  </div>
                )}
                {selectedFinding.cwe && (
                  <div>
                    <span className="text-gray-500">CWE:</span>
                    <span className="ml-2 text-white">{selectedFinding.cwe}</span>
                  </div>
                )}
                {selectedFinding.owasp && (
                  <div>
                    <span className="text-gray-500">OWASP:</span>
                    <span className="ml-2 text-white">{selectedFinding.owasp}</span>
                  </div>
                )}
                {selectedFinding.cvss_score && (
                  <div>
                    <span className="text-gray-500">CVSS:</span>
                    <span className="ml-2 text-white">{selectedFinding.cvss_score}</span>
                  </div>
                )}
              </div>
              {selectedFinding.url && (
                <div>
                  <span className="text-gray-500 text-sm">URL:</span>
                  <p className="text-sm text-blue-400 break-all mt-1">{selectedFinding.url}</p>
                </div>
              )}
              <div className="pt-4 border-t border-gray-800">
                <span className="text-sm text-gray-500">Change Status:</span>
                <div className="flex gap-2 mt-2">
                  {['active', 'resolved', 'false_positive', 'accepted_risk'].map((status) => (
                    <button
                      key={status}
                      onClick={() => handleStatusChange(selectedFinding.id, status, selectedFinding.scan_id)}
                      disabled={selectedFinding.status === status}
                      className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                        selectedFinding.status === status
                          ? 'bg-blue-600 text-white cursor-default'
                          : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                      }`}
                    >
                      {status.replace('_', ' ')}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function StatusBadge({ status }: { status: string }) {
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
