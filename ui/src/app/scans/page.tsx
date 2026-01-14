'use client'

import { useEffect, useState } from 'react'
import { getScans, cancelScan, getGradeColor, formatDate, formatDuration, type Scan } from '@/lib/api'

export default function ScansPage() {
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState<string>('')
  const [cancelling, setCancelling] = useState<Set<string>>(new Set())

  async function fetchScans() {
    try {
      const data = await getScans({ limit: 100 })
      setScans(data.scans || [])
    } catch (err) {
      console.error('Failed to fetch scans:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchScans()
    const interval = setInterval(fetchScans, 5000)
    return () => clearInterval(interval)
  }, [])

  async function handleCancel(scanId: string) {
    setCancelling(prev => new Set(prev).add(scanId))
    try {
      await cancelScan(scanId)
      fetchScans()
    } catch (err) {
      console.error('Failed to cancel scan:', err)
    } finally {
      setCancelling(prev => {
        const next = new Set(prev)
        next.delete(scanId)
        return next
      })
    }
  }

  const filteredScans = scans.filter(scan =>
    scan.target_url.toLowerCase().includes(filter.toLowerCase())
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Scans</h1>
          <p className="text-gray-400 mt-1">View all security scans</p>
        </div>
        <a
          href="/scan/new"
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          New Scan
        </a>
      </div>

      {/* Search */}
      <div className="relative">
        <input
          type="text"
          placeholder="Search scans..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="w-full px-4 py-2 bg-gray-900 border border-gray-800 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
        />
        <svg className="absolute right-3 top-2.5 w-5 h-5 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
      </div>

      {/* Scans Table */}
      <div className="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center h-32">
            <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-500"></div>
          </div>
        ) : filteredScans.length === 0 ? (
          <div className="p-8 text-center text-gray-500">
            No scans found. Start a new scan to get started.
          </div>
        ) : (
          <table className="w-full">
            <thead className="bg-gray-800/50">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Target</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Type</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Status</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Score</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Findings</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Duration</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Date</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {filteredScans.map((scan) => (
                <tr key={scan.id} className="hover:bg-gray-800/50 transition-colors">
                  <td className="px-4 py-3">
                    <a href={`/scans/${scan.id}`} className="text-sm text-blue-400 hover:text-blue-300">
                      {scan.target_url}
                    </a>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-sm text-gray-400 capitalize">{scan.scan_type}</span>
                  </td>
                  <td className="px-4 py-3">
                    <StatusBadge status={scan.status} />
                  </td>
                  <td className="px-4 py-3">
                    {scan.grade ? (
                      <div className="flex items-center gap-2">
                        <span className={`text-lg font-bold ${getGradeColor(scan.grade)}`}>{scan.grade}</span>
                        <span className="text-sm text-gray-500">{scan.score}/100</span>
                      </div>
                    ) : (
                      <span className="text-gray-500">-</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-sm text-gray-400">{scan.findings_count || 0}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-sm text-gray-400">
                      {scan.duration_seconds ? formatDuration(scan.duration_seconds) : '-'}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-sm text-gray-500">{formatDate(scan.created_at)}</span>
                  </td>
                  <td className="px-4 py-3">
                    {(scan.status === 'running' || scan.status === 'pending' || scan.status === 'queued') && (
                      <button
                        onClick={() => handleCancel(scan.id)}
                        disabled={cancelling.has(scan.id)}
                        className="px-2 py-1 bg-red-600/20 hover:bg-red-600/40 text-red-400 rounded text-xs font-medium transition-colors disabled:opacity-50"
                      >
                        {cancelling.has(scan.id) ? 'Cancelling...' : 'Cancel'}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    pending: 'bg-gray-500/20 text-gray-400',
    queued: 'bg-gray-500/20 text-gray-400',
    running: 'bg-blue-500/20 text-blue-400',
    completed: 'bg-green-500/20 text-green-400',
    failed: 'bg-red-500/20 text-red-400',
    cancelled: 'bg-orange-500/20 text-orange-400'
  }

  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 text-xs font-medium rounded ${styles[status] || styles.pending}`}>
      {status === 'running' && (
        <span className="w-1.5 h-1.5 bg-blue-400 rounded-full animate-pulse"></span>
      )}
      {status}
    </span>
  )
}
