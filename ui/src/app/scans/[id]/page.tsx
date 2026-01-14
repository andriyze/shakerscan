'use client'

import { useEffect, useState } from 'react'
import { useParams } from 'next/navigation'
import { getScan } from '@/lib/api'
import ReportView from '@/components/ReportView'

export default function ScanDetailPage() {
  const params = useParams()
  const scanId = params.id as string
  const [scan, setScan] = useState<any | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    async function fetchScan() {
      try {
        const data = await getScan(scanId)
        setScan(data)
        setError(null)
      } catch (err) {
        setError('Failed to load scan details')
      } finally {
        setLoading(false)
      }
    }

    fetchScan()
    const interval = setInterval(() => {
      if (scan?.status === 'running' || scan?.status === 'pending') {
        fetchScan()
      }
    }, 5000)
    return () => clearInterval(interval)
  }, [scanId, scan?.status])

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
      </div>
    )
  }

  if (error || !scan) {
    return (
      <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4 text-red-400">
        {error || 'Scan not found'}
      </div>
    )
  }

  // Show progress bar while running
  if (scan.status === 'running' || scan.status === 'pending') {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-3">
          <a href="/scans" className="text-gray-400 hover:text-white">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
          </a>
          <h1 className="text-2xl font-bold text-white">{scan.target_url}</h1>
        </div>
        <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-6">
          <div className="flex items-center justify-between mb-3">
            <span className="text-blue-400 font-medium text-lg">
              {scan.status === 'pending' ? 'Waiting to start...' : `Scanning: ${scan.current_phase || 'Processing'}`}
            </span>
            <span className="text-blue-400 text-xl font-bold">{scan.progress || 0}%</span>
          </div>
          <div className="w-full bg-blue-500/20 rounded-full h-3">
            <div
              className="bg-blue-500 h-3 rounded-full transition-all duration-500"
              style={{ width: `${scan.progress || 0}%` }}
            ></div>
          </div>
          <p className="text-gray-400 text-sm mt-4">
            The scan is in progress. This page will automatically update when complete.
          </p>
        </div>
      </div>
    )
  }

  // Show error for failed scans
  if (scan.status === 'failed') {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-3">
          <a href="/scans" className="text-gray-400 hover:text-white">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
          </a>
          <h1 className="text-2xl font-bold text-white">{scan.target_url}</h1>
        </div>
        <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-6 text-red-400">
          <h2 className="text-lg font-semibold mb-2">Scan Failed</h2>
          <p>{scan.error_message || 'An unknown error occurred during the scan.'}</p>
        </div>
      </div>
    )
  }

  // Show full report for completed scans
  return (
    <div>
      <div className="flex items-center gap-3 mb-4">
        <a href="/scans" className="text-gray-400 hover:text-white">
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
          </svg>
        </a>
        <span className="text-gray-500">Back to scans</span>
      </div>
      <ReportView
        scan={scan}
        isAuthenticated={true}
        enableRemediationTracking={true}
      />
    </div>
  )
}
