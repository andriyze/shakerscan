'use client'

import { useEffect, useState, Suspense, useRef } from 'react'
import { useParams, useSearchParams } from 'next/navigation'
import Link from 'next/link'
import { getScan, getScanLogs } from '@/lib/api'
import ReportView from '@/components/ReportView'

function ScanDetailContent() {
  const params = useParams()
  const searchParams = useSearchParams()
  const scanId = params.id as string
  const [scan, setScan] = useState<any | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [logs, setLogs] = useState<string[]>([])
  const [logsError, setLogsError] = useState<string | null>(null)
  const logsRef = useRef<HTMLDivElement | null>(null)

  // Build back URL with preserved filters
  const buildBackUrl = () => {
    const returnParams = new URLSearchParams()
    searchParams.forEach((value, key) => {
      if (key.startsWith('return_')) {
        returnParams.set(key.replace('return_', ''), value)
      }
    })
    const queryString = returnParams.toString()
    return queryString ? `/scans?${queryString}` : '/scans'
  }

  const backUrl = buildBackUrl()

  useEffect(() => {
    async function fetchScanAndLogs() {
      try {
        const data = await getScan(scanId)
        setScan(data)
        setError(null)
        if (data?.status === 'running' || data?.status === 'pending') {
          try {
            const logData = await getScanLogs(scanId, 200)
            setLogs(logData?.lines || [])
            setLogsError(null)
          } catch {
            setLogsError('Failed to load logs')
          }
        }
      } catch (err) {
        setError('Failed to load scan details')
      } finally {
        setLoading(false)
      }
    }

    fetchScanAndLogs()
    const interval = setInterval(() => {
      if (scan?.status === 'running' || scan?.status === 'pending') {
        fetchScanAndLogs()
      }
    }, 5000)
    return () => clearInterval(interval)
  }, [scanId, scan?.status])

  useEffect(() => {
    if (logsRef.current) {
      logsRef.current.scrollTop = logsRef.current.scrollHeight
    }
  }, [logs])

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
          <Link href={backUrl} className="text-gray-400 hover:text-white">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
          </Link>
          <h1 className="text-2xl font-bold text-white">{scan.target_url}</h1>
        </div>
        <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-6">
          <div className="flex items-center justify-between mb-3">
            <span className="text-blue-400 font-medium text-lg">
              {scan.status === 'pending'
                ? 'Waiting to start...'
                : `Scanning: ${(scan.current_phase || 'Processing').replace(/_/g, ' ')}`}
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

        <div className="bg-gray-900 rounded-lg p-4 border border-gray-800">
          <div className="flex items-center justify-between mb-2">
            <h2 className="text-sm font-semibold text-gray-400">Live Logs</h2>
            <span className="text-xs text-gray-500">{logs.length} lines</span>
          </div>
          <div ref={logsRef} className="max-h-64 overflow-y-auto bg-black/30 rounded p-3 font-mono text-xs text-gray-300">
            {logs.length > 0 ? (
              logs.map((line, idx) => (
                <div key={idx} className="whitespace-pre-wrap break-words">
                  {line}
                </div>
              ))
            ) : (
              <div className="text-gray-500">No logs yet.</div>
            )}
          </div>
          {logsError && (
            <p className="text-red-400 text-xs mt-2">{logsError}</p>
          )}
        </div>
      </div>
    )
  }

  // Show error for failed scans - but show partial results if available
  if (scan.status === 'failed') {
    const hasPartialResults = scan.result && (
      scan.result.dns || scan.result.tls || scan.result.http ||
      (scan.result.findings && scan.result.findings.length > 0)
    )
    const isPartial = scan.result?.scan_metadata?.partial === true

    // If we have partial results, show the report with a warning banner
    if (hasPartialResults) {
      return (
        <div>
          <div className="flex items-center gap-3 mb-4">
            <Link href={backUrl} className="text-gray-400 hover:text-white">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
            </Link>
            <span className="text-gray-500">Back to scans</span>
          </div>
          <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-4 mb-6">
            <div className="flex items-start gap-3">
              <svg className="w-5 h-5 text-amber-400 mt-0.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              <div>
                <h3 className="text-amber-400 font-semibold">Partial Results</h3>
                <p className="text-amber-300/80 text-sm mt-1">
                  {scan.result?.scan_metadata?.terminated_reason || scan.error_message || 'Scan was terminated before completion.'}
                  {scan.result?.scan_metadata?.terminated_at_phase && (
                    <span className="block mt-1 text-amber-300/60">
                      Last checkpoint: {scan.result.scan_metadata.terminated_at_phase}
                    </span>
                  )}
                </p>
              </div>
            </div>
          </div>
          <ReportView
            scan={scan}
            isAuthenticated={true}
            enableRemediationTracking={true}
          />
        </div>
      )
    }

    // No partial results - show error only
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-3">
          <Link href={backUrl} className="text-gray-400 hover:text-white">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
          </Link>
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
        <Link href={backUrl} className="text-gray-400 hover:text-white">
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
          </svg>
        </Link>
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

export default function ScanDetailPage() {
  return (
    <Suspense fallback={
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
      </div>
    }>
      <ScanDetailContent />
    </Suspense>
  )
}
