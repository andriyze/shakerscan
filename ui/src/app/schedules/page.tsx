'use client'

import { useEffect, useState, useCallback, Suspense } from 'react'
import { useSearchParams, useRouter } from 'next/navigation'
import {
  getSchedules, createSchedule, updateSchedule, deleteSchedule,
  getTargets,
  type Schedule, type Target
} from '@/lib/api'
import { SCAN_TYPES, type ScanType } from '@/lib/constants'
import { Button, Card, CardSkeleton, ConfirmDialog, EmptyState, ErrorState, useToast } from '@/components/ui'
import { utcTimeToLocalLabel } from '@/lib/format'

const DAYS_OF_WEEK = [
  { value: 0, label: 'Monday' },
  { value: 1, label: 'Tuesday' },
  { value: 2, label: 'Wednesday' },
  { value: 3, label: 'Thursday' },
  { value: 4, label: 'Friday' },
  { value: 5, label: 'Saturday' },
  { value: 6, label: 'Sunday' },
]

function formatRelativeTime(dateStr: string): string {
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = date.getTime() - now.getTime()
  const absDiffMs = Math.abs(diffMs)

  const minutes = Math.floor(absDiffMs / 60000)
  const hours = Math.floor(absDiffMs / 3600000)
  const days = Math.floor(absDiffMs / 86400000)

  if (diffMs > 0) {
    // Future
    if (minutes < 60) return `in ${minutes}m`
    if (hours < 24) return `in ${hours}h`
    return `in ${days}d`
  } else {
    // Past
    if (minutes < 60) return `${minutes}m ago`
    if (hours < 24) return `${hours}h ago`
    return `${days}d ago`
  }
}

function SchedulesContent() {
  const searchParams = useSearchParams()
  const router = useRouter()
  const toast = useToast()

  const [schedules, setSchedules] = useState<Schedule[]>([])
  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState(false)
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [targets, setTargets] = useState<Target[]>([])
  const [deleting, setDeleting] = useState<string | null>(null)
  const [confirmDelete, setConfirmDelete] = useState<Schedule | null>(null)

  // Create form state
  const [formTargetId, setFormTargetId] = useState('')
  const [formName, setFormName] = useState('')
  const [formFrequency, setFormFrequency] = useState<'daily' | 'weekly'>('daily')
  const [formDayOfWeek, setFormDayOfWeek] = useState(0)
  const [formTime, setFormTime] = useState('02:00')
  const [formScanType, setFormScanType] = useState<ScanType>('standard')
  const [creating, setCreating] = useState(false)
  const [error, setError] = useState('')

  const fetchSchedules = useCallback(async (opts?: { background?: boolean }) => {
    if (!opts?.background) setLoading(true)
    try {
      const params: { is_active?: boolean } = {}
      if (statusFilter === 'active') params.is_active = true
      if (statusFilter === 'disabled') params.is_active = false
      const data = await getSchedules(params)
      setSchedules(data.schedules || [])
      setFetchError(false)
    } catch (err) {
      console.error('Failed to fetch schedules:', err)
      if (!opts?.background) setFetchError(true)
    } finally {
      if (!opts?.background) setLoading(false)
    }
  }, [statusFilter])

  useEffect(() => {
    fetchSchedules()
    const interval = setInterval(() => fetchSchedules({ background: true }), 30000)
    return () => clearInterval(interval)
  }, [fetchSchedules])

  // Handle ?create=true&target_id=... from targets page
  useEffect(() => {
    if (searchParams.get('create') === 'true') {
      const targetId = searchParams.get('target_id')
      if (targetId) setFormTargetId(targetId)
      setShowCreateModal(true)
      // Clear query params
      router.replace('/schedules')
    }
  }, [searchParams, router])

  // Load targets when modal opens
  useEffect(() => {
    if (showCreateModal) {
      getTargets().then(data => {
        setTargets(data.targets || [])
        // Pre-select first target if none selected
        if (!formTargetId && data.targets?.length > 0) {
          setFormTargetId(data.targets[0].id)
        }
      }).catch(err => console.error('Failed to fetch targets:', err))
    }
  }, [showCreateModal, formTargetId])

  useEffect(() => {
    if (!showCreateModal) return
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        setShowCreateModal(false)
        resetForm()
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [showCreateModal])

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault()
    if (!formTargetId) return

    setCreating(true)
    setError('')
    try {
      await createSchedule({
        target_id: formTargetId,
        name: formName || undefined,
        frequency: formFrequency,
        day_of_week: formFrequency === 'weekly' ? formDayOfWeek : undefined,
        time_of_day: formTime,
        scan_type: formScanType,
      })
      setShowCreateModal(false)
      resetForm()
      toast.success('Schedule created')
      fetchSchedules({ background: true })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create schedule')
    } finally {
      setCreating(false)
    }
  }

  async function handleToggle(schedule: Schedule) {
    try {
      await updateSchedule(schedule.id, { is_active: !schedule.is_active })
      toast.success(schedule.is_active ? 'Schedule paused' : 'Schedule resumed')
      fetchSchedules({ background: true })
    } catch (err) {
      console.error('Failed to toggle schedule:', err)
      toast.error('Failed to update schedule')
    }
  }

  async function handleDelete(schedule: Schedule) {
    setDeleting(schedule.id)
    try {
      await deleteSchedule(schedule.id)
      toast.success('Schedule deleted')
      setConfirmDelete(null)
      fetchSchedules({ background: true })
    } catch (err) {
      console.error('Failed to delete schedule:', err)
      toast.error('Failed to delete schedule')
    } finally {
      setDeleting(null)
    }
  }

  function resetForm() {
    setFormTargetId('')
    setFormName('')
    setFormFrequency('daily')
    setFormDayOfWeek(0)
    setFormTime('02:00')
    setFormScanType('standard')
    setError('')
  }

  function getScanTypeLabel(type: string): string {
    const found = SCAN_TYPES.find(t => t.value === type)
    return found?.label || type
  }

  const formLocalTime = utcTimeToLocalLabel(formTime)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Schedules</h1>
          <p className="text-gray-400 mt-1">Manage recurring scans</p>
        </div>
        <Button onClick={() => setShowCreateModal(true)}>
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          New Schedule
        </Button>
      </div>

      {/* Status Filter */}
      <div className="flex items-center gap-3">
        <label className="text-sm text-gray-400">Status:</label>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="px-3 py-2 bg-gray-900 border border-gray-800 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
        >
          <option value="all">All</option>
          <option value="active">Active</option>
          <option value="disabled">Disabled</option>
        </select>
      </div>

      {/* Schedule Cards */}
      {loading ? (
        <CardSkeleton count={3} />
      ) : fetchError ? (
        <ErrorState message="Failed to load schedules. Is the API running?" onRetry={() => fetchSchedules()} />
      ) : schedules.length === 0 ? (
        <EmptyState
          message="No schedules yet. Create one to automate your scans."
          action={{ label: 'Create schedule', onClick: () => setShowCreateModal(true) }}
        />
      ) : (
        <div className="space-y-3">
          {schedules.map((schedule) => {
            const localTime = (schedule.timezone || 'UTC') === 'UTC'
              ? utcTimeToLocalLabel(schedule.time_of_day.slice(0, 5))
              : null
            return (
            <div
              key={schedule.id}
              className={`bg-gray-900 rounded-lg border ${schedule.is_active ? 'border-gray-800' : 'border-gray-800/50 opacity-60'} p-4`}
            >
              <div className="flex items-start gap-4">
                {/* Toggle */}
                <button
                  type="button"
                  onClick={() => handleToggle(schedule)}
                  role="switch"
                  aria-checked={schedule.is_active}
                  aria-label={schedule.is_active ? 'Disable schedule' : 'Enable schedule'}
                  className={`mt-1 relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                    schedule.is_active ? 'bg-blue-600' : 'bg-gray-700'
                  }`}
                  title={schedule.is_active ? 'Disable schedule' : 'Enable schedule'}
                >
                  <span
                    className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                      schedule.is_active ? 'translate-x-4' : 'translate-x-0'
                    }`}
                  />
                </button>

                {/* Info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-white truncate">
                      {schedule.target_url?.replace(/^https?:\/\//, '')}
                    </span>
                    {schedule.name && (
                      <span className="text-sm text-gray-500 truncate">
                        ({schedule.name})
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-3 mt-1 text-sm text-gray-400">
                    <span className="px-2 py-0.5 bg-gray-800 rounded text-xs">
                      {getScanTypeLabel(schedule.scan_type)}
                    </span>
                    <span>
                      {schedule.frequency === 'weekly'
                        ? `Weekly ${DAYS_OF_WEEK.find(d => d.value === schedule.day_of_week)?.label || ''}`
                        : 'Daily'}
                    </span>
                    <span>
                      {schedule.time_of_day} {schedule.timezone || 'UTC'}
                      {localTime && <span className="text-gray-500"> (= {localTime} local)</span>}
                    </span>
                  </div>
                  <div className="flex items-center gap-4 mt-1 text-xs text-gray-500">
                    {schedule.next_run_at && (
                      <span>Next: {formatRelativeTime(schedule.next_run_at)}</span>
                    )}
                    {schedule.last_run_at && (
                      <span>Last: {formatRelativeTime(schedule.last_run_at)}</span>
                    )}
                    {!schedule.last_run_at && (
                      <span>Never run</span>
                    )}
                  </div>
                </div>

                {/* Delete */}
                <button
                  type="button"
                  onClick={() => setConfirmDelete(schedule)}
                  disabled={deleting === schedule.id}
                  className="text-gray-500 hover:text-red-400 transition-colors p-1 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded"
                  title="Delete schedule"
                  aria-label="Delete schedule"
                >
                  {deleting === schedule.id ? (
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-red-400"></div>
                  ) : (
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                    </svg>
                  )}
                </button>
              </div>
            </div>
            )
          })}
        </div>
      )}

      {/* Create Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <Card className="max-w-md w-full">
            <div className="p-4 border-b border-gray-800 flex items-center justify-between">
              <h2 className="font-medium text-white">New Schedule</h2>
              <button
                type="button"
                onClick={() => { setShowCreateModal(false); resetForm() }}
                aria-label="Close"
                className="text-gray-400 hover:text-white"
              >
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <form onSubmit={handleCreate} className="p-4 space-y-4">
              {/* Target */}
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">Target</label>
                <select
                  value={formTargetId}
                  onChange={(e) => setFormTargetId(e.target.value)}
                  className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  required
                >
                  <option value="">Select target...</option>
                  {targets.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.url.replace(/^https?:\/\//, '')} {t.name ? `(${t.name})` : ''}
                    </option>
                  ))}
                </select>
              </div>

              {/* Name */}
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">Name (optional)</label>
                <input
                  type="text"
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                  placeholder="Weekly prod scan"
                  className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>

              {/* Frequency */}
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">Frequency</label>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => setFormFrequency('daily')}
                    className={`flex-1 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                      formFrequency === 'daily'
                        ? 'bg-blue-600 text-white'
                        : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                    }`}
                  >
                    Daily
                  </button>
                  <button
                    type="button"
                    onClick={() => setFormFrequency('weekly')}
                    className={`flex-1 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                      formFrequency === 'weekly'
                        ? 'bg-blue-600 text-white'
                        : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                    }`}
                  >
                    Weekly
                  </button>
                </div>
              </div>

              {/* Day of Week (weekly only) */}
              {formFrequency === 'weekly' && (
                <div>
                  <label className="block text-sm font-medium text-gray-400 mb-1">Day</label>
                  <select
                    value={formDayOfWeek}
                    onChange={(e) => setFormDayOfWeek(Number(e.target.value))}
                    className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  >
                    {DAYS_OF_WEEK.map((day) => (
                      <option key={day.value} value={day.value}>{day.label}</option>
                    ))}
                  </select>
                </div>
              )}

              {/* Time */}
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">Time (UTC)</label>
                <input
                  type="time"
                  value={formTime}
                  onChange={(e) => setFormTime(e.target.value)}
                  className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  required
                />
                {formLocalTime && (
                  <p className="mt-1 text-xs text-gray-500">= {formLocalTime} your local time</p>
                )}
              </div>

              {/* Scan Type */}
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">Scan Type</label>
                <select
                  value={formScanType}
                  onChange={(e) => setFormScanType(e.target.value as ScanType)}
                  className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                >
                  {SCAN_TYPES.map((type) => (
                    <option key={type.value} value={type.value}>
                      {type.label} - {type.description} {type.duration ? `(${type.duration})` : ''}
                    </option>
                  ))}
                </select>
              </div>

              {error && (
                <p className="text-sm text-red-400">{error}</p>
              )}

              <div className="flex gap-3">
                <button
                  type="button"
                  onClick={() => { setShowCreateModal(false); resetForm() }}
                  className="flex-1 px-4 py-2 bg-gray-800 hover:bg-gray-700 text-white rounded-lg text-sm font-medium transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating || !formTargetId}
                  className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-600/50 text-white rounded-lg text-sm font-medium transition-colors"
                >
                  {creating ? 'Creating...' : 'Create Schedule'}
                </button>
              </div>
            </form>
          </Card>
        </div>
      )}

      <ConfirmDialog
        open={confirmDelete !== null}
        title="Delete schedule?"
        message={confirmDelete ? (
          <>This will permanently delete the schedule for <span className="text-gray-200">{confirmDelete.target_url?.replace(/^https?:\/\//, '')}</span>.</>
        ) : undefined}
        confirmLabel="Delete"
        danger
        busy={confirmDelete !== null && deleting === confirmDelete.id}
        onConfirm={() => { if (confirmDelete) handleDelete(confirmDelete) }}
        onCancel={() => setConfirmDelete(null)}
      />
    </div>
  )
}

export default function SchedulesPage() {
  return (
    <Suspense fallback={<CardSkeleton count={3} />}>
      <SchedulesContent />
    </Suspense>
  )
}
