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
import {
  buildAsmScheduleOptions,
  buildScheduleMutation,
  readAsmScheduleOptions,
  type AsmEndpointFilter,
  type AsmFamily,
  type ScheduleKind,
} from '@/lib/deferredWorkContracts'

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
  if (!dateStr) return '—'
  const date = new Date(dateStr)
  if (isNaN(date.getTime())) return '—'
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

function getScheduleKind(schedule: Schedule): ScheduleKind {
  if (schedule.schedule_kind === 'asm_improve') return 'asm_improve'
  if (schedule.schedule_kind === 'evidence_retention_sweep') return 'evidence_retention_sweep'
  if ((schedule.scan_options as { kind?: string } | undefined)?.kind === 'asm_improve') return 'asm_improve'
  if ((schedule.scan_options as { kind?: string } | undefined)?.kind === 'evidence_retention_sweep') return 'evidence_retention_sweep'
  return 'normal_scan'
}

type RetentionClassFilter = 'all' | 'standard' | 'short' | 'audit' | 'sensitive'

const ASM_FAMILIES: Array<{ value: AsmFamily; label: string; detail: string }> = [
  { value: 'all', label: 'All runnable checks', detail: 'Balanced SQLi/XSS/auth mix' },
  { value: 'sqli', label: 'SQLi', detail: 'Focused injection coverage' },
  { value: 'xss', label: 'XSS', detail: 'Focused browser/client coverage' },
  { value: 'auth', label: 'Authz/BFLA', detail: 'Requires primary credentials' },
  { value: 'bola', label: 'BOLA/IDOR', detail: 'Requires Lab/deep and two users' },
]

function scheduleOptions(schedule: Schedule): Record<string, unknown> {
  return (schedule.scan_options || {}) as Record<string, unknown>
}

function numberOption(options: Record<string, unknown>, key: string, fallback: number): number {
  const raw = options[key]
  const value = typeof raw === 'number' ? raw : Number(raw)
  return Number.isFinite(value) ? value : fallback
}

function boolOption(options: Record<string, unknown>, key: string, fallback = false): boolean {
  const raw = options[key]
  return typeof raw === 'boolean' ? raw : raw === 'true' ? true : raw === 'false' ? false : fallback
}

function asmSummary(schedule: Schedule): string {
  const options = scheduleOptions(schedule)
  const bits = [
    `${numberOption(options, 'batch_size', 100)} endpoints`,
    `${numberOption(options, 'stale_days', 30)}d stale`,
  ]
  const family = String(options.check_family || options.asm_check_family || 'all')
  if (family !== 'all') bits.push(family)
  const endpointFilter = String(options.endpoint_filter || options.asm_endpoint_filter || 'all')
  if (endpointFilter !== 'all') bits.push(`${endpointFilter} endpoints`)
  if (boolOption(options, 'exploit_depth')) bits.push('Lab/deep')
  return bits.join(' · ')
}

function retentionSummary(schedule: Schedule): string {
  const options = scheduleOptions(schedule)
  const bits = [
    boolOption(options, 'dry_run', true) ? 'dry-run preview' : 'execute sweep',
    `${numberOption(options, 'limit', 200)} max objects`,
  ]
  const retentionClass = String(options.retention_class || 'all')
  if (retentionClass !== 'all') bits.push(retentionClass)
  if (options.older_than_days !== undefined && options.older_than_days !== null && options.older_than_days !== '') {
    bits.push(`${numberOption(options, 'older_than_days', 0)}d minimum age`)
  }
  if (boolOption(options, 'delete_local_files', true)) bits.push('delete local files')
  if (!boolOption(options, 'dry_run', true) && options.approval_receipt_id) bits.push('receipt scoped')
  return bits.join(' · ')
}

function SchedulesContent() {
  const searchParams = useSearchParams()
  const router = useRouter()
  const toast = useToast()

  const [schedules, setSchedules] = useState<Schedule[]>([])
  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState(false)
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [healthFilter, setHealthFilter] = useState(false)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [targets, setTargets] = useState<Target[]>([])
  const [deleting, setDeleting] = useState<string | null>(null)
  const [confirmDelete, setConfirmDelete] = useState<Schedule | null>(null)
  const [editingSchedule, setEditingSchedule] = useState<Schedule | null>(null)

  // Create form state
  const [formTargetId, setFormTargetId] = useState('')
  const [formName, setFormName] = useState('')
  const [formFrequency, setFormFrequency] = useState<'daily' | 'weekly'>('daily')
  const [formDayOfWeek, setFormDayOfWeek] = useState(0)
  const [formTime, setFormTime] = useState('02:00')
  const [formScanType, setFormScanType] = useState<ScanType>('standard')
  const [formKind, setFormKind] = useState<ScheduleKind>('normal_scan')
  const [formAsmBatchSize, setFormAsmBatchSize] = useState(100)
  const [formAsmStaleDays, setFormAsmStaleDays] = useState(30)
  const [formAsmEndpointFilter, setFormAsmEndpointFilter] = useState<AsmEndpointFilter>('all')
  const [formAsmFamily, setFormAsmFamily] = useState<AsmFamily>('all')
  const [formAsmExploitDepth, setFormAsmExploitDepth] = useState(false)
  const [formRetentionDryRun, setFormRetentionDryRun] = useState(true)
  const [formRetentionOlderDays, setFormRetentionOlderDays] = useState('')
  const [formRetentionClass, setFormRetentionClass] = useState<RetentionClassFilter>('all')
  const [formRetentionLimit, setFormRetentionLimit] = useState(200)
  const [formRetentionDeleteLocalFiles, setFormRetentionDeleteLocalFiles] = useState(true)
  const [formRetentionApprovalReceipt, setFormRetentionApprovalReceipt] = useState('')
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
    if (searchParams.get('health') === 'attention') {
      setHealthFilter(true)
    }
    if (searchParams.get('create') === 'true') {
      const targetId = searchParams.get('target_id')
      if (targetId) setFormTargetId(targetId)
      setEditingSchedule(null)
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
    if (!formTargetId && !editingSchedule) return

    setCreating(true)
    setError('')
    try {
      const scan_options = buildScheduleOptions()
      const mutation = buildScheduleMutation({
        name: formName,
        frequency: formFrequency,
        dayOfWeek: formDayOfWeek,
        timeOfDay: formTime,
        kind: formKind,
        scanType: formScanType,
        scanOptions: scan_options,
      })
      if (editingSchedule) {
        await updateSchedule(editingSchedule.id, mutation)
        toast.success('Schedule updated')
      } else {
        await createSchedule({
          target_id: formTargetId,
          ...mutation,
        })
        toast.success('Schedule created')
      }
      setShowCreateModal(false)
      resetForm()
      fetchSchedules({ background: true })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save schedule')
    } finally {
      setCreating(false)
    }
  }

  function buildScheduleOptions(): Record<string, unknown> | undefined {
    if (formKind === 'evidence_retention_sweep') {
      const options: Record<string, unknown> = {
        dry_run: formRetentionDryRun,
        limit: Math.max(1, Math.min(1000, Number(formRetentionLimit) || 200)),
        delete_local_files: formRetentionDeleteLocalFiles,
      }
      const olderDays = formRetentionOlderDays.trim()
      if (olderDays !== '') options.older_than_days = Math.max(0, Math.min(3650, Number(olderDays) || 0))
      if (formRetentionClass !== 'all') options.retention_class = formRetentionClass
      if (!formRetentionDryRun && formRetentionApprovalReceipt.trim()) {
        options.approval_receipt_id = formRetentionApprovalReceipt.trim()
      }
      return options
    }
    if (formKind !== 'asm_improve') return {}
    return buildAsmScheduleOptions({
      batchSize: formAsmBatchSize,
      staleDays: formAsmStaleDays,
      endpointFilter: formAsmEndpointFilter,
      family: formAsmFamily,
      exploitDepth: formAsmExploitDepth,
    })
  }

  function openEdit(schedule: Schedule) {
    const options = scheduleOptions(schedule)
    const asmOptions = readAsmScheduleOptions(options)
    setEditingSchedule(schedule)
    setFormTargetId(schedule.target_id)
    setFormName(schedule.name || '')
    setFormFrequency(schedule.frequency)
    setFormDayOfWeek(schedule.day_of_week ?? 0)
    setFormTime((schedule.time_of_day || '02:00').slice(0, 5))
    setFormScanType((schedule.scan_type || 'standard') as ScanType)
    setFormKind(getScheduleKind(schedule))
    setFormAsmBatchSize(asmOptions.batchSize)
    setFormAsmStaleDays(asmOptions.staleDays)
    setFormAsmEndpointFilter(asmOptions.endpointFilter)
    setFormAsmFamily(asmOptions.family)
    setFormAsmExploitDepth(asmOptions.exploitDepth)
    setFormRetentionDryRun(boolOption(options, 'dry_run', true))
    setFormRetentionOlderDays(options.older_than_days === undefined || options.older_than_days === null ? '' : String(options.older_than_days))
    const retentionClass = String(options.retention_class || 'all')
    setFormRetentionClass(['standard', 'short', 'audit', 'sensitive'].includes(retentionClass) ? retentionClass as RetentionClassFilter : 'all')
    setFormRetentionLimit(numberOption(options, 'limit', 200))
    setFormRetentionDeleteLocalFiles(boolOption(options, 'delete_local_files', true))
    setFormRetentionApprovalReceipt(String(options.approval_receipt_id || ''))
    setError('')
    setShowCreateModal(true)
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
    setFormKind('normal_scan')
    setFormAsmBatchSize(100)
    setFormAsmStaleDays(30)
    setFormAsmEndpointFilter('all')
    setFormAsmFamily('all')
    setFormAsmExploitDepth(false)
    setFormRetentionDryRun(true)
    setFormRetentionOlderDays('')
    setFormRetentionClass('all')
    setFormRetentionLimit(200)
    setFormRetentionDeleteLocalFiles(true)
    setFormRetentionApprovalReceipt('')
    setEditingSchedule(null)
    setError('')
  }

  function getScanTypeLabel(type: string): string {
    const found = SCAN_TYPES.find(t => t.value === type)
    return found?.label || type
  }

  const formLocalTime = utcTimeToLocalLabel(formTime)
  const asmNeedsLabDepth = formKind === 'asm_improve' && formAsmFamily === 'bola' && !formAsmExploitDepth
  const visibleSchedules = healthFilter
    ? schedules.filter(schedule => ['attention', 'warning'].includes(schedule.schedule_health?.status || ''))
    : schedules
  const unhealthyCount = schedules.filter(schedule => ['attention', 'warning'].includes(schedule.schedule_health?.status || '')).length

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
      <div className="flex flex-wrap items-center gap-3">
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
        <button
          type="button"
          onClick={() => setHealthFilter(value => !value)}
          className={`rounded-lg border px-3 py-2 text-sm transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
            healthFilter
              ? 'border-amber-500/50 bg-amber-500/15 text-amber-200'
              : 'border-gray-800 bg-gray-900 text-gray-300 hover:border-gray-700'
          }`}
        >
          Needs attention{unhealthyCount ? ` (${unhealthyCount})` : ''}
        </button>
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
      ) : visibleSchedules.length === 0 ? (
        <EmptyState
          message="No schedules match the current filter."
          action={healthFilter ? { label: 'Show all schedules', onClick: () => setHealthFilter(false) } : undefined}
        />
      ) : (
        <div className="space-y-3">
          {visibleSchedules.map((schedule) => {
            const localTime = (schedule.timezone || 'UTC') === 'UTC'
              ? utcTimeToLocalLabel(schedule.time_of_day.slice(0, 5))
              : null
            const scheduleKind = getScheduleKind(schedule)
            const health = schedule.schedule_health
            return (
            <div
              key={schedule.id}
              className={`bg-gray-900 rounded-lg border ${
                health?.status === 'attention'
                  ? 'border-amber-600/70'
                  : schedule.is_active ? 'border-gray-800' : 'border-gray-800/50 opacity-60'
              } p-4`}
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
                    {scheduleKind === 'asm_improve' ? (
                      <span className="px-2 py-0.5 bg-purple-500/15 text-purple-300 rounded text-xs" title="Continuous-ASM coverage wave: picks recon vs test batch from current gaps">
                        ASM coverage wave
                      </span>
                    ) : scheduleKind === 'evidence_retention_sweep' ? (
                      <span className="px-2 py-0.5 bg-amber-500/15 text-amber-300 rounded text-xs" title="Scheduled evidence retention sweep">
                        Evidence retention sweep
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 bg-gray-800 rounded text-xs">
                        {getScanTypeLabel(schedule.scan_type)}
                      </span>
                    )}
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
                  {scheduleKind === 'asm_improve' && (
                    <div className="mt-2 text-xs text-gray-500">
                      {asmSummary(schedule)}
                    </div>
                  )}
                  {scheduleKind === 'evidence_retention_sweep' && (
                    <div className="mt-2 text-xs text-gray-500">
                      {retentionSummary(schedule)}
                    </div>
                  )}
                  {health && ['attention', 'warning'].includes(health.status) && (
                    <div className="mt-3 rounded-md border border-amber-700/50 bg-amber-500/10 p-3">
                      <div className="flex flex-wrap items-start justify-between gap-3">
                        <div className="min-w-0">
                          <div className="text-sm font-medium text-amber-200">Schedule needs attention</div>
                          <div className="mt-1 text-sm text-amber-100/80">
                            {health.recent_failed_count || 1} recent failure{health.recent_failed_count === 1 ? '' : 's'}
                            {health.lookback_days ? ` in ${health.lookback_days} days` : ''}.
                            {health.latest_error ? ` ${health.latest_error}` : ''}
                          </div>
                          {health.recommendation && (
                            <div className="mt-1 text-xs text-amber-100/70">{health.recommendation}</div>
                          )}
                        </div>
                        <div className="flex flex-wrap gap-2">
                          {health.latest_failed_scan_id && (
                            <a
                              href={`/scans/${health.latest_failed_scan_id}`}
                              className="inline-flex items-center rounded border border-amber-500/40 bg-amber-500/15 px-2.5 py-1.5 text-xs font-medium text-amber-100 hover:bg-amber-500/25 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                            >
                              Failed scan
                            </a>
                          )}
                          {health.suggested_scan_type && (
                            <button
                              type="button"
                              onClick={() => openEdit(schedule)}
                              className="inline-flex items-center rounded border border-gray-700 bg-gray-950 px-2.5 py-1.5 text-xs font-medium text-gray-200 hover:border-gray-600 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                            >
                              Edit budget
                            </button>
                          )}
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                {/* Actions */}
                <button
                  type="button"
                  onClick={() => openEdit(schedule)}
                  className="text-gray-500 hover:text-blue-300 transition-colors p-1 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded"
                  title="Edit schedule"
                  aria-label="Edit schedule"
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16.862 3.487l3.651 3.651M4 20h4.5L19.293 9.207a1 1 0 000-1.414l-3.086-3.086a1 1 0 00-1.414 0L4 15.5V20z" />
                  </svg>
                </button>
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
          <Card className="max-w-2xl w-full max-h-[90vh] overflow-y-auto">
            <div className="p-4 border-b border-gray-800 flex items-center justify-between">
              <h2 className="font-medium text-white">{editingSchedule ? 'Edit Schedule' : 'New Schedule'}</h2>
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
                <label htmlFor="schedule-target" className="block text-sm font-medium text-gray-400 mb-1">Target</label>
                {editingSchedule ? (
                  <div className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-300">
                    {editingSchedule.target_url?.replace(/^https?:\/\//, '')}
                  </div>
                ) : (
                  <select
                    id="schedule-target"
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
                )}
              </div>

              {/* Name */}
              <div>
                <label htmlFor="schedule-name" className="block text-sm font-medium text-gray-400 mb-1">Name (optional)</label>
                <input
                  id="schedule-name"
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
                  <label htmlFor="schedule-day" className="block text-sm font-medium text-gray-400 mb-1">Day</label>
                  <select
                    id="schedule-day"
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
                <label htmlFor="schedule-time" className="block text-sm font-medium text-gray-400 mb-1">Time (UTC)</label>
                <input
                  id="schedule-time"
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

              {/* Schedule kind (§9): full scan vs ASM coverage wave vs retention sweep */}
              <div>
                <label htmlFor="schedule-kind" className="block text-sm font-medium text-gray-400 mb-1">Schedule type</label>
                <select
                  id="schedule-kind"
                  value={formKind}
                  onChange={(e) => setFormKind(e.target.value as ScheduleKind)}
                  className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="normal_scan">Full scan each run</option>
                  <option value="asm_improve">Keep this target covered (ASM coverage wave)</option>
                  <option value="evidence_retention_sweep">Evidence retention sweep</option>
                </select>
                {formKind === 'asm_improve' && (
                  <p className="mt-1 text-xs text-gray-500">
                    Each run queues a bounded ASM wave: test claimable endpoints using these limits,
                    or refresh discovery when no eligible inventory exists.
                  </p>
                )}
                {formKind === 'evidence_retention_sweep' && (
                  <p className="mt-1 text-xs text-gray-500">
                    Each run previews or executes bounded cleanup for expired evidence objects. Scheduled execution still requires an approval receipt in the schedule options.
                  </p>
                )}
              </div>

              {formKind === 'asm_improve' && (
                <div className="grid gap-4 rounded-lg border border-gray-800 bg-gray-950/40 p-3 sm:grid-cols-2">
                  <div>
                    <label htmlFor="schedule-asm-batch-size" className="block text-sm font-medium text-gray-400 mb-1">Batch size</label>
                    <input
                      id="schedule-asm-batch-size"
                      type="number"
                      min={1}
                      max={1000}
                      value={formAsmBatchSize}
                      onChange={(e) => setFormAsmBatchSize(Number(e.target.value))}
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                    />
                  </div>
                  <div>
                    <label htmlFor="schedule-asm-stale-days" className="block text-sm font-medium text-gray-400 mb-1">Retest stale after days</label>
                    <input
                      id="schedule-asm-stale-days"
                      type="number"
                      min={0}
                      value={formAsmStaleDays}
                      onChange={(e) => setFormAsmStaleDays(Number(e.target.value))}
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                    />
                  </div>
                  <div>
                    <label htmlFor="schedule-asm-endpoint-filter" className="block text-sm font-medium text-gray-400 mb-1">Endpoint scope</label>
                    <select
                      id="schedule-asm-endpoint-filter"
                      value={formAsmEndpointFilter}
                      onChange={(e) => setFormAsmEndpointFilter(e.target.value as AsmEndpointFilter)}
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                    >
                      <option value="all">All endpoints</option>
                      <option value="api">API-like endpoints only</option>
                    </select>
                  </div>
                  <div>
                    <label htmlFor="schedule-asm-family" className="block text-sm font-medium text-gray-400 mb-1">Check family</label>
                    <select
                      id="schedule-asm-family"
                      value={formAsmFamily}
                      onChange={(e) => setFormAsmFamily(e.target.value as AsmFamily)}
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                    >
                      {ASM_FAMILIES.map((family) => (
                        <option key={family.value} value={family.value}>
                          {family.label} - {family.detail}
                        </option>
                      ))}
                    </select>
                  </div>
                  <label className="sm:col-span-2 flex items-start gap-3 rounded-lg border border-gray-800 bg-gray-900/70 p-3">
                    <input
                      id="schedule-asm-exploit-depth"
                      type="checkbox"
                      aria-label="Enable Lab/deep checks"
                      checked={formAsmExploitDepth}
                      onChange={(e) => setFormAsmExploitDepth(e.target.checked)}
                      className="mt-1 h-4 w-4 rounded border-gray-600 bg-gray-800 text-blue-600 focus:ring-blue-500"
                    />
                    <span>
                      <span className="block text-sm font-medium text-gray-200">Enable Lab/deep checks</span>
                      <span className="block text-xs text-gray-500">Required for BOLA/write-side depth and still subject to credential preconditions.</span>
                    </span>
                  </label>
                </div>
              )}

              {formKind === 'evidence_retention_sweep' && (
                <div className="grid gap-4 rounded-lg border border-gray-800 bg-gray-950/40 p-3 sm:grid-cols-2">
                  <label className="sm:col-span-2 flex items-start gap-3 rounded-lg border border-gray-800 bg-gray-900/70 p-3">
                    <input
                      id="schedule-retention-dry-run"
                      type="checkbox"
                      aria-label="Preview only"
                      checked={formRetentionDryRun}
                      onChange={(e) => setFormRetentionDryRun(e.target.checked)}
                      className="mt-1 h-4 w-4 rounded border-gray-600 bg-gray-800 text-blue-600 focus:ring-blue-500"
                    />
                    <span>
                      <span className="block text-sm font-medium text-gray-200">Preview only</span>
                      <span className="block text-xs text-gray-500">Dry-run is the safe default; scheduled deletes require an approval receipt.</span>
                    </span>
                  </label>
                  <div>
                    <label htmlFor="schedule-retention-class" className="block text-sm font-medium text-gray-400 mb-1">Retention class</label>
                    <select
                      id="schedule-retention-class"
                      value={formRetentionClass}
                      onChange={(e) => setFormRetentionClass(e.target.value as RetentionClassFilter)}
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                    >
                      <option value="all">All eligible classes</option>
                      <option value="short">Short</option>
                      <option value="standard">Standard</option>
                      <option value="audit">Audit</option>
                      <option value="sensitive">Sensitive</option>
                    </select>
                  </div>
                  <div>
                    <label htmlFor="schedule-retention-older-days" className="block text-sm font-medium text-gray-400 mb-1">Minimum age override</label>
                    <input
                      id="schedule-retention-older-days"
                      type="number"
                      min={0}
                      max={3650}
                      value={formRetentionOlderDays}
                      onChange={(e) => setFormRetentionOlderDays(e.target.value)}
                      placeholder="Use policy"
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                    />
                  </div>
                  <div>
                    <label htmlFor="schedule-retention-limit" className="block text-sm font-medium text-gray-400 mb-1">Object limit</label>
                    <input
                      id="schedule-retention-limit"
                      type="number"
                      min={1}
                      max={1000}
                      value={formRetentionLimit}
                      onChange={(e) => setFormRetentionLimit(Number(e.target.value))}
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                    />
                  </div>
                  <label className="flex items-start gap-3 rounded-lg border border-gray-800 bg-gray-900/70 p-3">
                    <input
                      id="schedule-retention-delete-local-files"
                      type="checkbox"
                      aria-label="Delete local files"
                      checked={formRetentionDeleteLocalFiles}
                      onChange={(e) => setFormRetentionDeleteLocalFiles(e.target.checked)}
                      className="mt-1 h-4 w-4 rounded border-gray-600 bg-gray-800 text-blue-600 focus:ring-blue-500"
                    />
                    <span>
                      <span className="block text-sm font-medium text-gray-200">Delete local files</span>
                      <span className="block text-xs text-gray-500">Remote evidence objects are reported as preserved.</span>
                    </span>
                  </label>
                  {!formRetentionDryRun && (
                    <div className="sm:col-span-2">
                      <label htmlFor="schedule-retention-approval-receipt" className="block text-sm font-medium text-gray-400 mb-1">Approval receipt</label>
                      <input
                        id="schedule-retention-approval-receipt"
                        type="text"
                        value={formRetentionApprovalReceipt}
                        onChange={(e) => setFormRetentionApprovalReceipt(e.target.value)}
                        placeholder="Receipt UUID required for scheduled deletion"
                        className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                      />
                      <p className="mt-1 text-xs text-amber-300">
                        Scheduled deletion fails closed unless this receipt is valid when the job runs.
                      </p>
                    </div>
                  )}
                </div>
              )}

              {/* Scan Type */}
              {formKind === 'normal_scan' && (
              <div>
                <label htmlFor="schedule-scan-type" className="block text-sm font-medium text-gray-400 mb-1">Scan Type</label>
                <select
                  id="schedule-scan-type"
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
              )}

              {asmNeedsLabDepth && (
                <p className="text-sm text-amber-300">BOLA/IDOR waves require Lab/deep checks before they can be scheduled.</p>
              )}

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
                  disabled={creating || (!formTargetId && !editingSchedule) || asmNeedsLabDepth}
                  className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-600/50 text-white rounded-lg text-sm font-medium transition-colors"
                >
                  {creating ? 'Saving...' : editingSchedule ? 'Save Schedule' : 'Create Schedule'}
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
