'use client'

import { Fragment, useEffect, useState, useCallback, Suspense } from 'react'
import { useSearchParams, useRouter } from 'next/navigation'
import {
  getSchedules, createSchedule, updateSchedule, deleteSchedule,
  getTargets,
  type Schedule, type Target
} from '@/lib/api'
import { Pencil, Plus, Trash2 } from 'lucide-react'
import {
  ActionMenu, Button, CardSkeleton, ConfirmDialog, EmptyState, ErrorState, MenuItem, Modal, PageHeader, ROW_ACTION_REVEAL, Select,
  StatusDot, Table, TableCell, TableContainer, TableHead, TableHeaderCell, TableRow, TableSkeleton, Toggle, Toolbar, useToast,
} from '@/components/ui'
import { boundedTargetDisplay, usableWebTargets } from '@/lib/targetChoices'
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

const ASM_FAMILIES: Array<{ value: AsmFamily; label: string; detail: string }> = [
  { value: 'all', label: 'All runnable checks', detail: 'Balanced SQLi/XSS mix' },
  { value: 'sqli', label: 'SQLi', detail: 'Focused injection coverage' },
  { value: 'xss', label: 'XSS', detail: 'Focused browser/client coverage' },
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
  const [formBudgetProfile, setFormBudgetProfile] = useState<'fast' | 'balanced' | 'thorough' | 'deep'>('balanced')
  const [formKind, setFormKind] = useState<ScheduleKind>('normal_scan')
  const [formAsmBatchSize, setFormAsmBatchSize] = useState(100)
  const [formAsmStaleDays, setFormAsmStaleDays] = useState(30)
  const [formAsmEndpointFilter, setFormAsmEndpointFilter] = useState<AsmEndpointFilter>('all')
  const [formAsmFamily, setFormAsmFamily] = useState<AsmFamily>('all')
  const [formAsmExploitDepth, setFormAsmExploitDepth] = useState(false)
  const [formAsmApprovalReceiptId, setFormAsmApprovalReceiptId] = useState('')
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
        setTargets(usableWebTargets(data.targets || []))
      }).catch(err => console.error('Failed to fetch targets:', err))
    }
  }, [showCreateModal, formTargetId])


  async function handleCreate(e: React.FormEvent) {
    e.preventDefault()
    if (!formTargetId && !editingSchedule) return
    if (formKind === 'evidence_retention_sweep') {
      setError('Choose a scan or ASM schedule to migrate this retired retention schedule.')
      return
    }
    if (formKind === 'asm_improve' && !formAsmApprovalReceiptId.trim()) {
      setError('A current target-bound asm.improve approval receipt is required.')
      return
    }

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
    if (formKind === 'normal_scan') return { budget_profile: formBudgetProfile }
    return buildAsmScheduleOptions({
      batchSize: formAsmBatchSize,
      staleDays: formAsmStaleDays,
      endpointFilter: formAsmEndpointFilter,
      family: formAsmFamily,
      exploitDepth: formAsmExploitDepth,
      approvalReceiptId: formAsmApprovalReceiptId,
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
    setFormBudgetProfile((options.budget_profile as 'fast' | 'balanced' | 'thorough' | 'deep') || 'balanced')
    setFormKind(getScheduleKind(schedule))
    setFormAsmBatchSize(asmOptions.batchSize)
    setFormAsmStaleDays(asmOptions.staleDays)
    setFormAsmEndpointFilter(asmOptions.endpointFilter)
    setFormAsmFamily(['all', 'sqli', 'xss'].includes(asmOptions.family) ? asmOptions.family : 'all')
    setFormAsmExploitDepth(asmOptions.exploitDepth)
    setFormAsmApprovalReceiptId(asmOptions.approvalReceiptId)
    setError('')
    setShowCreateModal(true)
  }

  async function handleToggle(schedule: Schedule) {
    if (getScheduleKind(schedule) === 'evidence_retention_sweep') {
      toast.error('Evidence retention schedules are retired. Edit this schedule to migrate it to a scan or ASM schedule.')
      return
    }
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
    setFormBudgetProfile('balanced')
    setFormKind('normal_scan')
    setFormAsmBatchSize(100)
    setFormAsmStaleDays(30)
    setFormAsmEndpointFilter('all')
    setFormAsmFamily('all')
    setFormAsmExploitDepth(false)
    setFormAsmApprovalReceiptId('')
    setEditingSchedule(null)
    setError('')
  }

  function getScanTypeLabel(type: string): string {
    return type === 'scan' ? 'Scan' : `Legacy ${type}`
  }

  const formLocalTime = utcTimeToLocalLabel(formTime)
  const visibleSchedules = healthFilter
    ? schedules.filter(schedule => ['attention', 'warning'].includes(schedule.schedule_health?.status || ''))
    : schedules
  const unhealthyCount = schedules.filter(schedule => ['attention', 'warning'].includes(schedule.schedule_health?.status || '')).length

  return (
    <div>
      <PageHeader
        title="Schedules"
        description="Recurring scans and coverage waves, dispatched within a jitter window."
        actions={
          <Button onClick={() => setShowCreateModal(true)}>
            <Plus className="h-4 w-4" aria-hidden="true" />
            New Schedule
          </Button>
        }
      />

      <Toolbar>
        <Select
          fullWidth={false}
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          aria-label="Filter schedules by status"
        >
          <option value="all">All statuses</option>
          <option value="active">Active</option>
          <option value="disabled">Disabled</option>
        </Select>
        <button
          type="button"
          aria-pressed={healthFilter}
          onClick={() => setHealthFilter(value => !value)}
          className={`rounded-lg border px-3 py-[7px] text-sm font-medium transition-colors focus:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500 ${
            healthFilter
              ? 'border-amber-500/40 bg-amber-500/10 text-amber-200'
              : 'border-gray-700 bg-gray-900 text-gray-300 hover:border-gray-600 hover:text-white'
          }`}
        >
          Needs attention{unhealthyCount ? ` (${unhealthyCount})` : ''}
        </button>
        {!loading && !fetchError && <span className="text-sm tabular-nums text-gray-400">{visibleSchedules.length} schedule{visibleSchedules.length === 1 ? '' : 's'}</span>}
      </Toolbar>

      {loading ? (
        <TableContainer><TableSkeleton rows={4} cols={5} /></TableContainer>
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
        <TableContainer>
          <Table aria-label="Schedules">
            <TableHead>
              <tr>
                <TableHeaderCell className="w-14"><span className="sr-only">Enabled</span></TableHeaderCell>
                <TableHeaderCell>Target</TableHeaderCell>
                <TableHeaderCell>Type</TableHeaderCell>
                <TableHeaderCell>Cadence</TableHeaderCell>
                <TableHeaderCell>Next run</TableHeaderCell>
                <TableHeaderCell>Last run</TableHeaderCell>
                <TableHeaderCell className="text-right"><span className="sr-only">Actions</span></TableHeaderCell>
              </tr>
            </TableHead>
            <tbody>
          {visibleSchedules.map((schedule) => {
            const localTime = (schedule.timezone || 'UTC') === 'UTC'
              ? utcTimeToLocalLabel(schedule.time_of_day.slice(0, 5))
              : null
            const scheduleKind = getScheduleKind(schedule)
            const legacyRetention = scheduleKind === 'evidence_retention_sweep'
            const health = schedule.schedule_health
            const needsAttention = Boolean(health && ['attention', 'warning'].includes(health.status))
            const hasDetails = needsAttention || scheduleKind === 'asm_improve' || legacyRetention
            const targetLabel = boundedTargetDisplay({ url: schedule.target_url }, { maxLength: 200, stripScheme: true })
            return (
            <Fragment key={schedule.id}>
            <TableRow className={`${schedule.is_active ? '' : 'text-gray-500'} ${hasDetails ? '[&>td]:pb-2' : ''}`}>
              <TableCell>
                <span className="inline-flex" title={legacyRetention ? 'Legacy retention schedules cannot be enabled' : schedule.is_active ? 'Disable schedule' : 'Enable schedule'}>
                  <Toggle
                    checked={schedule.is_active}
                    disabled={legacyRetention}
                    onChange={() => handleToggle(schedule)}
                    label={legacyRetention ? 'Legacy retention schedule is disabled' : 'Schedule enabled'}
                  />
                </span>
              </TableCell>
              <TableCell>
                <span className={`block max-w-[20rem] truncate font-medium ${schedule.is_active ? 'text-gray-100' : 'text-gray-400'}`} title={targetLabel}>{targetLabel}</span>
                {schedule.name && <span className="block max-w-[20rem] truncate text-xs text-gray-500">{schedule.name}</span>}
              </TableCell>
              <TableCell className="whitespace-nowrap text-sm">
                {scheduleKind === 'asm_improve' ? (
                  <span title="Continuous-ASM coverage wave: picks recon vs test batch from current gaps">ASM coverage wave</span>
                ) : legacyRetention ? (
                  <span className="text-amber-300" title="Retired evidence retention schedule">Legacy retention schedule</span>
                ) : (
                  getScanTypeLabel(schedule.scan_type)
                )}
              </TableCell>
              <TableCell className="whitespace-nowrap">
                <span className="block">
                  {schedule.frequency === 'weekly'
                    ? `Weekly ${DAYS_OF_WEEK.find(d => d.value === schedule.day_of_week)?.label || ''}`
                    : 'Daily'}
                  {' · '}<span className="tabular-nums">{schedule.time_of_day} {schedule.timezone || 'UTC'}</span>
                </span>
                <span className="block text-xs text-gray-500">
                  {localTime && <span className="tabular-nums">= {localTime} local · </span>}
                  <span title="Each dispatch is chosen within this window to avoid every scanner starting simultaneously.">
                    Dispatch jitter ±{schedule.jitter_minutes || 0}m
                  </span>
                </span>
              </TableCell>
              <TableCell className="whitespace-nowrap">
                {!schedule.is_active ? (
                  <StatusDot tone="warning">Paused — no next run</StatusDot>
                ) : schedule.next_run_at ? (
                  <StatusDot tone={needsAttention ? 'danger' : 'success'} title={new Date(schedule.next_run_at).toLocaleString()}>
                    Next jittered dispatch: {formatRelativeTime(schedule.next_run_at)}
                  </StatusDot>
                ) : (
                  <StatusDot tone="neutral">Next dispatch unavailable</StatusDot>
                )}
              </TableCell>
              <TableCell className="whitespace-nowrap text-xs tabular-nums text-gray-400">
                {schedule.last_run_at ? formatRelativeTime(schedule.last_run_at) : 'Never run'}
              </TableCell>
              <TableCell className="whitespace-nowrap">
                <span className="flex items-center justify-end gap-1">
                  <Button size="sm" variant="secondary" className={ROW_ACTION_REVEAL} onClick={() => openEdit(schedule)} aria-label="Edit schedule" title="Edit schedule">
                    <Pencil className="h-3.5 w-3.5" aria-hidden="true" />Edit
                  </Button>
                  <ActionMenu label={`More actions for ${targetLabel}`}>
                    <MenuItem icon={<Pencil />} onSelect={() => openEdit(schedule)}>Edit schedule</MenuItem>
                    <MenuItem icon={<Trash2 />} tone="danger" disabled={deleting === schedule.id} onSelect={() => setConfirmDelete(schedule)}>
                      {deleting === schedule.id ? 'Deleting…' : 'Delete schedule'}
                    </MenuItem>
                  </ActionMenu>
                </span>
              </TableCell>
            </TableRow>
            {hasDetails && (
              <tr className="group/row">
                <td colSpan={7} className="px-4 pb-3 pl-[4.5rem]">
                  {scheduleKind === 'asm_improve' && (
                    <div className="text-xs text-gray-500">
                      {asmSummary(schedule)}
                    </div>
                  )}
                  {legacyRetention && (
                    <div className="rounded-md border border-amber-700/50 bg-amber-500/10 p-2 text-xs text-amber-100">
                      Retention schedules are retired and cannot run. Edit this record to migrate it to a scan or ASM schedule, or delete it. Evidence cleanup now requires an interactive exact-preview approval.
                    </div>
                  )}
                  {health && needsAttention && (
                    <div className="mt-2 rounded-md border border-amber-700/50 bg-amber-500/10 p-3 first:mt-0">
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
                              className="inline-flex items-center rounded-md border border-amber-500/40 bg-amber-500/15 px-2.5 py-1.5 text-xs font-medium text-amber-100 hover:bg-amber-500/25 focus:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500"
                            >
                              Failed scan
                            </a>
                          )}
                          {health.suggested_scan_type && (
                            <Button size="sm" variant="secondary" onClick={() => openEdit(schedule)}>Edit budget</Button>
                          )}
                        </div>
                      </div>
                    </div>
                  )}
                </td>
              </tr>
            )}
            </Fragment>
            )
          })}
            </tbody>
          </Table>
        </TableContainer>
      )}

      {/* Create Modal */}
      <Modal
        open={showCreateModal}
        title={editingSchedule ? 'Edit Schedule' : 'New Schedule'}
        onClose={() => { setShowCreateModal(false); resetForm() }}
        size="lg"
      >
            <form onSubmit={handleCreate} className="space-y-4">
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
                    className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-hidden focus:border-blue-500"
                    required
                  >
                    <option value="">Select target...</option>
                    {targets.map((t) => (
                      <option key={t.id} value={t.id}>
                        {boundedTargetDisplay(t, { stripScheme: true })}
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
                  className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-hidden focus:border-blue-500"
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
                    className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-hidden focus:border-blue-500"
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
                  className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-hidden focus:border-blue-500"
                  required
                />
                {formLocalTime && (
                  <p className="mt-1 text-xs text-gray-500">= {formLocalTime} your local time</p>
                )}
              </div>

              {/* Schedule kind (§9): full scan vs ASM coverage wave */}
              <div>
                <label htmlFor="schedule-kind" className="block text-sm font-medium text-gray-400 mb-1">Schedule type</label>
                <select
                  id="schedule-kind"
                  value={formKind}
                  onChange={(e) => setFormKind(e.target.value as ScheduleKind)}
                  className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-hidden focus:border-blue-500"
                >
                  <option value="normal_scan">Scan each run</option>
                  <option value="asm_improve">Keep this target covered (ASM coverage wave)</option>
                  {formKind === 'evidence_retention_sweep' && (
                    <option value="evidence_retention_sweep" disabled>Legacy evidence retention (select a replacement)</option>
                  )}
                </select>
                {formKind === 'asm_improve' && (
                  <p className="mt-1 text-xs text-gray-500">
                    Each run queues a bounded ASM wave: test claimable endpoints using these limits,
                    or refresh discovery when no eligible inventory exists.
                  </p>
                )}
                {formKind === 'evidence_retention_sweep' && (
                  <p className="mt-1 text-xs text-amber-300">
                    This legacy type cannot be saved or resumed. Choose a scan or ASM schedule to migrate it; use Evidence cleanup for retention.
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
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-hidden focus:border-blue-500"
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
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-hidden focus:border-blue-500"
                    />
                  </div>
                  <div>
                    <label htmlFor="schedule-asm-endpoint-filter" className="block text-sm font-medium text-gray-400 mb-1">Endpoint scope</label>
                    <select
                      id="schedule-asm-endpoint-filter"
                      value={formAsmEndpointFilter}
                      onChange={(e) => setFormAsmEndpointFilter(e.target.value as AsmEndpointFilter)}
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-hidden focus:border-blue-500"
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
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-hidden focus:border-blue-500"
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
                      className="mt-1 h-4 w-4 rounded-sm border-gray-600 bg-gray-800 text-blue-600 focus:ring-blue-500"
                    />
                    <span>
                      <span className="block text-sm font-medium text-gray-200">Enable Lab/deep checks</span>
                      <span className="block text-xs text-gray-500">Raises proof depth within the selected SQLi/XSS family and remains budget bounded.</span>
                    </span>
                  </label>
                  <div className="sm:col-span-2">
                    <label htmlFor="schedule-asm-approval" className="block text-sm font-medium text-gray-400 mb-1">
                      asm.improve approval receipt
                    </label>
                    <input
                      id="schedule-asm-approval"
                      type="text"
                      value={formAsmApprovalReceiptId}
                      onChange={(e) => setFormAsmApprovalReceiptId(e.target.value)}
                      required
                      placeholder="Target-bound approval receipt UUID"
                      autoComplete="off"
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white font-mono text-sm focus:outline-hidden focus:border-blue-500"
                    />
                    <p className="mt-1 text-xs text-gray-500">
                      Revalidated before every wave. Expired or revoked receipts disable the schedule.
                    </p>
                  </div>
                </div>
              )}

              {/* Scan budget */}
              {formKind === 'normal_scan' && (
              <div>
                <label htmlFor="schedule-budget-profile" className="block text-sm font-medium text-gray-400 mb-1">Budget</label>
                <select
                  id="schedule-budget-profile"
                  value={formBudgetProfile}
                  onChange={(e) => setFormBudgetProfile(e.target.value as 'fast' | 'balanced' | 'thorough' | 'deep')}
                  className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-hidden focus:border-blue-500"
                >
                  <option value="fast">Fast — 30 minutes / 5,000 requests</option>
                  <option value="balanced">Balanced — 60 minutes / 20,000 requests</option>
                  <option value="thorough">Thorough — 180 minutes / 60,000 requests</option>
                  <option value="deep">Deep — 360 minutes / 150,000 requests</option>
                </select>
                </div>
              )}

              <div className="rounded-lg border border-gray-800 bg-gray-950 p-3 text-xs text-gray-400">
                <p className="font-medium text-gray-200">Effective execution policy</p>
                {formKind === 'normal_scan' ? (
                  <ul className="mt-2 space-y-1">
                    <li>Testing permission: Passive checks only</li>
                    <li>Credentials: None</li>
                    <li>Authorization receipt: Not required; active checks are not enabled</li>
                    <li>Dispatch: {formTime} UTC with ±{editingSchedule?.jitter_minutes ?? 30} minute jitter</li>
                  </ul>
                ) : (
                  <ul className="mt-2 space-y-1">
                    <li>Wave: {formAsmFamily === 'all' ? 'Server-selected eligible families' : formAsmFamily.toUpperCase()}</li>
                    <li>Lab/deep eligibility: {formAsmExploitDepth ? 'Enabled' : 'Disabled'}</li>
                    <li>Credentials: None; credential-dependent auth/BOLA families are not schedulable</li>
                    <li>Active authority: Current target-bound asm.improve receipt, revalidated per wave</li>
                    <li>Dispatch: {formTime} UTC with ±{editingSchedule?.jitter_minutes ?? 30} minute jitter</li>
                  </ul>
                )}
              </div>

              {error && (
                <p className="text-sm text-red-400">{error}</p>
              )}

              <div className="flex gap-3">
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => { setShowCreateModal(false); resetForm() }}
                  className="flex-1"
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  loading={creating}
                  disabled={(!formTargetId && !editingSchedule) || formKind === 'evidence_retention_sweep'}
                  className="flex-1"
                >
                  {creating ? 'Saving…' : editingSchedule ? 'Save Schedule' : 'Create Schedule'}
                </Button>
              </div>
            </form>
      </Modal>

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
