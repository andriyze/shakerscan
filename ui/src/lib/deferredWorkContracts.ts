export type ScheduleKind = 'normal_scan' | 'asm_improve' | 'evidence_retention_sweep'
export type SchedulableScheduleKind = Exclude<ScheduleKind, 'evidence_retention_sweep'>
export type AsmFamily = 'all' | 'sqli' | 'xss' | 'auth' | 'bola'
export type AsmEndpointFilter = 'all' | 'api'

export interface AsmScheduleForm {
  batchSize: number
  staleDays: number
  endpointFilter: AsmEndpointFilter
  family: AsmFamily
  exploitDepth: boolean
}

export function buildAsmScheduleOptions(form: AsmScheduleForm): Record<string, unknown> {
  const options: Record<string, unknown> = {
    batch_size: Math.max(1, Math.min(1000, Number(form.batchSize) || 100)),
    stale_days: Math.max(0, Number(form.staleDays) || 0),
  }
  if (form.endpointFilter !== 'all') options.endpoint_filter = form.endpointFilter
  if (form.family !== 'all') options.check_family = form.family
  if (form.exploitDepth) options.exploit_depth = true
  return options
}

export function readAsmScheduleOptions(options: Record<string, unknown>): AsmScheduleForm {
  const numberOption = (key: string, fallback: number) => {
    const value = Number(options[key])
    return Number.isFinite(value) ? value : fallback
  }
  const rawFamily = String(options.check_family || options.asm_check_family || 'all')
  const family: AsmFamily = ['all', 'sqli', 'xss', 'auth', 'bola'].includes(rawFamily)
    ? rawFamily as AsmFamily
    : 'all'
  return {
    batchSize: numberOption('batch_size', 100),
    staleDays: numberOption('stale_days', 30),
    endpointFilter: String(options.endpoint_filter || options.asm_endpoint_filter || 'all') === 'api' ? 'api' : 'all',
    family,
    exploitDepth: options.exploit_depth === true || options.exploit_depth === 'true',
  }
}

export interface ScheduleMutation {
  name?: string
  frequency: 'daily' | 'weekly'
  day_of_week?: number
  time_of_day: string
  schedule_kind: SchedulableScheduleKind
  scan_options?: Record<string, unknown>
}

export function buildScheduleMutation(input: {
  name?: string
  frequency: 'daily' | 'weekly'
  dayOfWeek: number
  timeOfDay: string
  kind: SchedulableScheduleKind
  scanOptions?: Record<string, unknown>
}): ScheduleMutation {
  return {
    name: input.name || undefined,
    frequency: input.frequency,
    day_of_week: input.frequency === 'weekly' ? input.dayOfWeek : undefined,
    time_of_day: input.timeOfDay,
    schedule_kind: input.kind,
    scan_options: input.scanOptions,
  }
}

export interface SkipReasonView {
  key: string
  label: string
  reason: string | null
}

export function normalizeSkipReasons(values: unknown[], limit = 8): {
  items: SkipReasonView[]
  remaining: number
} {
  const items = values.slice(0, limit).map((value, index) => {
    if (typeof value === 'string') {
      return { key: `${value}-${index}`, label: value, reason: null }
    }
    const row = value && typeof value === 'object' ? value as Record<string, unknown> : {}
    const label = String(row.module || row.check || row.name || `module_${index}`)
    return {
      key: `${label}-${index}`,
      label,
      reason: row.reason ? String(row.reason) : null,
    }
  })
  return { items, remaining: Math.max(0, values.length - items.length) }
}

export function safeRemediationHref(value: unknown): string | null {
  const href = String(value || '').trim()
  if (!href) return null
  if (href.startsWith('/') && !href.startsWith('//')) return href
  return null
}

function count(value: unknown): number {
  const number = Number(value)
  return Number.isFinite(number) && number >= 0 ? number : 0
}

export function normalizeParentCoverage(contribution: Record<string, unknown>) {
  const assigned = count(contribution.assigned_endpoints)
  const attempted = count(contribution.attempted_endpoints)
  const selected = count(contribution.active_endpoints_selected)
  const telemetryShards = count(contribution.telemetry_shards)
  return {
    assigned,
    attempted,
    selected,
    tested: attempted || selected,
    telemetryShards,
    attemptTelemetryAvailable: telemetryShards > 0 || attempted > 0,
    contributingShards: count(contribution.shards_with_contribution),
    complete: assigned > 0 && (attempted || selected) >= assigned,
  }
}

export function normalizeFamilyCoverage(value: Record<string, unknown>) {
  const attempted = count(value.attempted ?? value.attempts)
  const completed = count(value.completed)
  const proved = count(value.proved)
  return {
    attempted,
    completed,
    proved,
    blocked: count(value.blocked),
    cancelled: count(value.cancelled),
    partial: count(value.partial),
    failed: count(value.failed),
    label: `${proved} proved / ${completed} completed / ${attempted} attempted`,
  }
}
