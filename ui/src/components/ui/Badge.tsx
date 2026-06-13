import {
  FINDING_STATUS_BADGE_STYLES,
  RETEST_VERDICT_BADGE_STYLES,
  RETEST_VERDICT_LABELS,
  SCAN_STATUS_BADGE_STYLES,
  SEVERITY_BADGE_STYLES,
  SOURCE_TYPE_BADGE_STYLES,
  type FindingSourceType,
  type FindingStatus,
  type ScanStatus,
  type SeverityLevel,
  gradeTextColorClass,
} from '@/lib/constants'

const BADGE_BASE = 'inline-flex items-center gap-1.5 px-2 py-0.5 text-xs font-medium rounded'

export function Badge({
  className = '',
  children,
}: {
  className?: string
  children: React.ReactNode
}) {
  return <span className={`${BADGE_BASE} ${className}`}>{children}</span>
}

export function SeverityBadge({ severity }: { severity: string }) {
  const style =
    SEVERITY_BADGE_STYLES[severity as SeverityLevel] ?? SEVERITY_BADGE_STYLES.info
  return <Badge className={`uppercase ${style}`}>{severity}</Badge>
}

export function ScanStatusBadge({ status }: { status: string }) {
  const style =
    SCAN_STATUS_BADGE_STYLES[status as ScanStatus] ?? SCAN_STATUS_BADGE_STYLES.pending
  return (
    <Badge className={style}>
      {status === 'running' && (
        <span className="w-1.5 h-1.5 bg-blue-400 rounded-full animate-pulse" aria-hidden="true" />
      )}
      {status}
    </Badge>
  )
}

export function FindingStatusBadge({ status }: { status: string }) {
  const style =
    FINDING_STATUS_BADGE_STYLES[status as FindingStatus] ?? FINDING_STATUS_BADGE_STYLES.active
  return <Badge className={style}>{status.replace(/_/g, ' ')}</Badge>
}

export function SourceTypeBadge({ type }: { type: FindingSourceType }) {
  return <Badge className={SOURCE_TYPE_BADGE_STYLES[type]}>{type}</Badge>
}

export function RetestVerdictBadge({
  verdict,
  pending = false,
  className = '',
}: {
  verdict?: string | null
  pending?: boolean
  className?: string
}) {
  if (pending) {
    return (
      <Badge className={`bg-blue-500/20 text-blue-300 ${className}`}>
        <span className="w-1.5 h-1.5 bg-blue-400 rounded-full animate-pulse" aria-hidden="true" />
        Verifying
      </Badge>
    )
  }
  if (!verdict) return null
  const style = RETEST_VERDICT_BADGE_STYLES[verdict] ?? RETEST_VERDICT_BADGE_STYLES.inconclusive
  const label = RETEST_VERDICT_LABELS[verdict] ?? verdict.replace(/_/g, ' ')
  return <Badge className={`${style} ${className}`}>{label}</Badge>
}

export function gradeTextColor(grade?: string | null): string {
  return gradeTextColorClass(grade)
}
