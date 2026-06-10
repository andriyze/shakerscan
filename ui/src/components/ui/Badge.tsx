import {
  FINDING_STATUS_BADGE_STYLES,
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

export function gradeTextColor(grade?: string | null): string {
  return gradeTextColorClass(grade)
}
