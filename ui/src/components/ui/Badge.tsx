import {
  CAMPAIGN_STATUS_BADGE_STYLES,
  FINDING_STATUS_BADGE_STYLES,
  HYPOTHESIS_STATUS_BADGE_STYLES,
  RETENTION_CLASS_BADGE_STYLES,
  RETEST_VERDICT_BADGE_STYLES,
  RETEST_VERDICT_LABELS,
  RISK_TIER_BADGE_STYLES,
  SCAN_STATUS_BADGE_STYLES,
  SEVERITY_BADGE_STYLES,
  SOURCE_TYPE_BADGE_STYLES,
  TIMELINE_STATUS_BADGE_STYLES,
  type FindingSourceType,
  type FindingStatus,
  type RiskTier,
  type ScanStatus,
  type SeverityLevel,
  type TimelineStatus,
  gradeTextColorClass,
} from '@/lib/constants'

const BADGE_BASE = 'inline-flex items-center gap-1.5 px-2 py-0.5 text-xs font-medium rounded'

export function Badge({
  className = '',
  children,
  title,
}: {
  className?: string
  children: React.ReactNode
  title?: string
}) {
  return <span className={`${BADGE_BASE} ${className}`} title={title}>{children}</span>
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

/**
 * Proof-state badge (docs §7): distinguishes a deterministically PROVEN finding
 * from a SUSPECTED (unproven High/Critical) lead at a glance in the findings list,
 * driven by the single server-derived `proof_state`. Renders nothing for ordinary
 * unverified low/medium findings so the list stays uncluttered.
 */
export function ProofStateBadge({
  proofState,
  className = '',
}: {
  proofState?: 'verified' | 'suspected' | 'refuted' | 'inconclusive' | 'unverified' | null
  className?: string
}) {
  if (proofState === 'verified') {
    return (
      <Badge className={`bg-emerald-500/20 text-emerald-300 ${className}`} >
        <span className="w-1.5 h-1.5 bg-emerald-400 rounded-full" aria-hidden="true" />
        Proven
      </Badge>
    )
  }
  if (proofState === 'suspected') {
    return (
      <Badge className={`bg-amber-500/20 text-amber-300 ${className}`} title="Unproven High/Critical — a lead, not confirmed exploitation">
        Suspected
      </Badge>
    )
  }
  if (proofState === 'refuted') {
    return (
      <Badge className={`bg-red-500/20 text-red-400 ${className}`} title="Counter-evidence refuted this claim">
        Refuted
      </Badge>
    )
  }
  if (proofState === 'inconclusive') {
    return (
      <Badge className={`bg-gray-500/20 text-gray-400 ${className}`} title="Evidence was inconclusive">
        Inconclusive
      </Badge>
    )
  }
  return null
}

export function RiskTierBadge({ tier, className = '' }: { tier?: string | null; className?: string }) {
  if (!tier) return null
  const style = RISK_TIER_BADGE_STYLES[tier as RiskTier] ?? RISK_TIER_BADGE_STYLES.read_only
  return <Badge className={`${style} ${className}`}>{tier.replace(/_/g, ' ')}</Badge>
}

export function TimelineStatusBadge({ status, className = '' }: { status: string; className?: string }) {
  const style = TIMELINE_STATUS_BADGE_STYLES[status as TimelineStatus] ?? TIMELINE_STATUS_BADGE_STYLES.planned
  return (
    <Badge className={`${style} ${className}`}>
      {status === 'running' && (
        <span className="w-1.5 h-1.5 bg-blue-400 rounded-full animate-pulse" aria-hidden="true" />
      )}
      {status.replace(/_/g, ' ')}
    </Badge>
  )
}

export function CampaignStatusBadge({ status, className = '' }: { status: string; className?: string }) {
  const style = CAMPAIGN_STATUS_BADGE_STYLES[status] ?? CAMPAIGN_STATUS_BADGE_STYLES.planned
  return (
    <Badge className={`${style} ${className}`}>
      {status === 'active' && (
        <span className="w-1.5 h-1.5 bg-blue-400 rounded-full animate-pulse" aria-hidden="true" />
      )}
      {status.replace(/_/g, ' ')}
    </Badge>
  )
}

export function RetentionClassBadge({ retentionClass, className = '' }: { retentionClass?: string | null; className?: string }) {
  if (!retentionClass) return null
  const style = RETENTION_CLASS_BADGE_STYLES[retentionClass] ?? RETENTION_CLASS_BADGE_STYLES.standard
  return <Badge className={`${style} ${className}`}>{retentionClass.replace(/_/g, ' ')}</Badge>
}

export function HypothesisStatusBadge({ status, className = '' }: { status: string; className?: string }) {
  const style = HYPOTHESIS_STATUS_BADGE_STYLES[status] ?? HYPOTHESIS_STATUS_BADGE_STYLES.open
  return (
    <Badge className={`${style} ${className}`}>
      {status === 'testing' && (
        <span className="w-1.5 h-1.5 bg-indigo-400 rounded-full animate-pulse" aria-hidden="true" />
      )}
      {status.replace(/_/g, ' ')}
    </Badge>
  )
}

export function gradeTextColor(grade?: string | null): string {
  return gradeTextColorClass(grade)
}
