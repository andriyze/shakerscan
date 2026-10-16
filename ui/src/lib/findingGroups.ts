// Presentation model for the findings list: grouping repeats, the location that tells rows
// apart, and which retest outcomes are worth a row's attention. Pure, so it is unit-tested.

export interface GroupableFinding {
  id: string
  title?: string | null
  severity?: string | null
  status?: string | null
  proof_state?: string | null
  url?: string | null
  target_id?: string | null
  ai_target_id?: string | null
  device_target_id?: string | null
  target_url?: string | null
  target_name?: string | null
  ai_target_name?: string | null
  first_seen_at?: string | null
  last_seen_at?: string | null
  latest_retest_verdict?: string | null
  is_candidate?: boolean
}

export interface FindingGroup<T extends GroupableFinding> {
  key: string
  /** The first member in the server's order; the group takes its place in the list. */
  lead: T
  members: T[]
  /** The most recent last_seen_at among members (ISO string), or null when none parse. */
  lastSeenAt: string | null
  /** Every member, when the server grouped them and listed only the first `members`. */
  count?: number
}

/** A group as `GET /findings?group_by=issue` answers it (the fields the list renders). */
export interface ServerFindingGroup<T extends GroupableFinding> {
  count: number
  last_seen_at: string | null
  lead: T
  member_ids: string[]
  members: Array<Pick<GroupableFinding, 'id' | 'url' | 'last_seen_at' | 'latest_retest_verdict'>>
}

/**
 * True for a page of server groups: a list/v1 envelope whose items carry a count, member ids and
 * a lead. An engine without grouping answers rows (legacy `findings`, or list/v1 rows), and the
 * caller groups in the browser instead.
 */
export function isServerGroupsPage<G = ServerFindingGroup<GroupableFinding>>(body: unknown): body is {
  items: G[]; next_cursor: string | null; has_more: boolean; total?: number
  total_kind: 'none' | 'estimate' | 'exact' | 'at_least'; generated_at: string; findings_total?: number
} {
  if (!body || typeof body !== 'object') return false
  const page = body as { items?: unknown; has_more?: unknown }
  if (!Array.isArray(page.items) || typeof page.has_more !== 'boolean') return false
  return page.items.every((item) => Boolean(item) && typeof item === 'object'
    && typeof (item as { count?: unknown }).count === 'number'
    && Array.isArray((item as { member_ids?: unknown }).member_ids)
    && Boolean((item as { lead?: unknown }).lead))
}

/**
 * True for the 422 an engine gives when it cannot group these filters exactly (too many findings
 * whose triage only it can read). The page then groups the loaded rows in the browser for this
 * request only: the engine does group, just not this filter.
 */
export function isGroupingTooBroadError(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false
  const { status, detail } = error as { status?: unknown; detail?: unknown }
  return Number(status) === 422 && Boolean(detail) && typeof detail === 'object'
    && (detail as { error?: unknown }).error === 'proof_filter_too_broad'
}

/** Members a group lists (all of them, unless the server listed only the first ones). */
export function groupSize<T extends GroupableFinding>(group: FindingGroup<T>): number {
  return Math.max(group.count ?? 0, group.members.length)
}

/**
 * Groups the server formed over every match, in its order, shaped like browser groups. A member
 * is listed by its location, retest and sighting; it shares the rest (title, severity, subject,
 * proof, status) with its lead, since that is what makes it a member.
 */
export function groupsFromServer<T extends GroupableFinding>(items: readonly ServerFindingGroup<T>[]): FindingGroup<T>[] {
  return items.map((item) => {
    const listed = new Map(item.members.map((member) => [member.id, member]))
    const members = item.member_ids.map((id) => {
      if (id === item.lead.id) return item.lead
      const member = listed.get(id)
      return {
        ...item.lead,
        id,
        url: member?.url ?? null,
        last_seen_at: member?.last_seen_at ?? null,
        latest_retest_verdict: member?.latest_retest_verdict ?? null,
      } as T
    })
    if (!members.length) members.push(item.lead)
    return { key: `server:${item.lead.id}`, lead: item.lead, members, lastSeenAt: item.last_seen_at, count: item.count }
  })
}

/** Status partitions the list; `all` is a view, never sent to the API. */
export type StatusView = 'active' | 'resolved' | 'false_positive' | 'accepted_risk' | 'all'

const STATUS_VIEWS: ReadonlySet<string> = new Set(['active', 'resolved', 'false_positive', 'accepted_risk', 'all'])

/**
 * The status view in effect. Open work is the default: a list of every historical row hid the
 * open ones among resolved and dismissed records. A view scoped to one run (a scan or a Hunt run)
 * is that run's evidence, whatever its triage, so it defaults to all statuses.
 */
export function effectiveStatusView(urlStatus: string | undefined | null, evidenceScoped: boolean): StatusView {
  if (urlStatus && STATUS_VIEWS.has(urlStatus)) return urlStatus as StatusView
  return evidenceScoped ? 'all' : 'active'
}

/** The URL value that selects `view`: the default is left out of the URL. */
export function statusViewParam(view: StatusView, evidenceScoped: boolean): string | undefined {
  return view === effectiveStatusView(undefined, evidenceScoped) ? undefined : view
}

function subjectKey(finding: GroupableFinding): string {
  return String(
    finding.target_id || finding.ai_target_id || finding.device_target_id
      || finding.target_url || findingHost(finding) || '',
  )
}

/** Findings that are the same issue on the same subject, in the same proof and triage state. */
export function findingGroupKey(finding: GroupableFinding): string {
  return [
    String(finding.title || '').trim().toLowerCase(),
    String(finding.severity || ''),
    subjectKey(finding),
    String(finding.proof_state || ''),
    String(finding.status || ''),
    finding.is_candidate ? 'candidate' : 'finding',
  ].join('\u0000')
}

function parsedTime(value: string | null | undefined): number | null {
  if (!value) return null
  const time = new Date(value).getTime()
  return Number.isNaN(time) ? null : time
}

/** Groups in first-seen order of the server's sort, so sorting still means what it says. */
export function groupFindings<T extends GroupableFinding>(findings: readonly T[]): FindingGroup<T>[] {
  const groups = new Map<string, FindingGroup<T>>()
  for (const finding of findings) {
    const key = findingGroupKey(finding)
    const group = groups.get(key)
    if (group) group.members.push(finding)
    else groups.set(key, { key, lead: finding, members: [finding], lastSeenAt: null })
  }
  for (const group of groups.values()) {
    let latest: number | null = null
    for (const member of group.members) {
      const time = parsedTime(member.last_seen_at)
      if (time !== null && (latest === null || time > latest)) {
        latest = time
        group.lastSeenAt = member.last_seen_at || null
      }
    }
  }
  return [...groups.values()]
}

/** Host of the finding's URL, else of its target; empty when neither parses. */
export function findingHost(finding: GroupableFinding): string {
  for (const raw of [finding.url, finding.target_url]) {
    if (!raw) continue
    try {
      return new URL(raw).host
    } catch {
      // not a URL; try the next
    }
  }
  return ''
}

/**
 * Where on the subject it was observed: the path plus the names (never values) of any query
 * parameters. Titles repeat; the location is what tells rows apart.
 */
export function findingLocation(finding: GroupableFinding): string {
  const raw = String(finding.url || '')
  if (!raw) return ''
  try {
    const parsed = new URL(raw)
    const names = Array.from(new Set(parsed.searchParams.keys())).slice(0, 4)
    return `${parsed.pathname || '/'}${names.length ? `?${names.join('&')}` : ''}`
  } catch {
    return raw.length > 80 ? `${raw.slice(0, 77)}…` : raw
  }
}

/**
 * What the finding is about: an AI target by name (several AI targets can share one endpoint
 * host, and the host alone made them read as duplicates), else the URL host, else the named
 * target (a device).
 */
export function findingSubject(finding: GroupableFinding): string {
  if (finding.ai_target_id && finding.ai_target_name) return String(finding.ai_target_name)
  return findingHost(finding) || String(finding.ai_target_name || finding.target_name || '')
}

export interface RetestSignal {
  label: string
  tone: 'danger' | 'success' | 'muted'
  title: string
}

const RETEST_LABELS: Record<string, string> = {
  exploited: 'Still vulnerable',
  likely_vulnerable: 'Likely vulnerable',
  blocked_by_security: 'Retest blocked',
  out_of_scope_internal: 'Retest out of scope',
  inconclusive: 'Retest inconclusive',
  false_positive: 'Retest: false positive',
  likely_fixed: 'Retest: likely fixed',
  error: 'Retest error',
}

const STILL_PRESENT = new Set(['exploited', 'likely_vulnerable'])
const GONE = new Set(['likely_fixed', 'false_positive'])

/**
 * The latest retest outcome, only when it tells the reader something the row does not: an open
 * finding a retest could not reproduce, a closed one a retest still reproduces, or a retest that
 * could not decide. "Still vulnerable" on an open finding repeats the row and is left out.
 */
export function retestSignal(verdict: string | null | undefined, status: string | null | undefined): RetestSignal | null {
  if (!verdict) return null
  const label = RETEST_LABELS[verdict] ?? `Retest: ${verdict.replace(/_/g, ' ')}`
  const title = `Latest retest: ${label.replace(/^Retest:\s*/, '').toLowerCase()}. A retest verdict does not change the triage status on its own.`
  const open = !status || status === 'active'
  if (STILL_PRESENT.has(verdict)) return open ? null : { label, tone: 'danger', title }
  if (GONE.has(verdict)) return open ? { label, tone: 'success', title } : null
  return { label, tone: 'muted', title }
}

/**
 * The count line: what is shown, how it is grouped, and whether the loaded rows are all of
 * them. A grouped view of a partial load says so; it never implies the groups are complete.
 */
export function findingCountSummary({
  total,
  loaded,
  offset,
  groups,
  statusLabel,
}: {
  total: number
  loaded: number
  offset: number
  groups: number | null
  statusLabel: string
}): string {
  const noun = `${statusLabel ? `${statusLabel} ` : ''}finding${total === 1 ? '' : 's'}`
  const partial = loaded < total
  const range = partial ? ` · showing ${(offset + 1).toLocaleString()}–${(offset + loaded).toLocaleString()}` : ''
  if (groups === null) return `${total.toLocaleString()} ${noun}${range}`
  const grouped = ` in ${groups.toLocaleString()} group${groups === 1 ? '' : 's'}`
  return partial
    ? `${total.toLocaleString()} ${noun}${range}${grouped} (groups cover the loaded rows only)`
    : `${total.toLocaleString()} ${noun}${grouped}`
}

/**
 * The count line for groups the server formed over every match: the findings, the groups, and
 * which groups this page shows. The groups are complete, so nothing is qualified.
 */
export function groupedCountSummary({
  findings,
  groups,
  start,
  shown,
  statusLabel,
}: {
  findings: number
  groups: number
  start: number
  shown: number
  statusLabel: string
}): string {
  const noun = `${statusLabel ? `${statusLabel} ` : ''}finding${findings === 1 ? '' : 's'}`
  const grouped = `${findings.toLocaleString()} ${noun} in ${groups.toLocaleString()} group${groups === 1 ? '' : 's'}`
  if (shown >= groups) return grouped
  return `${grouped} · showing groups ${start.toLocaleString()}–${(start + shown - 1).toLocaleString()}`
}
