'use client'

import Link from '@/components/WorkspaceLink'
import { Button, Card } from '@/components/ui'
import type { DeviceAgentShellPlan } from '@/lib/api'
import { HUNT_BUDGET_DIMENSIONS } from '@/lib/huntContract.generated'
import type { HuntV2 } from '@/lib/huntV2'
import { budgetUsage } from '@/lib/huntRunModel.mjs'
import HuntBudgetEditor from './HuntBudgetEditor'
import { formatHuntDuration } from './huntFormat'

// 'Maximum duration (seconds)' -> 'Duration': the unit is shown with the value.
const BUDGET_LABELS: Record<string, string> = Object.fromEntries(HUNT_BUDGET_DIMENSIONS.map(item => [item.name, item.label.replace(/^Maximum /, '').replace(/\s*\(seconds\)$/i, '').replace(/^./, first => first.toUpperCase())]))

const AUTHORITIES: Array<[key: string, label: string]> = [
  ['active_testing', 'Active testing'],
  ['allow_state_changing_http', 'State-changing HTTP'],
  ['network_discovery', 'Network discovery'],
  ['allow_oob_interactions', 'Out-of-band callbacks'],
  ['allow_identity_headers', 'Identity headers'],
  ['allow_direct_origin', 'Direct origin'],
  ['credential_access', 'Stored credentials'],
]

function seconds(value: number): string {
  return formatHuntDuration(new Date(0).toISOString(), new Date(value * 1000).toISOString()) || `${value}s`
}

/** One exact SSH command plan; only a proposed plan can be confirmed. */
export function ShellPlanCard({ plan, confirming, onConfirm }: {
  plan: DeviceAgentShellPlan; confirming: boolean; onConfirm: (plan: DeviceAgentShellPlan) => void
}) {
  return (
    <div className="space-y-3 rounded-lg border border-amber-500/30 bg-amber-500/5 p-4">
      <div className="flex items-center justify-between gap-3">
        <span className="text-sm font-medium text-amber-100">Port {plan.ssh_port} · {plan.status}</span>
        <span className="text-xs text-gray-500">Expires {new Date(plan.expires_at).toLocaleString()}</span>
      </div>
      <p className="text-xs text-gray-300">{plan.purpose}</p>
      <pre className="overflow-x-auto whitespace-pre-wrap rounded-sm bg-gray-950 p-3 text-xs text-blue-200">{plan.commands.join('\n')}</pre>
      <div className="space-y-1 text-xs text-gray-400">
        <p><span className="text-gray-500">Risk:</span> {plan.risk_summary}</p>
        <p className="break-all"><span className="text-gray-500">Pinned host key:</span> {plan.expected_host_key_fingerprint}</p>
        <p className="break-all"><span className="text-gray-500">Plan digest:</span> {plan.plan_digest}</p>
      </div>
      {plan.status === 'proposed' && (
        <Button onClick={() => onConfirm(plan)} loading={confirming}>Confirm and queue these exact remote commands</Button>
      )}
      {plan.scan_id && <p className="text-xs text-emerald-300">Queued scan: {plan.scan_id}</p>}
    </div>
  )
}

/** How the run was configured and what it spent; reference material rather than results. */
export function HuntDetails({ hunt, shellPlans, confirmingPlanId, onConfirmPlan, onChanged }: {
  hunt: HuntV2
  shellPlans: DeviceAgentShellPlan[]
  confirmingPlanId: string | null
  onConfirmPlan: (plan: DeviceAgentShellPlan) => void
  onChanged: (hunt: HuntV2) => void
}) {
  const policy = hunt.policy as Record<string, unknown>
  const usage = budgetUsage(hunt, BUDGET_LABELS)
  const pastPlans = shellPlans.filter(plan => plan.status !== 'proposed')
  const capabilities = hunt.capabilities || []
  return <div className="grid gap-5 lg:grid-cols-2">
    <div className="space-y-5">
      <Card className="p-5">
        <h2 className="font-medium text-white">Authority</h2>
        <ul className="mt-3 grid grid-cols-2 gap-2 text-sm">
          {AUTHORITIES.map(([key, label]) => {
            const on = policy[key] === true
            return <li key={key} className="flex items-center gap-2">
              <span className={`h-2 w-2 rounded-full ${on ? 'bg-emerald-400' : 'bg-gray-600'}`} aria-hidden="true" />
              <span className={on ? 'text-gray-200' : 'text-gray-500'}>{label}</span>
              <span className="sr-only">{on ? 'allowed' : 'off'}</span>
            </li>
          })}
        </ul>
        {Boolean(hunt.policy_adjustments?.length) && (
          <div className="mt-4 rounded-lg border border-amber-800 p-3 text-xs text-amber-100" role="status">
            <p className="font-medium">Resolved Hunt configuration</p>
            {hunt.policy_adjustments?.map((message) => <p key={message} className="mt-1">{message}</p>)}
          </div>
        )}
      </Card>

      <Card className="p-5">
        <div className="flex items-center justify-between gap-3">
          <h2 className="font-medium text-white">Budget</h2>
          <span className="text-xs text-gray-500">{hunt.budget_profile}{(hunt.budget_revision ?? 0) > 0 ? ' (amended)' : ''}</span>
        </div>
        <ul className="mt-3 space-y-2.5">
          {usage.rows.map(row => <li key={row.name}>
            <div className="flex items-baseline justify-between gap-3 text-xs">
              <span className="text-gray-300">{row.label}</span>
              <span className="font-mono text-gray-400">
                {row.name === 'max_duration_seconds' ? `${seconds(row.used)} / ${seconds(row.limit)}` : `${row.used.toLocaleString()} / ${row.limit.toLocaleString()}`}
              </span>
            </div>
            <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-gray-800">
              <div className={`h-full rounded-full ${row.ratio >= 1 ? 'bg-amber-400' : 'bg-blue-500'}`} style={{ width: `${Math.max(row.used > 0 ? 2 : 0, row.ratio * 100)}%` }} />
            </div>
          </li>)}
        </ul>
        {usage.disabled.length > 0 && <p className="mt-3 text-xs text-gray-500">Off for this run: {usage.disabled.join(', ')}</p>}
      </Card>
      <HuntBudgetEditor hunt={hunt} onChanged={onChanged} />
    </div>

    <div className="space-y-5">
      <Card className="p-5">
        <h2 className="font-medium text-white">Context it started with</h2>
        <dl className="mt-3 space-y-2 text-sm">
          <div className="flex justify-between gap-3">
            <dt className="text-gray-500">Target instructions</dt>
            <dd className="text-right text-gray-200">
              {hunt.target_skill?.skill
                ? <Link href={`/targets/${encodeURIComponent(hunt.target_id)}/asset`} className="text-blue-300 hover:text-blue-200">{hunt.target_skill.skill.title} · v{hunt.target_skill.revision}</Link>
                : <span className="text-gray-500">none</span>}
            </dd>
          </div>
          <div className="flex justify-between gap-3">
            <dt className="text-gray-500">Methodologies used</dt>
            <dd className="min-w-0 text-right text-gray-200">{(hunt.skills || []).length ? (hunt.skills || []).map(skill => skill.title).join(', ') : <span className="text-gray-500">none</span>}</dd>
          </div>
          {hunt.target_skill?.advisory?.methodology && <div className="rounded-lg border border-blue-500/20 p-3">
            <dt className="text-blue-200">Learned knowledge · advisory</dt>
            <dd className="mt-2 whitespace-pre-wrap text-xs leading-6 text-gray-400">{hunt.target_skill.advisory.methodology}</dd>
          </div>}
          {Boolean(hunt.context_pack?.target_actions) && <div className="flex justify-between gap-3">
            <dt className="text-gray-500">Saved target actions</dt>
            <dd><Link href={`/targets/${encodeURIComponent(hunt.target_id)}/asset`} className="text-blue-300">View and edit actions</Link></dd>
          </div>}
        </dl>
        <details className="mt-4 text-xs">
          <summary className="cursor-pointer text-gray-400 hover:text-gray-200">{capabilities.length} capabilities allowed</summary>
          <ul className="mt-2 grid gap-1 sm:grid-cols-2">
            {capabilities.map(capability => <li key={capability.name} className="flex justify-between gap-2 rounded bg-gray-950 px-2 py-1">
              <code className="truncate text-blue-300" title={capability.description}>{capability.name}</code>
              <span className="shrink-0 text-gray-500">{capability.risk_tier}</span>
            </li>)}
          </ul>
        </details>
      </Card>

      {pastPlans.length > 0 && <Card className="space-y-4 p-5">
        <h2 className="font-medium text-white">SSH command plans</h2>
        {pastPlans.map(plan => <ShellPlanCard key={plan.plan_id} plan={plan} confirming={confirmingPlanId === plan.plan_id} onConfirm={onConfirmPlan} />)}
      </Card>}

      <Card className="p-5">
        <h2 className="font-medium text-white">Record</h2>
        <dl className="mt-3 space-y-1.5 text-xs">
          <div className="flex justify-between gap-3"><dt className="text-gray-500">Run ID</dt><dd className="select-all break-all text-right font-mono text-gray-300">{hunt.hunt_id}</dd></div>
          {hunt.created_at && <div className="flex justify-between gap-3"><dt className="text-gray-500">Started</dt><dd className="text-gray-300">{new Date(hunt.created_at).toLocaleString()}</dd></div>}
          {hunt.completed_at && <div className="flex justify-between gap-3"><dt className="text-gray-500">Completed</dt><dd className="text-gray-300">{new Date(hunt.completed_at).toLocaleString()}</dd></div>}
          {formatHuntDuration(hunt.created_at, hunt.completed_at) && <div className="flex justify-between gap-3"><dt className="text-gray-500">{hunt.completed_at ? 'Elapsed' : 'Elapsed so far'}</dt><dd className="text-gray-300">{formatHuntDuration(hunt.created_at, hunt.completed_at)}</dd></div>}
          {hunt.stop_reason && <div className="flex justify-between gap-3"><dt className="text-gray-500">Stop reason</dt><dd className="text-gray-300">{hunt.stop_reason.replaceAll('_', ' ')}</dd></div>}
          {typeof policy.approval_receipt_id === 'string' && <div className="flex justify-between gap-3"><dt className="text-gray-500">Approval receipt</dt><dd className="break-all text-right font-mono text-gray-400">{policy.approval_receipt_id}</dd></div>}
          {typeof policy.scope_receipt_id === 'string' && <div className="flex justify-between gap-3"><dt className="text-gray-500">Scope receipt</dt><dd className="break-all text-right font-mono text-gray-400">{policy.scope_receipt_id}</dd></div>}
        </dl>
      </Card>
    </div>
  </div>
}
