'use client'

import type { ReactNode } from 'react'
import Link from '@/components/WorkspaceLink'
import {
  Archive, BookOpen, CalendarClock, Camera, Cpu, Crosshair, ExternalLink, Globe, HardDrive, Lock,
  Network, Play, Printer, Radar, RotateCcw, Router, Server, ShieldCheck, ShieldOff, SlidersHorizontal, Tv,
} from 'lucide-react'
import { Button, ROW_ACTION_REVEAL, StatusDot, gradeTextColor } from '@/components/ui'
import { DeleteRecordsButton } from '@/components/lifecycle/DeleteRecordsButton'
import type { TargetAsset } from '@/lib/targetAssetApi'
import { featureEnabled } from '@/lib/workspaceCapabilities'
import { configureScanHref, latestGrade, originLabel, relativeTime, scanUrls, severitySummary } from '@/lib/targetInventoryModel.mjs'
import { boundedDisplayText, boundedTargetDisplay } from '@/lib/targetChoices'
import { TargetDomainDiscovery } from '../TargetDomainDiscovery'
import { TargetSkillEditor } from '../TargetSkillEditor'
import { MenuItem, MenuSeparator, RowMenu } from './RowMenu'

// One grid for the column header, every row and the group headers, so columns line up across
// groups inside the single inventory table.
export const ROW_GRID = 'lg:grid lg:grid-cols-[1.75rem_minmax(0,2.4fr)_8.5rem_minmax(0,1.4fr)_9rem_7.5rem_6.5rem] lg:items-center lg:gap-3'

const SEVERITY_STYLE: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-300',
  high: 'bg-orange-500/15 text-orange-300',
  medium: 'bg-amber-400/10 text-amber-200',
  low: 'bg-sky-500/10 text-sky-300',
  info: 'bg-gray-700/40 text-gray-300',
}
const DEVICE_ICON: Record<string, typeof Tv> = { media: Tv, camera: Camera, printer: Printer, router: Router, nas: HardDrive }

export type RowActions = {
  scan: (asset: TargetAsset) => void
  networkScan: (asset: TargetAsset) => void
  authorize: (assets: TargetAsset[]) => void
  revoke: (asset: TargetAsset) => void
  restore: (asset: TargetAsset) => void
  refresh: () => void
}

export function assetKind(asset: TargetAsset): 'device' | 'domain' | 'address' {
  if (asset.connected_device) return 'device'
  const locator = asset.locator || ''
  if (/^\d+(\.\d+){3}$/.test(locator) || locator.includes(':') || /^\d+$/.test(locator)) return 'address'
  if (!locator.includes('.') || /\.(local|internal|localhost|lan)$/.test(locator)) return 'address'
  return 'domain'
}

function AssetIcon({ asset }: { asset: TargetAsset }) {
  const kind = assetKind(asset)
  const Icon = kind === 'device' ? DEVICE_ICON[asset.device_class || ''] || Cpu : kind === 'address' ? Server : Globe
  return <Icon className="mt-0.5 h-4 w-4 shrink-0 text-gray-500" aria-hidden="true" />
}

/** A muted placeholder that still names what is absent for screen readers and on hover. */
function Absent({ label }: { label: string }) {
  return <span className="text-sm text-gray-600" title={label}><span aria-hidden="true">—</span><span className="sr-only">{label}</span></span>
}

function Pill({ children, className = '', title }: { children: ReactNode; className?: string; title?: string }) {
  return <span title={title} className={`inline-flex items-center gap-1 rounded-sm px-1.5 py-px text-[11px] font-medium leading-4 ${className}`}>{children}</span>
}

export function SeverityPills({ counts, compact = false }: { counts?: TargetAsset['severity_counts']; compact?: boolean }) {
  const items = severitySummary(counts).filter(item => item.severity !== 'info')
  if (!items.length) return compact ? null : <Absent label="No open findings" />
  return <span className="flex flex-wrap gap-1 lg:flex-nowrap">{items.map(item =>
    <Pill key={item.severity} title={`${item.count} ${item.severity}`} className={`tabular-nums ${SEVERITY_STYLE[item.severity]}`}>
      {item.count}<span className="uppercase opacity-80">{item.severity.slice(0, 1)}</span>
    </Pill>)}</span>
}

function WebApps({ asset }: { asset: TargetAsset }) {
  const origins = (asset.origins || []).filter(origin => origin.is_active)
  const shown = origins.slice(0, 3)
  const ports = asset.service_count || 0
  if (!origins.length && !ports) {
    return <Absent label={assetKind(asset) === 'domain' ? 'No web app yet · scan to detect' : 'No services yet · discover to find'} />
  }
  return <span className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1">
    {shown.map(origin => {
      const label = originLabel(origin.url)
      return <Link key={origin.id} href={`/targets/${origin.id}/asset`} title={origin.url}
        className="inline-flex max-w-full items-center gap-1 font-mono text-xs text-gray-300 transition-colors hover:text-blue-300">
        {label.secure ? <Lock className="h-3 w-3 text-gray-500" aria-label="HTTPS" /> : <Globe className="h-3 w-3 text-gray-500" aria-label="HTTP" />}
        <span>{label.scheme ? `${label.scheme}:${label.port}` : label.label}</span>
        {origin.last_grade && <span className={`font-sans font-semibold ${gradeTextColor(origin.last_grade)}`}>{origin.last_grade}</span>}
      </Link>
    })}
    {origins.length > shown.length && <Link href={`/targets/${asset.id}/asset`} className="text-xs text-gray-400 hover:text-blue-300">+{origins.length - shown.length} more</Link>}
    {ports > 0 && <span className="inline-flex items-center gap-1 text-xs text-gray-400" title="Open ports found by network discovery"><Network className="h-3 w-3 text-gray-500" aria-hidden="true" />{ports} port{ports === 1 ? '' : 's'}</span>}
  </span>
}

function LastScan({ asset }: { asset: TargetAsset }) {
  if (asset.scanning) {
    return <span className="inline-flex items-center gap-1.5 text-xs font-medium text-blue-300"><span className="h-1.5 w-1.5 animate-pulse rounded-full bg-blue-400" aria-hidden="true" />Scanning…</span>
  }
  const when = relativeTime(asset.last_scanned_at)
  if (!when) return <span className="text-xs text-gray-500">Never scanned</span>
  const grade = latestGrade(asset)
  return <span className="inline-flex items-center gap-2 text-xs tabular-nums text-gray-400" title={asset.last_scanned_at ? new Date(asset.last_scanned_at).toLocaleString() : undefined}>
    {grade && <span title="Observed posture from the latest scan · review coverage before relying on it" aria-label={`Observed posture ${grade} · review coverage`}
      className={`flex h-5 w-5 items-center justify-center rounded-sm bg-gray-800 text-xs font-semibold ${gradeTextColor(grade)}`}>{grade}</span>}
    {when}
  </span>
}

export function TargetRow({ asset, selected, onSelect, actions, busy, nested = false, discoverDomain }: {
  asset: TargetAsset; selected: boolean; onSelect: (selected: boolean) => void
  actions: RowActions; busy: boolean; nested?: boolean
  /** A standalone root domain carries its subdomain discovery in its own menu. */
  discoverDomain?: string
}) {
  // Historical rows can carry pathological labels; keep every rendered label bounded.
  const locator = boundedDisplayText(asset.locator, 120)
  const name = asset.name && asset.name !== asset.locator ? boundedDisplayText(asset.name, 120) : null
  const devices = featureEnabled('devices')
  const webApps = (asset.origins || []).filter(origin => origin.is_active).length
  const domain = assetKind(asset) === 'domain'
  const canScan = asset.is_active && (webApps > 0 || domain || devices)
  const scanLabel = webApps ? `Scan ${webApps} web app${webApps === 1 ? '' : 's'}` : domain ? 'Scan website' : 'Discover services'
  const schedule = asset.origins?.find(origin => origin.is_active)?.id || asset.id
  const facts = [
    name ? locator : null,
    asset.environment,
    asset.connected_device ? (asset.device_class && asset.device_class !== 'generic' ? asset.device_class : 'device') : null,
  ].filter(Boolean)
  return <div role="row" data-testid="target-asset-row" aria-selected={selected}
    className={`group/row relative border-t border-gray-800/70 px-4 py-2 text-sm transition-colors ${selected ? 'bg-blue-500/[0.06]' : 'hover:bg-gray-800/30'} ${ROW_GRID}`}>
    <span role="cell" className="absolute left-4 top-3.5 lg:static">
      <input type="checkbox" aria-label={`Select ${name || locator}`} checked={selected} onChange={event => onSelect(event.target.checked)}
        className="h-4 w-4 cursor-pointer rounded border-gray-600 bg-gray-900 accent-blue-500" />
    </span>
    <span role="cell" className={`flex min-w-0 items-start gap-2.5 pl-7 lg:pl-0 ${nested ? 'lg:pl-6' : ''}`}>
      <AssetIcon asset={asset} />
      <span className="min-w-0">
        <span className="flex min-w-0 items-center gap-2">
          <Link href={`/targets/${asset.id}/asset`} className="block truncate font-medium text-gray-100 hover:text-blue-300" title={boundedTargetDisplay({ url: asset.url }, { maxLength: 300 })}>
            {name || locator}
          </Link>
          {asset.has_target_skill && <span className="shrink-0 text-gray-500" title="Hunt instructions saved for this target"><BookOpen className="h-3.5 w-3.5" aria-hidden="true" /><span className="sr-only">Instructions</span></span>}
          {!asset.is_active && <Pill className="shrink-0 bg-amber-500/10 text-amber-300"><Archive className="h-3 w-3" aria-hidden="true" />Archived</Pill>}
        </span>
        <span className="block truncate text-xs text-gray-500">
          {facts.map((fact, index) => <span key={index} className={index === 0 && name ? 'font-mono' : 'capitalize'}>{index > 0 && <span aria-hidden="true"> · </span>}{fact}</span>)}
        </span>
      </span>
    </span>
    <span role="cell" className="mt-1.5 block pl-7 lg:mt-0 lg:pl-0">
      {asset.authorized
        ? <StatusDot tone="success" title="Standing authorization recorded: scans and Hunts can test this target">Authorized</StatusDot>
        : asset.is_active
          ? <StatusDot tone="neutral" className="text-gray-400" title="No standing authorization: only passive checks run until you authorize it">Not authorized</StatusDot>
          : <Absent label="Archived" />}
    </span>
    <span role="cell" className="mt-1.5 block pl-7 lg:mt-0 lg:pl-0"><WebApps asset={asset} /></span>
    <span role="cell" className="mt-1.5 flex items-center gap-4 pl-7 lg:mt-0 lg:block lg:pl-0"><SeverityPills counts={asset.severity_counts} /></span>
    <span role="cell" className="mt-1 block pl-7 lg:mt-0 lg:pl-0"><LastScan asset={asset} /></span>
    <span role="cell" className="mt-2 flex items-center justify-end gap-1 lg:mt-0">
      {asset.is_active
        // The menu always offers the same action, so the quick button can stay out of sight
        // until the row is hovered or focused.
        ? <Button size="sm" variant="secondary" disabled={!canScan} loading={busy} onClick={() => actions.scan(asset)} aria-label={`${scanLabel}: ${locator}`} title={scanLabel}
            className={busy || asset.scanning ? '' : ROW_ACTION_REVEAL}>
            {webApps || domain ? <><Play className="h-3.5 w-3.5" aria-hidden="true" />Scan</> : <><Radar className="h-3.5 w-3.5" aria-hidden="true" />Discover</>}
          </Button>
        : <Button size="sm" variant="secondary" loading={busy} onClick={() => actions.restore(asset)} aria-label={`Restore ${locator}`}><RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />Restore</Button>}
      <RowMenu label={`More actions for ${locator}`}>
        {asset.is_active && <>
          <MenuItem icon={<Play />} disabled={!webApps && !domain} onSelect={() => actions.scan(asset)}
            description="Balanced budget · passive policy">{webApps > 1 ? `Quick scan (${webApps} web apps)` : 'Quick scan'}</MenuItem>
          <MenuItem icon={<SlidersHorizontal />} disabled={!scanUrls(asset).length} href={configureScanHref(scanUrls(asset))}
            description="Choose budget, permissions, credentials, and coverage">Customize Scan…</MenuItem>
          {devices && <MenuItem icon={<Radar />} onSelect={() => actions.networkScan(asset)} description="Open ports, services and web apps">Network scan</MenuItem>}
          {discoverDomain && featureEnabled('discovery') && <TargetDomainDiscovery menuItem domain={discoverDomain} onSettled={actions.refresh} />}
          <MenuItem icon={<Crosshair />} href={`/hunt?target=${asset.id}`} description="AI investigation with this target's instructions">Start Hunt</MenuItem>
          <TargetSkillEditor menuItem targetId={asset.id} targetName={name || locator} hasSkill={asset.has_target_skill} />
          <MenuSeparator />
          {asset.authorized
            ? <MenuItem icon={<ShieldOff />} onSelect={() => actions.revoke(asset)}>Revoke authorization</MenuItem>
            : <MenuItem icon={<ShieldCheck />} onSelect={() => actions.authorize([asset])}>Authorize testing…</MenuItem>}
          <MenuItem icon={<CalendarClock />} href={`/schedules?create=true&target_id=${schedule}`}>Schedule scans</MenuItem>
        </>}
        <MenuItem icon={<ExternalLink />} href={`/targets/${asset.id}/asset`}>Open details</MenuItem>
        <MenuSeparator />
        <DeleteRecordsButton selection={{ kind: 'target', target_id: asset.id }} archived={!asset.is_active} subject={boundedDisplayText(asset.url || asset.locator, 200)}
          label={asset.is_active ? 'Archive or delete…' : 'Delete…'} variant="ghost"
          className="w-full justify-start px-3! text-red-300 hover:bg-red-500/10"
          onDeleted={actions.refresh} onArchived={actions.refresh} />
      </RowMenu>
    </span>
  </div>
}
