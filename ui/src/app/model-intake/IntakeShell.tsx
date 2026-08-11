'use client'

import { useState } from 'react'
import { CheckCircle2, Circle, Copy, LockKeyhole, PackageCheck, ShieldAlert, Server } from 'lucide-react'
import {
  downloadModelIntakeLicenseArtifact,
  downloadModelIntakeSbom,
  type ModelIntakeRunnerInstallPlan,
  type ModelIntakeRunnerReadiness,
  type ModelIntakeRunnerStorage,
  type ModelIntakeScanSummary,
} from '@/lib/api'

// Model Intake is one pipeline: pick a model, produce technical evidence, then
// take that exact evidence through controlled admission. It used to render as
// eight stacked panels with two competing numbering schemes, so this shell
// keeps the shared context pinned and shows one phase at a time.
export const INTAKE_PHASES = [
  { id: 'source', label: 'Source', helper: 'Model and deployment target' },
  { id: 'preflight', label: 'Preflight', helper: 'Technical evidence scan' },
  { id: 'admission', label: 'Admission', helper: 'Controlled deployment decision' },
  { id: 'status', label: 'Status', helper: 'Adapters, runners, admissions' },
] as const

export type IntakePhase = (typeof INTAKE_PHASES)[number]['id']

export function isTerminalScanStatus(status: ModelIntakeScanSummary['status']): boolean {
  return status === 'completed' || status === 'failed' || status === 'cancelled'
}

function chipClass(tone: 'ok' | 'warn' | 'idle'): string {
  if (tone === 'ok') return 'bg-green-950/50 text-green-300'
  if (tone === 'warn') return 'bg-yellow-950/50 text-yellow-200'
  return 'bg-gray-800 text-gray-400'
}

function Chip({
  label,
  value,
  tone,
  onClick,
  title,
}: {
  label: string
  value: string
  tone: 'ok' | 'warn' | 'idle'
  onClick?: () => void
  title?: string
}) {
  const content = (
    <>
      <span className="shrink-0 opacity-70">{label}</span>
      <span className="min-w-0 truncate font-medium">{value}</span>
    </>
  )
  const base = `inline-flex min-w-0 items-center gap-1.5 rounded px-2 py-1 text-xs ${chipClass(tone)}`
  // A chip that reports a problem should also be the way to reach the fix.
  if (!onClick) return <span className={base}>{content}</span>
  return (
    <button type="button" onClick={onClick} title={title} className={`${base} hover:brightness-125 focus:outline-none focus:ring-1 focus:ring-cyan-500`}>
      {content}
    </button>
  )
}

export function IntakeContextBar({
  source,
  environment,
  policyProfile,
  operatorReady,
  adaptersReady,
  adaptersTotal,
  runnerStatus,
  runnerSupportedHost,
  runnerUnsupportedReason,
  runnerHostPlatform,
  onOpenRunnerStatus,
}: {
  source: string
  environment: string
  policyProfile: string
  operatorReady: boolean
  adaptersReady: number | null
  adaptersTotal: number | null
  runnerStatus: string | null
  runnerSupportedHost: boolean | undefined
  runnerUnsupportedReason: string | undefined
  runnerHostPlatform: string | undefined
  onOpenRunnerStatus?: () => void
}) {
  // A microVM tier that cannot exist on this host is neutral information, not a
  // warning the operator can act on. Only a supported host that is misconfigured
  // deserves attention.
  const runnerUnsupported = runnerSupportedHost === false
  // "n/a on linux" would be nonsense — Firecracker is a Linux technology. The
  // wall on a Linux cloud guest is the missing CPU extension, not the OS.
  const runnerValue = runnerUnsupported
    ? runnerUnsupportedReason === 'no_hardware_virtualization'
      ? 'no kvm on this host'
      : `n/a on ${runnerHostPlatform || 'this host'}`
    : (runnerStatus || 'checking').toLowerCase()
  const runnerTone: 'ok' | 'warn' | 'idle' = runnerUnsupported
    ? 'idle'
    : runnerStatus === 'READY'
      ? 'ok'
      : runnerStatus
        ? 'warn'
        : 'idle'
  const adapterValue = adaptersTotal === null ? 'checking' : `${adaptersReady ?? 0}/${adaptersTotal} ready`
  const adapterTone = adaptersTotal === null ? 'idle' : adaptersReady === adaptersTotal ? 'ok' : 'warn'
  return (
    <div className="min-w-0 rounded-lg border border-gray-800 bg-gray-900 p-3">
      <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-2">
        <PackageCheck className="h-4 w-4 shrink-0 text-cyan-300" />
        <span className="min-w-0 max-w-full break-all font-mono text-sm text-white">
          {source || <span className="font-sans text-gray-500">No model selected yet</span>}
        </span>
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        <Chip label="target" value={environment} tone="idle" />
        <Chip label="policy" value={policyProfile} tone="idle" />
        {/* Not a warning: a preflight scan needs no credential, so an absent one
            is only relevant once the operator reaches the admission phase. */}
        <Chip
          label="credential"
          value={operatorReady ? 'deployment' : 'needed for admission'}
          tone={operatorReady ? 'ok' : 'idle'}
        />
        <Chip label="adapters" value={adapterValue} tone={adapterTone} />
        <Chip
          label="runner"
          value={runnerValue}
          tone={runnerTone}
          onClick={onOpenRunnerStatus}
          title="Open the microVM runner status and setup"
        />
      </div>
    </div>
  )
}

export function IntakePhaseTabs({
  phase,
  onPhaseChange,
  completed,
}: {
  phase: IntakePhase
  onPhaseChange: (next: IntakePhase) => void
  completed: Partial<Record<IntakePhase, boolean>>
}) {
  return (
    <nav aria-label="Model Intake phases" className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
      {INTAKE_PHASES.map((item, index) => {
        const active = item.id === phase
        const done = Boolean(completed[item.id])
        return (
          <button
            key={item.id}
            type="button"
            aria-current={active ? 'step' : undefined}
            onClick={() => onPhaseChange(item.id)}
            className={`flex min-w-0 items-start gap-2 rounded-lg border p-3 text-left transition ${
              active ? 'border-cyan-500 bg-cyan-950/40' : 'border-gray-800 bg-gray-950 hover:border-gray-700'
            }`}
          >
            {done ? (
              <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-green-300" />
            ) : (
              <Circle className={`mt-0.5 h-4 w-4 shrink-0 ${active ? 'text-cyan-300' : 'text-gray-600'}`} />
            )}
            <span className="min-w-0">
              <span className="block text-sm font-medium text-white">
                {item.id === 'status' ? item.label : `${index + 1}. ${item.label}`}
              </span>
              <span className="mt-0.5 block break-words text-xs text-gray-500">{item.helper}</span>
            </span>
          </button>
        )
      })}
    </nav>
  )
}

export function RunnerInstallCard({
  readiness,
  plan,
  onRecheck,
  storage,
  cleanupBusy,
  onCleanup,
}: {
  readiness: ModelIntakeRunnerReadiness | null
  plan: ModelIntakeRunnerInstallPlan | null
  onRecheck: () => void
  storage: ModelIntakeRunnerStorage | null
  cleanupBusy: boolean
  onCleanup: (dryRun: boolean) => void
}) {
  const [open, setOpen] = useState(false)
  const [signer, setSigner] = useState('local-pem')
  const [kmsKeyId, setKmsKeyId] = useState('')
  const [copied, setCopied] = useState(false)
  const installed = readiness?.ready === true
  const signerArgument = signer.startsWith('kms:') ? `kms:${kmsKeyId.trim() || '<key-id>'}` : signer
  const command = (plan?.command || '').replace('<choice>', signerArgument)
  const commandReady = !signer.startsWith('kms:') || Boolean(kmsKeyId.trim())
  const formatBytes = (value: number | undefined) => {
    if (!Number.isFinite(value)) return '—'
    const bytes = Number(value)
    if (bytes >= 1024 ** 4) return `${(bytes / 1024 ** 4).toFixed(1)} TiB`
    if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(1)} GiB`
    if (bytes >= 1024 ** 2) return `${(bytes / 1024 ** 2).toFixed(1)} MiB`
    return `${bytes} B`
  }

  async function copyCommand() {
    try {
      await navigator.clipboard.writeText(command)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      setCopied(false)
    }
  }

  return (
    <div className="min-w-0 rounded-lg border border-gray-800 bg-gray-950 p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-white">
            <Server className="h-4 w-4 text-cyan-300" />
            <h3 className="text-sm font-semibold">microVM runner (Firecracker)</h3>
          </div>
          <p className="mt-1 max-w-3xl text-xs text-gray-500">
            Runs the exact model in a disposable no-egress microVM. Not installed by default: it
            needs root, changes the host, and downloads a multi-gigabyte guest image.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className={`rounded px-2 py-1 text-xs font-semibold ${
            installed ? 'bg-green-950/50 text-green-300'
              : readiness?.supported_host === false ? 'bg-gray-800 text-gray-400'
                : 'bg-yellow-950/50 text-yellow-200'
          }`}>
            {installed ? 'READY' : readiness?.supported_host === false ? 'unavailable on this host' : 'not installed'}
          </span>
          <button type="button" onClick={onRecheck} className="rounded border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-800">
            Re-check
          </button>
        </div>
      </div>

      <div className="mt-3 rounded border border-gray-800 bg-gray-900/70 p-3 text-xs text-gray-400">
        <div className="font-medium text-gray-300">Linux host requirements</div>
        <ul className="mt-1 list-disc space-y-1 pl-4">
          <li>x86_64 Linux with KVM available at <code>/dev/kvm</code></li>
          <li>CPU virtualization exposed to the host; cloud VMs usually require nested virtualization</li>
          <li>cgroup v2, systemd, nftables, root for the one-time host installation, and several GB of disk</li>
          <li>
            Python 3 with the venv module (for example <code>python3.12-venv</code> on Ubuntu 24.04)
          </li>
        </ul>
        <p className="mt-2 text-[11px] text-gray-500">
          ShakerScan never installs this privileged tier silently. One host command downloads,
          verifies, installs, connects, and checks the runner.
        </p>
      </div>

      {storage?.available && storage.filesystem && (
        <div className="mt-3 rounded border border-gray-800 bg-gray-900/70 p-3">
          <div className="flex flex-wrap items-start justify-between gap-2">
            <div>
              <div className="text-xs font-medium text-gray-200">Runner storage</div>
              <p className="mt-1 text-[11px] text-gray-500">
                Every job is checked before large disk images are created. A conversion can need several
                times the model size while it runs; jobs are rejected if that would cross the safety reserve.
              </p>
            </div>
            <span className={`rounded px-2 py-1 text-xs font-semibold ${storage.active_job ? 'bg-cyan-950/50 text-cyan-200' : 'bg-gray-800 text-gray-300'}`}>
              {storage.active_job ? 'job active' : 'idle'}
            </span>
          </div>
          <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
            <div className="rounded border border-gray-800 bg-gray-950 p-2"><div className="text-[10px] uppercase text-gray-600">Free now</div><div className="mt-1 text-sm font-semibold text-white">{formatBytes(storage.filesystem.free_bytes)}</div></div>
            <div className="rounded border border-gray-800 bg-gray-950 p-2"><div className="text-[10px] uppercase text-gray-600">Safety reserve</div><div className="mt-1 text-sm font-semibold text-white">{formatBytes(storage.filesystem.reserve_bytes)}</div></div>
            <div className="rounded border border-gray-800 bg-gray-950 p-2"><div className="text-[10px] uppercase text-gray-600">Runner scratch</div><div className="mt-1 text-sm font-semibold text-white">{formatBytes(storage.usage?.scratch_bytes)}</div></div>
            <div className="rounded border border-gray-800 bg-gray-950 p-2"><div className="text-[10px] uppercase text-gray-600">Converted models retained</div><div className="mt-1 text-sm font-semibold text-white">{formatBytes(storage.usage?.converted_models_bytes)}</div></div>
          </div>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <button type="button" disabled={cleanupBusy} onClick={() => onCleanup(true)} className="rounded border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-800 disabled:opacity-50">Preview cleanup</button>
            <button type="button" disabled={cleanupBusy || storage.active_job} onClick={() => onCleanup(false)} className="rounded bg-cyan-800 px-3 py-1.5 text-xs font-medium text-white hover:bg-cyan-700 disabled:opacity-50">Clean inactive scratch</button>
            <span className="text-[11px] text-gray-500">
              {formatBytes(storage.reclaimable?.bytes)} safely reclaimable now · automatic cleanup {storage.automatic_cleanup?.enabled ? 'on' : 'off'}
            </span>
          </div>
          <p className="mt-2 text-[11px] text-gray-600">
            Automatic cleanup removes inactive scratch after {storage.automatic_cleanup?.scratch_retention_hours ?? 24} hours and expired job metadata after {storage.automatic_cleanup?.job_retention_days ?? 30} days. Acquired and converted models are never auto-deleted because admissions may still reference them.
          </p>
          <p className="mt-1 text-[11px] text-gray-600">
            Configured limits: {formatBytes(storage.limits?.max_input_bytes)} model input · {formatBytes(storage.limits?.max_output_bytes)} guest output. A 100 GiB conversion can require close to 900 GiB free with the current copy-isolated layout.
          </p>
        </div>
      )}

      {plan && (
        plan.supported ? (
          <div className="mt-3">
            <button
              type="button"
              onClick={() => setOpen((value) => !value)}
              className={`inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium text-white ${
                installed ? 'border border-gray-700 bg-gray-800 hover:bg-gray-700' : 'bg-cyan-700 hover:bg-cyan-600'
              }`}
            >
              <Server className="h-4 w-4" />{
                open
                  ? 'Hide installation details'
                  : installed
                    ? 'Installation, recovery, and upgrade details'
                    : 'Set up microVM runner'
              }
            </button>
            {open && (
              <div className="mt-3 grid gap-3 rounded border border-gray-800 bg-gray-900 p-3">
                <p className="text-xs text-gray-400">
                  {installed
                    ? 'This runner is installed. The same reviewed procedure installs it on another compatible host or refreshes its pinned components here.'
                    : 'Open a terminal on the computer running ShakerScan, copy the one command below, and run it. The command enters the correct ShakerScan folder for you.'}
                </p>
                <div>
                  <div className="text-xs font-medium text-gray-300">Receipt signer</div>
                  <div className="mt-2 grid gap-2 sm:grid-cols-2">
                    {plan.signer_choices.map((choice) => (
                      <button
                        key={choice.value}
                        type="button"
                        onClick={() => setSigner(choice.value)}
                        className={`min-w-0 rounded border p-2 text-left ${
                          signer === choice.value ? 'border-cyan-500 bg-cyan-950/40' : 'border-gray-800 bg-gray-950 hover:border-gray-700'
                        }`}
                      >
                        <div className="text-xs font-medium text-white">
                          {choice.label}{choice.production ? '' : ' (non-production)'}
                        </div>
                        <div className="mt-1 break-words text-[11px] text-gray-500">{choice.detail}</div>
                      </button>
                    ))}
                  </div>
                  {signer.startsWith('kms:') && (
                    <label className="mt-3 grid gap-1 text-xs text-gray-300">
                      AWS KMS signing key ID or ARN
                      <input
                        value={kmsKeyId}
                        onChange={(event) => setKmsKeyId(event.target.value)}
                        className="w-full rounded border border-gray-700 bg-gray-950 px-3 py-2 font-mono text-xs text-white focus:border-cyan-500 focus:outline-none"
                        placeholder="arn:aws:kms:region:account:key/…"
                      />
                      <span className="text-[11px] text-gray-500">
                        Production receipts require KMS. The installer exports and registers its public key automatically.
                      </span>
                    </label>
                  )}
                </div>
                <div className="text-xs font-medium text-gray-300">Run this one command</div>
                <div className="flex min-w-0 items-center gap-2 rounded border border-gray-800 bg-black/40 p-2">
                  <code className="min-w-0 flex-1 break-all font-mono text-[11px] text-cyan-200">{command}</code>
                  <button type="button" onClick={copyCommand} disabled={!commandReady} className="shrink-0 rounded border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-800 disabled:cursor-not-allowed disabled:opacity-40">
                    <Copy className="h-3 w-3" /> {copied ? 'Copied' : 'Copy'}
                  </button>
                </div>
                <p className="text-[11px] text-gray-500">
                  Runtime: <code className="text-gray-300">{plan.runtime_dir || '~/.shakerscan'}</code>
                  {plan.install_kind === 'source_checkout'
                    ? ' (local source checkout)'
                    : ' (curl installation)'}
                </p>
                <p className="text-[11px] text-gray-500">
                  {plan.install_kind === 'source_checkout'
                    ? 'The command enters this source checkout automatically.'
                    : 'Curl installations live in ~/.shakerscan; the command enters that folder automatically.'}
                </p>
                <div className="text-xs text-gray-500">
                  <div className="font-medium text-gray-400">It will:</div>
                  <ul className="mt-1 list-disc pl-4">
                    {plan.host_mutations.map((item) => <li key={item}>{item}</li>)}
                  </ul>
                  <p className="mt-2">{plan.cost}</p>
                </div>
                <p className="text-xs text-gray-500">
                  This one host command verifies the staged kernel and rootfs, installs or refreshes the
                  service, restarts the API, and registers the purpose-scoped runner trust anchor. It builds
                  or downloads anything it still needs. When it
                  finishes, choose <span className="text-gray-300">Re-check</span> above.
                </p>
              </div>
            )}
          </div>
        ) : (
          <div className="mt-3 rounded border border-gray-800 bg-gray-900 p-3 text-xs text-gray-400">
            {plan.reason} Every other Model Intake check is unaffected.
          </div>
        )
      )}
    </div>
  )
}

export function PreflightScanTracker({
  scans,
  onUseInAdmission,
  onRefresh,
}: {
  scans: ModelIntakeScanSummary[]
  onUseInAdmission: (scanId: string) => void
  onRefresh: () => void
}) {
  if (scans.length === 0) return null
  return (
    <div className="min-w-0 rounded-lg border border-gray-800 bg-gray-950 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="text-sm font-medium text-gray-200">Preflight scans queued from this page</div>
        <button type="button" onClick={onRefresh} className="rounded border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-800">
          Refresh
        </button>
      </div>
      <div className="mt-3 grid gap-2">
        {scans.map((scan) => {
          const terminal = isTerminalScanStatus(scan.status)
          const attachable = scan.status === 'completed' && scan.complete_artifact
          return (
            <div key={scan.id} className="grid min-w-0 gap-2 rounded border border-gray-800 bg-gray-900 p-3 sm:grid-cols-[minmax(0,1fr)_auto]">
              <div className="min-w-0">
                <div className="truncate font-mono text-xs text-gray-300">{scan.id}</div>
                <div className="mt-1 text-xs text-gray-500">
                  {terminal
                    ? new Date(scan.created_at).toLocaleString()
                    : `${scan.current_phase || 'running'} · ${scan.progress ?? 0}%`}
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <span
                  className={`rounded px-2 py-1 text-xs font-semibold ${
                    scan.status === 'completed'
                      ? 'bg-green-950/50 text-green-300'
                      : terminal
                        ? 'bg-red-950/50 text-red-300'
                        : 'bg-yellow-950/50 text-yellow-200'
                  }`}
                >
                  {scan.status}
                </span>
                <a
                  href={`/scans/${scan.id}`}
                  className="rounded border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-800"
                >
                  Report
                </a>
                {scan.status === 'completed' && (
                  <>
                    <button
                      type="button"
                      onClick={() => { void downloadModelIntakeSbom(scan.id) }}
                      title="Download the CycloneDX bill of materials for this scan"
                      className="rounded border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-800"
                    >
                      SBOM
                    </button>
                    <button
                      type="button"
                      onClick={() => { void downloadModelIntakeLicenseArtifact(scan.id, 'license-bom') }}
                      title="Download reconciled model and dependency license evidence"
                      className="rounded border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-800"
                    >
                      License BOM
                    </button>
                    <button
                      type="button"
                      onClick={() => { void downloadModelIntakeLicenseArtifact(scan.id, 'third-party-notices') }}
                      title="Download the draft third-party notices file"
                      className="rounded border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-800"
                    >
                      Notices draft
                    </button>
                  </>
                )}
                <button
                  type="button"
                  disabled={!attachable}
                  title={!attachable && scan.status === 'completed' ? 'A complete artifact download is required for admission' : undefined}
                  onClick={() => onUseInAdmission(scan.id)}
                  className="inline-flex items-center gap-1.5 rounded border border-cyan-700 bg-cyan-950/40 px-2 py-1 text-xs text-cyan-100 hover:bg-cyan-900/40 disabled:cursor-not-allowed disabled:border-gray-700 disabled:bg-transparent disabled:text-gray-600"
                >
                  <LockKeyhole className="h-3 w-3" /> Use in admission
                </button>
              </div>
            </div>
          )
        })}
      </div>
      <div className="mt-3 flex gap-2 text-xs text-gray-500">
        <ShieldAlert className="h-3.5 w-3.5 shrink-0" />
        <span>
          A preflight scan is technical evidence only. Binding one to a controlled submission is what
          makes it reviewable for deployment authority.
        </span>
      </div>
    </div>
  )
}
