'use client'

import { Suspense, useCallback, useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'next/navigation'
import Link from '@/components/WorkspaceLink'
import { Card } from '@/components/ui'
import { getAITargets, getScan, type AITarget, type Scan } from '@/lib/api'
import { getHuntV2, type HuntV2 } from '@/lib/huntV2'
import {
  compileBoundaryCandidate, evaluateBoundaryRegression, exportBoundaryRegression,
  inspectBoundaryCandidate, materializeBoundaryProposal, queueBoundaryVerification,
  type BoundaryContext, type BoundaryHandoff, type BoundaryMaterialization,
  type BoundaryPrincipal, type BoundaryProposal, type BoundaryRegressionArtifact,
  type BoundaryRegressionEvaluation,
} from '@/lib/aiBoundary'
import { boundaryBaseFromTarget, boundaryCandidateIds, boundaryScanMessage, savedArtifactMatchesSource } from '@/lib/aiBoundaryPresentation'

type Environment = 'preview' | 'staging' | 'development'
type Profile = 'smoke' | 'trace' | 'standard' | 'deep'
type PrincipalKey = keyof BoundaryPrincipal

const inputStyle = 'w-full rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none'
const buttonStyle = 'rounded-lg border border-blue-500/50 bg-blue-500/15 px-3 py-2 text-sm font-medium text-blue-100 hover:bg-blue-500/25 disabled:cursor-not-allowed disabled:opacity-40'
const emptyPrincipal = (): BoundaryPrincipal => ({ role: '', subject: '', tenant: '', resource_id: '' })
const principalFields: Array<{ key: PrincipalKey; label: string }> = [
  { key: 'role', label: 'Role' }, { key: 'subject', label: 'Subject' },
  { key: 'tenant', label: 'Tenant' }, { key: 'resource_id', label: 'Controlled resource ID' },
]

function parseObject(label: string, value: string): Record<string, unknown> {
  const parsed: unknown = JSON.parse(value)
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error(`${label} must be a JSON object`)
  return parsed as Record<string, unknown>
}

function artifactFromText(text: string): BoundaryRegressionArtifact {
  const parsed = parseObject('Regression artifact', text)
  if (parsed.schema_version !== 'ai-boundary-regression/v1'
      || typeof parsed.ai_target_id !== 'string'
      || typeof parsed.source_scan_id !== 'string'
      || typeof parsed.artifact_sha256 !== 'string'
      || !parsed.verify_request || typeof parsed.verify_request !== 'object'
      || Array.isArray(parsed.verify_request)) {
    throw new Error('Select a versioned AI Boundary regression artifact')
  }
  return parsed as unknown as BoundaryRegressionArtifact
}

function BoundaryWorkflow() {
  const params = useSearchParams()
  const [targets, setTargets] = useState<AITarget[]>([])
  const [targetId, setTargetId] = useState('')
  const [huntId, setHuntId] = useState(params.get('hunt') || '')
  const [candidateId, setCandidateId] = useState(params.get('candidate') || '')
  const [hunt, setHunt] = useState<HuntV2 | null>(null)
  const [context, setContext] = useState<BoundaryContext | null>(null)
  const [owner, setOwner] = useState<BoundaryPrincipal>(emptyPrincipal)
  const [attacker, setAttacker] = useState<BoundaryPrincipal>(emptyPrincipal)
  const [expectedRule, setExpectedRule] = useState('')
  const [baseText, setBaseText] = useState('')
  const [handoff, setHandoff] = useState<BoundaryHandoff | null>(null)
  const [importedProposal, setImportedProposal] = useState<BoundaryProposal | null>(null)
  const [materialized, setMaterialized] = useState<BoundaryMaterialization | null>(null)
  const [environment, setEnvironment] = useState<Environment>('preview')
  const [profile, setProfile] = useState<Profile>('standard')
  const [sourceScanId, setSourceScanId] = useState('')
  const [sourceScan, setSourceScan] = useState<Scan | null>(null)
  const [artifact, setArtifact] = useState<BoundaryRegressionArtifact | null>(null)
  const [artifactText, setArtifactText] = useState('')
  const [laterScanId, setLaterScanId] = useState('')
  const [laterScan, setLaterScan] = useState<Scan | null>(null)
  const [evaluation, setEvaluation] = useState<BoundaryRegressionEvaluation | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    async function loadTargets() {
      try {
        const first = await getAITargets({ limit: 500 })
        const rows = [...first.targets]
        for (let offset = rows.length; offset < first.total; offset += 500) {
          const page = await getAITargets({ limit: 500, offset })
          rows.push(...page.targets)
          if (page.targets.length === 0) break
        }
        if (!cancelled) setTargets(rows)
      } catch (cause) {
        if (!cancelled) setError(cause instanceof Error ? cause.message : 'Failed to load AI targets')
      }
    }
    loadTargets()
    return () => { cancelled = true }
  }, [])

  const target = targets.find((item) => item.id === targetId)
  const candidateIds = useMemo(() => hunt ? boundaryCandidateIds(hunt) : [], [hunt])
  const proposal = handoff?.proposal || importedProposal
  const principalsReady = [owner, attacker].every((principal) =>
    principalFields.every(({ key }) => principal[key].trim().length > 0))

  const run = useCallback(async (task: () => Promise<void>) => {
    setBusy(true)
    setError(null)
    setNotice(null)
    try { await task() } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The boundary workflow could not continue')
    } finally { setBusy(false) }
  }, [])

  function invalidateProposal() {
    setHandoff(null)
    setImportedProposal(null)
    setMaterialized(null)
    setArtifact(null)
    setEvaluation(null)
  }

  function editPrincipal(slot: 'owner' | 'attacker', key: PrincipalKey, value: string) {
    const setter = slot === 'owner' ? setOwner : setAttacker
    setter((current) => ({ ...current, [key]: value }))
    invalidateProposal()
  }

  function useTargetFixture() {
    if (!target) return
    const base = boundaryBaseFromTarget(target.metadata_json)
    if (!base) {
      setError('This AI target has no complete saved Boundary fixture. Enter its fixture base below.')
      return
    }
    setBaseText(JSON.stringify(base, null, 2))
    for (const slot of ['owner', 'attacker'] as const) {
      const value = base[slot]
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        const saved = value as Record<string, unknown>
        const principal = Object.fromEntries(principalFields.map(({ key }) => [key, String(saved[key] || '')])) as unknown as BoundaryPrincipal
        if (slot === 'owner') setOwner(principal)
        else setAttacker(principal)
      }
    }
    invalidateProposal()
    setError(null)
  }

  async function loadHunt() {
    await run(async () => {
      const loaded = await getHuntV2(huntId.trim())
      setHunt(loaded)
      setContext(null)
      invalidateProposal()
      setNotice(`${boundaryCandidateIds(loaded).length} candidate ID(s) recorded by this Hunt.`)
    })
  }

  async function inspect() {
    await run(async () => {
      const inspected = await inspectBoundaryCandidate(huntId.trim(), candidateId.trim())
      setContext(inspected)
      invalidateProposal()
    })
  }

  async function compile() {
    await run(async () => {
      const compiled = await compileBoundaryCandidate(huntId.trim(), candidateId.trim(), {
        owner, attacker, ...(expectedRule.trim() ? { expected_rule: expectedRule.trim() } : {}),
      })
      setContext(compiled.candidate_context)
      setHandoff(compiled)
      setImportedProposal(null)
      setMaterialized(null)
      setArtifact(null)
    })
  }

  async function materialize() {
    if (!proposal) return
    await run(async () => setMaterialized(await materializeBoundaryProposal(proposal, parseObject('Boundary fixture base', baseText))))
  }

  async function verify() {
    if (!proposal || !materialized || !targetId || !target || target.production_mode) return
    await run(async () => {
      const queued = await queueBoundaryVerification(targetId, proposal, parseObject('Boundary fixture base', baseText), environment, profile)
      setSourceScanId(queued.scan_id)
      setSourceScan(null)
      setNotice(`Verification queued as Scan ${queued.scan_id}.`)
    })
  }

  async function refreshScan(scanId: string, later: boolean) {
    await run(async () => {
      const loaded = await getScan(scanId.trim())
      if (later) setLaterScan(loaded)
      else setSourceScan(loaded)
      setNotice(boundaryScanMessage(loaded.status))
    })
  }

  async function exportArtifact() {
    if (!proposal || !targetId) return
    await run(async () => {
      const exported = await exportBoundaryRegression(
        targetId, sourceScanId.trim(), proposal, parseObject('Boundary fixture base', baseText),
      )
      setArtifact(exported)
      setArtifactText(JSON.stringify(exported, null, 2))
      setNotice('Regression artifact exported with its legitimate controls and source proof.')
    })
  }

  function downloadArtifact() {
    if (!artifact) return
    const url = URL.createObjectURL(new Blob([JSON.stringify(artifact, null, 2)], { type: 'application/json' }))
    const link = document.createElement('a')
    link.href = url
    link.download = `ai-boundary-regression-${artifact.source_scan_id}.json`
    document.body.appendChild(link)
    link.click()
    link.remove()
    window.setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  async function loadArtifact() {
    await run(async () => {
      const supplied = artifactFromText(artifactText)
      const request = supplied.verify_request
      const loaded = await exportBoundaryRegression(
        supplied.ai_target_id, supplied.source_scan_id,
        request.proposal, request.boundary_base,
      )
      if (!savedArtifactMatchesSource(supplied, loaded)) {
        throw new Error('Saved artifact differs from its source Scan and fixture')
      }
      setArtifact(loaded)
      setTargetId(loaded.ai_target_id)
      setSourceScanId(loaded.source_scan_id)
      setSourceScan(null)
      setHandoff(null)
      setImportedProposal(loaded.verify_request.proposal)
      setBaseText(JSON.stringify(loaded.verify_request.boundary_base, null, 2))
      setEnvironment(loaded.verify_request.environment)
      setProfile(loaded.verify_request.scan_profile)
      setMaterialized(null)
      setEvaluation(null)
      setNotice('Artifact matched its source Scan. Review the target before queueing a rerun.')
    })
  }

  async function queueRegression() {
    if (!artifact || !target?.is_active || target.production_mode || target.id !== artifact.ai_target_id) return
    await run(async () => {
      const request = artifact.verify_request
      const queued = await queueBoundaryVerification(
        artifact.ai_target_id, request.proposal, request.boundary_base,
        request.environment, request.scan_profile,
      )
      setLaterScanId(queued.scan_id)
      setLaterScan(null)
      setEvaluation(null)
      setNotice(`Regression verification queued as Scan ${queued.scan_id}.`)
    })
  }

  async function evaluate() {
    if (!artifact) return
    await run(async () => setEvaluation(await evaluateBoundaryRegression(
      artifact.ai_target_id, artifact, laterScanId.trim(),
    )))
  }

  return (
    <div className="space-y-5 p-6 lg:p-8">
      <div>
        <Link href="/ai-gate" className="text-sm text-blue-300 hover:text-blue-200">← AI Gate</Link>
        <h1 className="mt-2 text-2xl font-bold text-white">Agent boundary verification</h1>
        <p className="mt-1 max-w-3xl text-sm text-gray-400">
          Review one Hunt candidate, supply two controlled principals and any missing business rule,
          then submit the existing deterministic AI Boundary verifier. Export a versioned regression
          after a completed scan and compare a later run against the same allowed workflows.
        </p>
      </div>
      {error && <div role="alert" className="rounded-lg border border-red-500/40 bg-red-950/40 p-3 text-sm text-red-200">{error}</div>}
      {notice && <div role="status" className="rounded-lg border border-blue-500/30 bg-blue-950/30 p-3 text-sm text-blue-100">{notice}</div>}

      <Card className="space-y-4 p-5">
        <h2 className="text-lg font-semibold text-white">1. Choose a Hunt candidate and AI target</h2>
        <div className="grid gap-3 xl:grid-cols-2">
          <label className="space-y-1 text-sm text-gray-300">Hunt ID
            <div className="flex gap-2"><input className={inputStyle} value={huntId} onChange={(event) => { setHuntId(event.target.value); setHunt(null); setContext(null); invalidateProposal() }} placeholder="Hunt UUID" />
              <button className={buttonStyle} disabled={busy || !huntId.trim()} onClick={loadHunt}>Load</button></div>
          </label>
          <label className="space-y-1 text-sm text-gray-300">Candidate ID
            <input className={inputStyle} list="boundary-candidates" value={candidateId} onChange={(event) => { setCandidateId(event.target.value); setContext(null); invalidateProposal() }} placeholder="Candidate UUID" />
            <datalist id="boundary-candidates">{candidateIds.map((id) => <option key={id} value={id} />)}</datalist>
          </label>
          <label className="space-y-1 text-sm text-gray-300">AI target
            <select className={inputStyle} value={targetId} onChange={(event) => { setTargetId(event.target.value); invalidateProposal() }}>
              <option value="">Select a configured AI target</option>
              {targets.filter((item) => item.is_active).map((item) => <option key={item.id} value={item.id} disabled={item.production_mode}>
                {item.name} · {item.target_type}{item.production_mode ? ' · production Boundary verification unavailable' : ''}
              </option>)}
            </select>
          </label>
          <div className="flex items-end gap-2">
            <button className={buttonStyle} disabled={busy || !huntId.trim() || !candidateId.trim()} onClick={inspect}>Inspect candidate</button>
            <button className={buttonStyle} disabled={busy || !target} onClick={useTargetFixture}>Use saved fixture</button>
          </div>
        </div>
        {hunt && target && <p className="rounded-lg border border-gray-800 bg-gray-950 p-3 text-xs text-gray-300">
          Hunt asset: {hunt.target_url || hunt.target_id} · AI test endpoint: {target.endpoint_url}.
          Review these bindings before queueing verification.
        </p>}
        {context && <div className="rounded-lg bg-gray-950 p-3 text-sm text-gray-300">
          <p>Candidate: {context.kind || 'unsupported family'} · {context.status} · {context.evidence.resolved.length} Hunt-local evidence reference(s)</p>
          {context.context.missing_fields.length > 0 && <p className="mt-1 text-amber-300">Missing candidate fields: {context.context.missing_fields.join(', ')}</p>}
          {context.context.issues.length > 0 && <p className="mt-1 text-amber-300">Context issues: {context.context.issues.join(', ')}</p>}
        </div>}
      </Card>

      <Card className="space-y-4 p-5">
        <h2 className="text-lg font-semibold text-white">2. Confirm principal and policy facts</h2>
        <p className="text-sm text-gray-400">These values are declarations for a proposed test. The verifier establishes the actual bindings and backend effect.</p>
        <div className="grid gap-4 xl:grid-cols-2">
          {(['owner', 'attacker'] as const).map((slot) => <div key={slot} className="space-y-3 rounded-lg border border-gray-800 p-3">
            <h3 className="font-medium capitalize text-gray-200">{slot} controlled principal</h3>
            {principalFields.map(({ key, label }) => <label key={key} className="block space-y-1 text-sm text-gray-300">{label}
              <input className={inputStyle} value={(slot === 'owner' ? owner : attacker)[key]} onChange={(event) => editPrincipal(slot, key, event.target.value)} />
            </label>)}
          </div>)}
        </div>
        <label className="block space-y-1 text-sm text-gray-300">Expected business rule, when required
          <textarea className={inputStyle} rows={2} value={expectedRule} onChange={(event) => { setExpectedRule(event.target.value); invalidateProposal() }} placeholder="State the operator-confirmed rule. Leave blank for a cross-tenant read hypothesis." />
        </label>
        <button className={buttonStyle} disabled={busy || !huntId.trim() || !candidateId.trim() || !principalsReady} onClick={compile}>Compile proposal</button>
        {handoff && <div className="rounded-lg bg-gray-950 p-3 text-sm text-gray-300">
          <p>Proposal: {handoff.status} {proposal ? `· ${proposal.kind}` : ''}</p>
          {handoff.missing_facts.length > 0 && <p className="mt-1 text-amber-300">Missing facts: {handoff.missing_facts.join(', ')}</p>}
          <p className="mt-1 text-xs text-gray-500">Compilation does not execute target traffic or verify a finding.</p>
        </div>}
      </Card>

      <Card className="space-y-4 p-5">
        <h2 className="text-lg font-semibold text-white">3. Verify the boundary</h2>
        <label className="block space-y-1 text-sm text-gray-300">Boundary fixture base · JSON, no credentials
          <textarea className={`${inputStyle} font-mono text-xs`} rows={11} value={baseText} onChange={(event) => { setBaseText(event.target.value); setMaterialized(null); setArtifact(null) }} placeholder="Use the saved target fixture or enter identity, resource, response, owner, and attacker bindings." />
        </label>
        <div className="flex flex-wrap items-end gap-3">
          <button className={buttonStyle} disabled={busy || proposal?.status !== 'ready' || !baseText.trim()} onClick={materialize}>Validate fixture</button>
          <label className="space-y-1 text-sm text-gray-300">Environment
            <select className={inputStyle} value={environment} onChange={(event) => setEnvironment(event.target.value as Environment)}>
              <option value="preview">Preview</option><option value="staging">Staging</option><option value="development">Development</option>
            </select>
          </label>
          <label className="space-y-1 text-sm text-gray-300">Scan profile
            <select className={inputStyle} value={profile} onChange={(event) => setProfile(event.target.value as Profile)}>
              <option value="smoke">Smoke</option><option value="trace">Trace</option><option value="standard">Standard</option><option value="deep">Deep</option>
            </select>
          </label>
          <button className={buttonStyle} disabled={busy || !materialized || !targetId || !target || target.production_mode || proposal?.status !== 'ready'} onClick={verify}>Queue verification</button>
        </div>
        {materialized && <p className="break-all text-xs text-emerald-300">Deterministic contract: {materialized.boundary_contract_sha256}</p>}
        <p className="text-xs text-gray-500">Queueing uses the AI target&apos;s current authorization, selected credentials, scope, and budget checks. No request is sent until you choose Queue verification.</p>
        <div className="grid gap-2 sm:grid-cols-[1fr_auto]">
          <label className="space-y-1 text-sm text-gray-300">Source Scan ID
            <input className={inputStyle} value={sourceScanId} onChange={(event) => { setSourceScanId(event.target.value); setSourceScan(null) }} placeholder="Queued scan or existing completed AI Boundary scan" />
          </label>
          <button className={`${buttonStyle} self-end`} disabled={busy || !sourceScanId.trim()} onClick={() => refreshScan(sourceScanId, false)}>Refresh status</button>
        </div>
        {sourceScan && <p className="text-sm text-gray-300">Source: <Link className="text-blue-300" href={`/scans/${sourceScan.id}`}>{sourceScan.id}</Link> · {sourceScan.status}. {boundaryScanMessage(sourceScan.status)}</p>}
      </Card>

      <Card className="space-y-4 p-5">
        <h2 className="text-lg font-semibold text-white">4. Save and rerun the regression</h2>
        <div className="flex flex-wrap gap-2">
          <button className={buttonStyle} disabled={busy || !sourceScanId.trim() || sourceScan?.status !== 'completed' || !proposal || !baseText.trim() || !targetId} onClick={exportArtifact}>Export completed scan</button>
          <button className={buttonStyle} disabled={!artifact} onClick={downloadArtifact}>Download artifact</button>
        </div>
        <label className="block space-y-1 text-sm text-gray-300">Regression artifact · paste a previously saved artifact here to continue later
          <textarea className={`${inputStyle} font-mono text-xs`} rows={6} value={artifactText} onChange={(event) => { setArtifactText(event.target.value); setArtifact(null); setEvaluation(null) }} placeholder="Versioned artifact JSON" />
        </label>
        <button className={buttonStyle} disabled={busy || !artifactText.trim()} onClick={loadArtifact}>Load saved artifact</button>
        {artifact && <div className="rounded-lg bg-gray-950 p-3 text-xs text-gray-300">
          <p className="break-all">Artifact: {artifact.artifact_sha256}</p>
          <p className="mt-1 break-all">Rerun target: {target?.name || artifact.ai_target_id} · {target?.endpoint_url || 'target unavailable'}</p>
          <p className="mt-1">Required allowed controls: {artifact.acceptance.required_legitimate_controls.join(', ')}</p>
        </div>}
        <div className="flex flex-wrap items-end gap-2">
          <button className={buttonStyle} disabled={busy || !artifact || !target?.is_active || target.production_mode || target.id !== artifact.ai_target_id} onClick={queueRegression}>Queue regression run</button>
          <label className="min-w-64 flex-1 space-y-1 text-sm text-gray-300">Later Scan ID
            <input className={inputStyle} value={laterScanId} onChange={(event) => { setLaterScanId(event.target.value); setLaterScan(null); setEvaluation(null) }} placeholder="Later completed scan" />
          </label>
          <button className={buttonStyle} disabled={busy || !laterScanId.trim()} onClick={() => refreshScan(laterScanId, true)}>Refresh status</button>
          <button className={buttonStyle} disabled={busy || !artifact || laterScan?.status !== 'completed'} onClick={evaluate}>Evaluate</button>
        </div>
        {laterScan && <p className="text-sm text-gray-300">Later run: <Link className="text-blue-300" href={`/scans/${laterScan.id}`}>{laterScan.id}</Link> · {laterScan.status}. {boundaryScanMessage(laterScan.status)}</p>}
        {evaluation && <div role="status" className={`rounded-lg border p-3 text-sm ${evaluation.status === 'pass' ? 'border-emerald-500/40 text-emerald-200' : 'border-amber-500/40 text-amber-200'}`}>
          <strong>Regression {evaluation.status}</strong>
          {evaluation.reasons.length > 0 && <span> · {evaluation.reasons.join(', ')}</span>}
          {evaluation.missing_legitimate_controls.length > 0 && <p className="mt-1">Allowed workflow gaps: {evaluation.missing_legitimate_controls.join(', ')}</p>}
        </div>}
        <p className="text-xs text-gray-500">The artifact carries fixture and proposal data. Store it with the care appropriate for those values. It never includes an approval receipt or grants execution authority.</p>
      </Card>
    </div>
  )
}

export default function BoundaryPage() {
  return <Suspense fallback={<div className="p-6 text-sm text-gray-300">Loading boundary workflow…</div>}><BoundaryWorkflow /></Suspense>
}
