'use client'

import { useCallback, useEffect, useMemo, useRef, useState, Fragment, Suspense } from 'react'
import Link from 'next/link'
import { getEvidenceInstance, getEvidenceInstances, getFindingEvidence, formatDate, type EvidenceInstance, type EvidenceObject } from '@/lib/api'
import { useUrlFilters } from '@/lib/useUrlFilters'
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorState,
  Input,
  LastUpdated,
  ProofStateBadge,
  RetentionClassBadge,
  SectionCard,
  Spinner,
  TableSkeleton,
} from '@/components/ui'
import EvidenceRetentionPanel from '@/components/EvidenceRetentionPanel'
import EvidenceObjectModal from '@/components/EvidenceObjectModal'

interface EvidenceFilters {
  [key: string]: string | number | undefined
  finding_id?: string
  tool_receipt_id?: string
}

const FAMILY_LABELS: Record<string, string> = {
  auth_bypass: 'Auth bypass', mass_assignment: 'Mass assignment', bola: 'BOLA', idor: 'IDOR',
  access_control: 'Access control', data_exposure: 'Data exposure', bfla: 'Function authz',
  injection: 'Injection', workflow: 'Workflow integrity', sqli: 'SQL injection', xss: 'XSS',
}
const SOURCE_LABELS: Record<string, string> = {
  research_principal_workflow: 'Principal workflow',
  family_proof_handoff: 'Family proof',
  research_http_experiment: 'HTTP experiment',
}
const PROOF_FILTERS = ['all', 'verified', 'suspected', 'inconclusive', 'refuted', 'unverified'] as const
type ProofFilter = (typeof PROOF_FILTERS)[number]
const PROOF_FILTER_LABELS: Record<ProofFilter, string> = {
  all: 'All', verified: 'Proven', suspected: 'Suspected', inconclusive: 'Inconclusive',
  refuted: 'Refuted', unverified: 'Unverified',
}

function humanFamily(f?: string | null): string { return f ? FAMILY_LABELS[f] || f.replace(/_/g, ' ') : '' }
function humanSource(s?: string | null): string { return s ? SOURCE_LABELS[s] || s.replace(/_/g, ' ') : '' }
function hostOf(url?: string | null): string { if (!url) return ''; try { return new URL(url).host } catch { return url } }
function asObject(v: unknown): Record<string, unknown> { return v && typeof v === 'object' ? (v as Record<string, unknown>) : {} }
function text(v: unknown): string { return typeof v === 'string' ? v : '' }
function formatBytes(n?: number): string {
  if (typeof n !== 'number' || n <= 0) return '—'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}

function proofObs(inst: EvidenceInstance) { return asObject(inst.proof_observation) }
function familyProof(inst: EvidenceInstance) { return asObject(proofObs(inst).family_proof) }
function evidenceFamily(inst: EvidenceInstance): string {
  return humanFamily(text(familyProof(inst).family)) || humanSource(inst.created_by) || 'Evidence'
}
function evidenceObjective(inst: EvidenceInstance): string { return text(proofObs(inst).objective) }
function evidenceCwe(inst: EvidenceInstance): string { return text(familyProof(inst).cwe) }

function EvidenceContent() {
  const { filters, setFilter } = useUrlFilters<EvidenceFilters>()

  const [instances, setInstances] = useState<EvidenceInstance[]>([])
  const [findingObjects, setFindingObjects] = useState<EvidenceObject[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(false)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)
  const [modalObjectId, setModalObjectId] = useState<string | null>(null)
  const [findingInput, setFindingInput] = useState<string>(filters.finding_id || '')
  const [proofFilter, setProofFilter] = useState<ProofFilter>('verified')
  const [search, setSearch] = useState('')
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [expandedInstance, setExpandedInstance] = useState<EvidenceInstance | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [detailError, setDetailError] = useState(false)
  const detailRequestId = useRef(0)

  const findingFilter = (filters.finding_id || '').trim()
  const toolReceiptFilter = (filters.tool_receipt_id || '').trim()

  const load = useCallback(async () => {
    try {
      const [instRes, objRes] = await Promise.all([
        // /evidence/instances only accepts UUID finding_ids (it 400s on fingerprint
        // ids like "t:abc…"), and instances never carry a finding_id anyway. In finding
        // mode we show objects (below), so skip the instances call; its own catch keeps
        // a browse-mode failure from discarding everything.
        findingFilter
          ? Promise.resolve({ evidence_instances: [] as EvidenceInstance[] })
          : getEvidenceInstances({
              tool_receipt_id: toolReceiptFilter || undefined,
              limit: 200,
              summary_only: true,
            }).catch(() => ({ evidence_instances: [] as EvidenceInstance[] })),
        // A finding's durable proof is stored as evidence OBJECTS, not instances,
        // so a finding deep-link must load objects or it looks empty. See getFindingEvidence.
        findingFilter
          ? getFindingEvidence(findingFilter).catch(() => ({ evidence_objects: [] as EvidenceObject[] }))
          : Promise.resolve({ evidence_objects: [] as EvidenceObject[] }),
      ])
      setInstances(instRes.evidence_instances || [])
      setFindingObjects(objRes.evidence_objects || [])
      setLoadError(false)
      setLastUpdated(new Date())
    } catch {
      setLoadError(true)
    } finally {
      setLoading(false)
    }
  }, [findingFilter, toolReceiptFilter])

  useEffect(() => {
    setLoading(true)
    load()
  }, [load])

  const visible = useMemo(() => {
    const q = search.trim().toLowerCase()
    return instances.filter((inst) => {
      if (proofFilter !== 'all' && (inst.proof_state || 'unverified') !== proofFilter) return false
      if (!q) return true
      const hay = [evidenceFamily(inst), evidenceObjective(inst), evidenceCwe(inst), inst.concrete_url, inst.id, humanSource(inst.created_by)]
        .filter(Boolean).join(' ').toLowerCase()
      return hay.includes(q)
    })
  }, [instances, proofFilter, search])

  const proofCounts = useMemo(() => {
    const c: Record<string, number> = {}
    for (const inst of instances) { const k = inst.proof_state || 'unverified'; c[k] = (c[k] || 0) + 1 }
    return c
  }, [instances])

  const countLabel = visible.length === instances.length ? `${instances.length}` : `${visible.length} of ${instances.length}`

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white">Evidence</h1>
          <p className="mt-1 text-gray-400">
            The durable proof captured for findings and autonomous tests — what was checked, on which target, and whether it held up.
          </p>
        </div>
        <LastUpdated updatedAt={lastUpdated} onRefresh={load} />
      </div>

      {findingFilter && (
        <div className="flex flex-wrap items-center gap-2 rounded-lg border border-blue-500/20 bg-blue-500/[0.06] px-4 py-2 text-sm text-blue-100">
          <span>Showing evidence for finding <span className="font-mono text-xs">{findingFilter.slice(0, 12)}…</span></span>
          <button type="button" onClick={() => { setFindingInput(''); setFilter('finding_id', undefined) }} className="rounded border border-blue-400/30 px-2 py-0.5 text-xs hover:bg-blue-500/10">Clear</button>
        </div>
      )}

      {/* Browse controls only apply to the autonomous-test instance list, not a single finding's objects. */}
      {!findingFilter && (
        <Card className="p-4">
          <div className="flex flex-col gap-3">
            <div className="flex flex-wrap items-center gap-2">
              {PROOF_FILTERS.map((pf) => {
                const count = pf === 'all' ? instances.length : proofCounts[pf] || 0
                const active = proofFilter === pf
                return (
                  <button
                    key={pf}
                    type="button"
                    aria-pressed={active}
                    onClick={() => setProofFilter(pf)}
                    className={`rounded-lg border px-3 py-1.5 text-sm transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                      active
                        ? 'border-blue-500/50 bg-blue-600/20 text-blue-200'
                        : 'border-gray-700 bg-gray-950 text-gray-300 hover:bg-gray-800'
                    }`}
                  >
                    {PROOF_FILTER_LABELS[pf]} <span className="text-gray-500">{count}</span>
                  </button>
                )
              })}
            </div>
            <p className="text-xs text-gray-500">
              Proven evidence is shown first. Choose another proof state to inspect incomplete or unverified records.
            </p>
            <Input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by vulnerability type, objective, target, or ID"
              aria-label="Search evidence"
            />
            <details className="rounded-lg border border-gray-800 bg-gray-950/40">
              <summary className="cursor-pointer list-none px-3 py-2 text-xs font-medium text-gray-500 hover:text-gray-300">
                Advanced: filter by finding ID / fingerprint
              </summary>
              <div className="flex gap-2 border-t border-gray-800 p-3">
                <Input
                  type="text"
                  value={findingInput}
                  onChange={(e) => setFindingInput(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') setFilter('finding_id', findingInput.trim() || undefined) }}
                  placeholder="Finding UUID / fingerprint"
                  aria-label="Filter by finding ID or fingerprint"
                />
                <Button variant="secondary" onClick={() => setFilter('finding_id', findingInput.trim() || undefined)}>Apply</Button>
              </div>
            </details>
          </div>
        </Card>
      )}

      {/* A finding's durable proof lives in evidence OBJECTS. */}
      {findingFilter && (
        <SectionCard title={`Evidence objects${findingObjects.length ? ` (${findingObjects.length})` : ''}`}>
          {loadError ? (
            <ErrorState message="Failed to load evidence." onRetry={load} />
          ) : loading ? (
            <TableSkeleton rows={3} />
          ) : findingObjects.length === 0 ? (
            <EmptyState message="No evidence objects for this finding" hint="This finding has no durable evidence objects captured yet." />
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-800 text-sm">
                <thead>
                  <tr className="text-left text-xs uppercase tracking-wide text-gray-500">
                    <th className="px-3 py-2">Object</th>
                    <th className="px-3 py-2">Hash</th>
                    <th className="px-3 py-2">Size</th>
                    <th className="px-3 py-2">Redaction</th>
                    <th className="px-3 py-2">Retention</th>
                    <th className="px-3 py-2">Created</th>
                    <th className="px-3 py-2"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800">
                  {findingObjects.map((obj) => (
                    <tr key={obj.id} className="hover:bg-gray-800/40">
                      <td className="px-3 py-2 text-gray-200">{obj.object_type?.replace(/_/g, ' ') || 'object'}</td>
                      <td className="px-3 py-2 font-mono text-xs text-gray-500">{(obj.content_sha256 || obj.hash || '').slice(0, 12) || '—'}{(obj.content_sha256 || obj.hash) ? '…' : ''}</td>
                      <td className="px-3 py-2 text-gray-400">{formatBytes(obj.size_bytes)}</td>
                      <td className="px-3 py-2 text-xs text-gray-400">{obj.redaction_profile || '—'}</td>
                      <td className="px-3 py-2"><RetentionClassBadge retentionClass={obj.retention_class} /></td>
                      <td className="px-3 py-2 text-gray-500">{obj.created_at ? formatDate(obj.created_at) : '—'}</td>
                      <td className="px-3 py-2 text-right">
                        <button type="button" onClick={() => setModalObjectId(obj.id)} className="text-xs text-blue-400 hover:text-blue-300">View object</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </SectionCard>
      )}

      {!findingFilter && (
        <SectionCard title={instances.length ? `Autonomous test evidence (${countLabel})` : 'Evidence'}>
          {loadError ? (
            <ErrorState message="Failed to load evidence." onRetry={load} />
          ) : loading ? (
            <TableSkeleton rows={5} />
          ) : instances.length === 0 ? (
            <EmptyState
              message="No evidence yet"
              hint="Evidence is recorded when proof-backed findings and autonomous tests capture durable request/response proof."
            />
          ) : visible.length === 0 ? (
            <EmptyState message="No evidence matches these filters" hint="Try a different proof state or clear the search." />
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-800 text-sm">
                <thead>
                  <tr className="text-left text-xs uppercase tracking-wide text-gray-500">
                    <th className="px-3 py-2">Evidence</th>
                    <th className="px-3 py-2">Target</th>
                    <th className="px-3 py-2">Proof</th>
                    <th className="px-3 py-2">Source</th>
                    <th className="px-3 py-2">Retention</th>
                    <th className="px-3 py-2">Created</th>
                    <th className="px-3 py-2"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800">
                  {visible.map((inst) => {
                    const cwe = evidenceCwe(inst)
                    const objective = evidenceObjective(inst)
                    const expanded = expandedId === inst.id
                    return (
                      <Fragment key={inst.id}>
                        <tr className="hover:bg-gray-800/40">
                          <td className="px-3 py-2">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="font-medium text-gray-100">{evidenceFamily(inst)}</span>
                              {cwe && <Badge className="bg-gray-800 text-gray-300">{cwe}</Badge>}
                            </div>
                            {objective ? (
                              <p className="mt-0.5 max-w-md truncate text-xs text-gray-500" title={objective}>{objective}</p>
                            ) : (
                              <p className="mt-0.5 max-w-md truncate text-xs text-gray-500">
                                No objective recorded — open details to see what is missing.
                              </p>
                            )}
                          </td>
                          <td className="px-3 py-2 text-gray-300">{hostOf(inst.concrete_url) || <span className="text-gray-600">—</span>}</td>
                          <td className="px-3 py-2">
                            {inst.proof_state && inst.proof_state !== 'unverified'
                              ? <ProofStateBadge proofState={inst.proof_state as 'verified'} />
                              : <span className="text-xs text-gray-500">unverified</span>}
                          </td>
                          <td className="px-3 py-2"><span className="text-xs text-gray-400">{humanSource(inst.created_by) || '—'}</span></td>
                          <td className="px-3 py-2"><RetentionClassBadge retentionClass={inst.retention_policy} /></td>
                          <td className="px-3 py-2 text-gray-500">{inst.created_at ? formatDate(inst.created_at) : '—'}</td>
                          <td className="px-3 py-2 text-right">
                            <button
                              type="button"
                              onClick={async () => {
                                if (expanded) {
                                  detailRequestId.current += 1
                                  setExpandedId(null)
                                  setExpandedInstance(null)
                                  setDetailError(false)
                                  return
                                }
                                setExpandedId(inst.id)
                                setExpandedInstance(null)
                                setDetailError(false)
                                setDetailLoading(true)
                                const requestId = detailRequestId.current + 1
                                detailRequestId.current = requestId
                                try {
                                  const detail = await getEvidenceInstance(inst.id)
                                  if (detailRequestId.current === requestId) setExpandedInstance(detail)
                                } catch {
                                  if (detailRequestId.current === requestId) setDetailError(true)
                                } finally {
                                  if (detailRequestId.current === requestId) setDetailLoading(false)
                                }
                              }}
                              aria-expanded={expanded}
                              className="text-xs text-blue-400 hover:text-blue-300"
                            >
                              {expanded ? 'Hide' : 'Details'}
                            </button>
                          </td>
                        </tr>
                        {expanded && (
                          <tr className="bg-gray-950/60">
                            <td colSpan={7} className="px-3 py-3">
                              {detailLoading ? (
                                <div className="flex items-center gap-2 text-xs text-gray-400"><Spinner className="h-4 w-4" /> Loading full proof…</div>
                              ) : detailError ? (
                                <p className="text-xs text-red-300">Full proof could not be loaded. Collapse and retry this row.</p>
                              ) : expandedInstance ? (
                                <EvidenceDetail
                                  inst={expandedInstance}
                                  onViewObject={expandedInstance.evidence_object_id ? () => setModalObjectId(expandedInstance.evidence_object_id!) : undefined}
                                />
                              ) : null}
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </SectionCard>
      )}

      <details className="rounded-lg border border-gray-800 bg-gray-950/30">
        <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-gray-400 hover:text-gray-200">
          Advanced: export and retention administration
        </summary>
        <div className="border-t border-gray-800 p-4">
          <EvidenceRetentionPanel findingId={findingFilter || undefined} />
        </div>
      </details>

      <EvidenceObjectModal objectId={modalObjectId} onClose={() => setModalObjectId(null)} />
    </div>
  )
}

function EvidenceDetail({ inst, onViewObject }: { inst: EvidenceInstance; onViewObject?: () => void }) {
  const po = proofObs(inst)
  const fp = familyProof(inst)
  const objective = text(po.objective)
  const expected = text(po.expected_signal)
  const falsifier = text(po.falsifier)
  const verdict = text(fp.verdict)
  const comparisons = Array.isArray(po.comparisons) ? po.comparisons : []
  const hasDecisionRule = Boolean(objective && expected && falsifier)
  const isUsableProof = inst.proof_state === 'verified' && hasDecisionRule && comparisons.length > 0

  return (
    <div className="grid gap-4 text-sm md:grid-cols-2">
      <div className="space-y-2">
        <div className={`rounded-lg border p-3 ${
          isUsableProof
            ? 'border-emerald-500/25 bg-emerald-500/[0.06] text-emerald-100'
            : 'border-amber-500/25 bg-amber-500/[0.06] text-amber-100'
        }`}>
          <div className="text-xs font-semibold uppercase tracking-wide">
            {isUsableProof ? 'Reproducible proof' : 'Incomplete evidence'}
          </div>
          <p className="mt-1 text-xs opacity-80">
            {isUsableProof
              ? 'The decision rule and request comparison are recorded.'
              : 'Do not treat this record as proof until its decision rule and request comparison are complete.'}
          </p>
        </div>
        {objective && <div><div className="text-xs font-medium text-gray-500">Objective</div><p className="text-gray-300">{objective}</p></div>}
        {expected && <div><div className="text-xs font-medium text-emerald-400">Signal that supports it</div><p className="text-gray-300">{expected}</p></div>}
        {falsifier && <div><div className="text-xs font-medium text-gray-500">What would disprove it</div><p className="text-gray-400">{falsifier}</p></div>}
        {!hasDecisionRule && (
          <p className="text-xs text-amber-300">
            Missing decision rule. Re-run verification with an expected signal and a condition that would disprove the claim.
          </p>
        )}
        <div className="flex flex-wrap gap-3 text-xs">
          {inst.finding_id && <Link href={`/findings/${inst.finding_id}`} className="text-blue-400 hover:text-blue-300">Open finding</Link>}
          {inst.scan_id && <Link href={`/scans/${inst.scan_id}`} className="text-blue-400 hover:text-blue-300">Open scan</Link>}
          {inst.target_id && <Link href={`/asm?target_id=${inst.target_id}`} className="text-blue-400 hover:text-blue-300">Open target coverage</Link>}
        </div>
      </div>
      <div className="space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          {verdict && (
            <Badge className={verdict === 'verified' ? 'bg-emerald-500/15 text-emerald-300' : 'bg-amber-500/15 text-amber-300'}>
              proof: {verdict.replace(/_/g, ' ')}
            </Badge>
          )}
          {fp.reproduction_count === 2 && <Badge className="bg-emerald-500/10 text-emerald-300">reproduced twice</Badge>}
          {fp.restoration_verified === true && <Badge className="bg-blue-500/10 text-blue-300">state restored</Badge>}
          {typeof inst.tool_receipt_id === 'string' && <span className="text-xs text-gray-600">receipt {inst.tool_receipt_id.slice(0, 8)}…</span>}
        </div>
        {comparisons.length > 0 ? (
          <details className="rounded border border-gray-800 bg-gray-950/50">
            <summary className="cursor-pointer px-2 py-1.5 text-xs text-blue-300">
              Read {comparisons.length} request comparison{comparisons.length === 1 ? '' : 's'}
            </summary>
            <div className="grid gap-2 border-t border-gray-800 p-2">
              {comparisons.slice(0, 3).map((comparison, index) => (
                <pre key={index} className="max-h-56 overflow-auto whitespace-pre-wrap break-words rounded bg-black/30 p-2 text-[10px] leading-4 text-gray-400">
                  {JSON.stringify(comparison, null, 2)}
                </pre>
              ))}
            </div>
          </details>
        ) : (
          <p className="text-xs text-amber-300">No request/response comparison was captured.</p>
        )}
        {onViewObject && (
          <button type="button" onClick={onViewObject} className="text-xs text-blue-400 hover:text-blue-300">View raw object</button>
        )}
        <details className="rounded border border-gray-800 bg-black/20">
          <summary className="cursor-pointer px-2 py-1.5 text-xs text-gray-500 hover:text-gray-300">Raw proof observation</summary>
          <pre className="max-h-64 overflow-auto p-2 text-[10px] leading-4 text-gray-500">{JSON.stringify(po, null, 2)}</pre>
        </details>
      </div>
    </div>
  )
}

export default function EvidencePage() {
  return (
    <Suspense fallback={
      <div className="flex h-32 items-center justify-center">
        <Spinner className="h-6 w-6 text-blue-500" />
      </div>
    }>
      <EvidenceContent />
    </Suspense>
  )
}
