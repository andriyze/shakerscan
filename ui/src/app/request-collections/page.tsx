'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import { Braces, ChevronLeft, ChevronRight, Plus, RefreshCw } from 'lucide-react'
import {
  createRequestCollection,
  getDevices,
  getRequestCollection,
  getTargets,
  listRequestCollectionInventory,
  listRequestCollections,
  upsertRequestCollectionBinding,
  upsertRequestCollectionEnvironment,
  upsertRequestCollectionSelection,
  type DeviceTarget,
  type RequestCollectionDetail,
  type RequestCollectionInventoryItem,
  type RequestCollectionReplayPolicy,
  type RequestCollectionTargetKind,
  type SharedRequestCollection,
  type Target,
} from '@/lib/api'
import {
  Button,
  Card,
  EmptyState,
  ErrorState,
  Field,
  Input,
  Modal,
  PageHeader,
  Select,
  Textarea,
  useToast,
} from '@/components/ui'

type Choice = {
  id: string
  label: string
  detail: string
  locator: string
  ownerKind: 'web' | 'device'
}

function splitValues(value: string): string[] {
  return Array.from(new Set(
    value.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean),
  ))
}

function parseJson(value: string, label: string): unknown {
  try {
    return JSON.parse(value)
  } catch {
    throw new Error(`${label} must be valid JSON.`)
  }
}

async function readFile(file: File | undefined): Promise<string | null> {
  if (!file) return null
  if (file.size > 50 * 1024 * 1024) throw new Error('Collection file exceeds 50 MiB.')
  return file.text()
}

function defaultOrigin(choice: Choice | undefined): string {
  if (!choice) return ''
  try {
    const parsed = new URL(choice.locator)
    return parsed.origin
  } catch {
    return ''
  }
}

export default function RequestCollectionsPage() {
  const toast = useToast()
  const [targets, setTargets] = useState<Target[]>([])
  const [devices, setDevices] = useState<DeviceTarget[]>([])
  const [targetKind, setTargetKind] = useState<RequestCollectionTargetKind>('web')
  const [targetId, setTargetId] = useState('')
  const [collections, setCollections] = useState<SharedRequestCollection[]>([])
  const [selectedId, setSelectedId] = useState('')
  const [detail, setDetail] = useState<RequestCollectionDetail | null>(null)
  const [inventory, setInventory] = useState<RequestCollectionInventoryItem[]>([])
  const [inventoryTotal, setInventoryTotal] = useState(0)
  const [inventoryOffset, setInventoryOffset] = useState(0)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [uploaderOpen, setUploaderOpen] = useState(false)

  const [uploadName, setUploadName] = useState('')
  const [uploadFormat, setUploadFormat] = useState('auto')
  const [documentText, setDocumentText] = useState('')
  const [environmentText, setEnvironmentText] = useState('')
  const [environmentName, setEnvironmentName] = useState('')
  const [baseUrl, setBaseUrl] = useState('')

  const [bindingOrigins, setBindingOrigins] = useState('')
  const [bindingEnvironmentId, setBindingEnvironmentId] = useState('')
  const [newEnvironmentName, setNewEnvironmentName] = useState('')
  const [newEnvironmentText, setNewEnvironmentText] = useState('')

  const [selectionName, setSelectionName] = useState('')
  const [selectionBindingId, setSelectionBindingId] = useState('')
  const [replayPolicy, setReplayPolicy] = useState<RequestCollectionReplayPolicy>('safe_reads')
  const [requestIds, setRequestIds] = useState('')
  const [folders, setFolders] = useState('')
  const [methods, setMethods] = useState('')
  const [tags, setTags] = useState('')
  const [pathRegex, setPathRegex] = useState('')
  const [safeMethodsOnly, setSafeMethodsOnly] = useState(true)
  const [maxRequests, setMaxRequests] = useState('500')

  useEffect(() => {
    let cancelled = false
    Promise.all([getTargets({ limit: 500 }), getDevices({ limit: 500 })])
      .then(([web, connected]) => {
        if (cancelled) return
        setTargets((web.targets || []).filter((item) => item.is_active))
        setDevices((connected.devices || []).filter((item) => item.is_active))
      })
      .catch((cause) => {
        if (!cancelled) setError(cause instanceof Error ? cause.message : 'Failed to load targets')
      })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [])

  const choices = useMemo<Choice[]>(() => targetKind === 'device'
    ? devices.map((item) => ({
        id: item.id,
        label: String(item.name || 'Connected device').slice(0, 160),
        detail: String(item.primary_locator || '').slice(0, 240),
        locator: String(item.primary_locator || '').slice(0, 2048),
        ownerKind: 'device' as const,
      }))
    : targets.map((item) => ({
        id: item.id,
        label: String(item.name || item.url || 'Web target').slice(0, 160),
        detail: String(item.url || '').slice(0, 240),
        locator: String(item.url || '').slice(0, 2048),
        ownerKind: 'web' as const,
      })), [devices, targetKind, targets])
  const selectedChoice = choices.find((choice) => choice.id === targetId)

  useEffect(() => {
    if (!choices.some((choice) => choice.id === targetId)) {
      setTargetId(choices[0]?.id || '')
    }
  }, [choices, targetId])

  const loadCollections = useCallback(async () => {
    if (!targetId) {
      setCollections([])
      setSelectedId('')
      return
    }
    try {
      const result = await listRequestCollections(targetId)
      setCollections(result.collections || [])
      setSelectedId((current) => (
        result.collections.some((item) => item.id === current)
          ? current
          : result.collections[0]?.id || ''
      ))
      setError(null)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Failed to load request collections')
    }
  }, [targetId])

  useEffect(() => { void loadCollections() }, [loadCollections])

  const loadDetail = useCallback(async (offset = 0) => {
    if (!selectedId) {
      setDetail(null)
      setInventory([])
      setInventoryTotal(0)
      return
    }
    try {
      const [nextDetail, nextInventory] = await Promise.all([
        getRequestCollection(selectedId),
        listRequestCollectionInventory(selectedId, { limit: 100, offset }),
      ])
      setDetail(nextDetail)
      setInventory(nextInventory.requests || [])
      setInventoryTotal(nextInventory.total || 0)
      setInventoryOffset(nextInventory.offset || 0)
      setError(null)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Failed to load request collection')
    }
  }, [selectedId])

  useEffect(() => { void loadDetail(0) }, [loadDetail])

  const matchingBindings = useMemo(() => (detail?.bindings || []).filter((binding) => (
    binding.target_id === targetId && binding.target_kind === targetKind
  )), [detail?.bindings, targetId, targetKind])

  useEffect(() => {
    setSelectionBindingId((current) => (
      matchingBindings.some((binding) => binding.id === current)
        ? current
        : matchingBindings[0]?.id || ''
    ))
  }, [matchingBindings])

  useEffect(() => {
    if (replayPolicy !== 'confirmed_active') setSafeMethodsOnly(true)
  }, [replayPolicy])

  function openUploader() {
    setUploadName('')
    setUploadFormat('auto')
    setDocumentText('')
    setEnvironmentText('')
    setEnvironmentName('')
    setBaseUrl(defaultOrigin(selectedChoice))
    setUploaderOpen(true)
  }

  async function uploadCollection() {
    if (!targetId || !documentText.trim()) return
    setBusy(true)
    try {
      const created = await createRequestCollection({
        target_id: targetId,
        name: uploadName.trim() || undefined,
        format: uploadFormat,
        document: parseJson(documentText, 'Collection document'),
        environment: environmentText.trim()
          ? parseJson(environmentText, 'Environment document')
          : undefined,
        environment_name: environmentName.trim() || undefined,
        base_url: targetKind === 'device' && baseUrl.trim() ? baseUrl.trim() : undefined,
      })
      setUploaderOpen(false)
      await loadCollections()
      setSelectedId(created.id)
      toast.success('Encrypted request collection uploaded and indexed')
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : 'Collection upload failed')
    } finally {
      setBusy(false)
    }
  }

  async function saveEnvironment() {
    if (!detail || !newEnvironmentName.trim() || !newEnvironmentText.trim()) return
    setBusy(true)
    try {
      const document = parseJson(newEnvironmentText, 'Environment document')
      if (!document || typeof document !== 'object' || Array.isArray(document)) {
        throw new Error('Environment document must be one JSON object.')
      }
      await upsertRequestCollectionEnvironment(detail.collection.id, {
        name: newEnvironmentName.trim(),
        document: document as Record<string, unknown>,
      })
      setNewEnvironmentName('')
      setNewEnvironmentText('')
      await loadDetail(inventoryOffset)
      toast.success('Encrypted environment saved')
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : 'Environment update failed')
    } finally {
      setBusy(false)
    }
  }

  async function saveBinding() {
    if (!detail || !targetId) return
    setBusy(true)
    try {
      await upsertRequestCollectionBinding(detail.collection.id, {
        target_kind: targetKind,
        target_id: targetId,
        allowed_origins: splitValues(bindingOrigins),
        environment_id: bindingEnvironmentId || undefined,
      })
      await loadDetail(inventoryOffset)
      toast.success('Exact-origin collection binding saved')
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : 'Collection binding failed')
    } finally {
      setBusy(false)
    }
  }

  async function saveSelection() {
    if (!detail || !selectionBindingId || !selectionName.trim()) return
    setBusy(true)
    try {
      await upsertRequestCollectionSelection(detail.collection.id, {
        name: selectionName.trim(),
        binding_id: selectionBindingId,
        replay_policy: replayPolicy,
        request_ids: splitValues(requestIds),
        folders: splitValues(folders),
        methods: splitValues(methods).map((method) => method.toUpperCase()),
        tags: splitValues(tags),
        path_regex: pathRegex.trim() || undefined,
        safe_methods_only: safeMethodsOnly,
        max_requests: Math.max(1, Math.min(Number.parseInt(maxRequests, 10) || 500, 2000)),
      })
      setSelectionName('')
      await loadDetail(inventoryOffset)
      toast.success('Named selection saved with a deterministic digest')
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : 'Selection update failed')
    } finally {
      setBusy(false)
    }
  }

  if (loading) return <div className="p-6 text-sm text-gray-400">Loading collection targets…</div>
  if (error && !targets.length && !devices.length) return <ErrorState message={error} />

  return (
    <div className="mx-auto max-w-7xl space-y-6 p-6">
      <PageHeader
        title="Request Collections"
        description="Upload once, bind to exact approved origins, browse a redacted inventory, and attach saved selections to Scan or Hunt. Documents and environment values are never returned after upload."
        icon={<Braces className="h-6 w-6" />}
        actions={<>
          <Button variant="secondary" onClick={() => void loadCollections()} disabled={!targetId}>
            <RefreshCw className="h-4 w-4" /> Refresh
          </Button>
          <Button onClick={openUploader} disabled={!targetId}>
            <Plus className="h-4 w-4" /> Upload
          </Button>
        </>}
      />

      <Card className="grid gap-4 p-5 md:grid-cols-[180px_minmax(0,1fr)]">
        <Field label="Target kind">
          <Select value={targetKind} onChange={(event) => setTargetKind(event.target.value as RequestCollectionTargetKind)}>
            <option value="web">Web application</option>
            <option value="api">API</option>
            <option value="device">Connected device</option>
          </Select>
        </Field>
        <Field label="Collection owner">
          <Select value={targetId} onChange={(event) => setTargetId(event.target.value)}>
            {!choices.length && <option value="">No active targets</option>}
            {choices.map((choice) => (
              <option key={choice.id} value={choice.id}>{choice.label} · {choice.detail}</option>
            ))}
          </Select>
        </Field>
      </Card>

      {error && <p className="rounded-lg border border-amber-800 bg-amber-950/20 p-3 text-sm text-amber-200">{error}</p>}

      {!collections.length ? (
        <EmptyState
          message="No shared request collections for this target"
          hint="Upload a Postman, HAR, OpenAPI, or Swagger JSON document to begin."
          action={{ label: 'Upload collection', onClick: openUploader }}
        />
      ) : (
        <div className="grid gap-5 lg:grid-cols-[280px_minmax(0,1fr)]">
          <Card className="h-fit space-y-2 p-3">
            {collections.map((collection) => (
              <button
                key={collection.id}
                type="button"
                onClick={() => setSelectedId(collection.id)}
                className={`w-full rounded-lg border p-3 text-left ${
                  selectedId === collection.id
                    ? 'border-blue-500 bg-blue-500/10'
                    : 'border-gray-800 bg-gray-950 hover:border-gray-700'
                }`}
              >
                <span className="block truncate text-sm font-medium text-white">{collection.name}</span>
                <span className="mt-1 block text-xs text-gray-500">
                  {collection.format} · {collection.request_count} requests
                </span>
              </button>
            ))}
          </Card>

          {detail && (
            <div className="space-y-5">
              <Card className="p-5">
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div>
                    <h2 className="text-lg font-medium text-white">{detail.collection.name}</h2>
                    <p className="mt-1 text-xs text-gray-500">
                      {detail.collection.request_count} requests · {detail.collection.safe_request_count} safe · {detail.collection.potentially_mutating_request_count} potentially state-changing
                    </p>
                  </div>
                  <span className="rounded bg-emerald-500/10 px-2 py-1 text-xs text-emerald-300">
                    encrypted · digest {detail.collection.payload_sha256.slice(0, 12)}
                  </span>
                </div>
              </Card>

              <Card className="space-y-4 p-5">
                <div>
                  <h3 className="font-medium text-white">Environments</h3>
                  <p className="mt-1 text-xs text-gray-500">Stored separately and decrypted only by the assigned worker.</p>
                </div>
                {detail.environments.map((environment) => (
                  <div key={environment.id} className="rounded border border-gray-800 bg-gray-950 p-3 text-sm text-gray-300">
                    {environment.name} · {environment.variable_count} variables · digest {environment.payload_sha256.slice(0, 12)}
                  </div>
                ))}
                <div className="grid gap-3 md:grid-cols-[220px_minmax(0,1fr)_auto] md:items-end">
                  <Field label="Environment name"><Input value={newEnvironmentName} onChange={(event) => setNewEnvironmentName(event.target.value)} /></Field>
                  <Field label="Environment JSON"><Textarea rows={3} value={newEnvironmentText} onChange={(event) => setNewEnvironmentText(event.target.value)} /></Field>
                  <Button onClick={saveEnvironment} loading={busy} disabled={!newEnvironmentName.trim() || !newEnvironmentText.trim()}>Save</Button>
                </div>
              </Card>

              <Card className="space-y-4 p-5">
                <div>
                  <h3 className="font-medium text-white">Exact-origin binding</h3>
                  <p className="mt-1 text-xs text-gray-500">Origins must use the exact target host and contain no path, query, or credentials.</p>
                </div>
                {matchingBindings.map((binding) => (
                  <div key={binding.id} className="rounded border border-gray-800 bg-gray-950 p-3 text-xs text-gray-300">
                    {binding.allowed_origins.join(', ')} · {binding.environment_id ? 'environment attached' : 'no environment'}
                  </div>
                ))}
                <div className="grid gap-3 md:grid-cols-2">
                  <Field label="Allowed origins (one per line)">
                    <Textarea rows={3} value={bindingOrigins} onChange={(event) => setBindingOrigins(event.target.value)} placeholder={defaultOrigin(selectedChoice) || 'https://api.example.com'} />
                  </Field>
                  <Field label="Environment">
                    <Select value={bindingEnvironmentId} onChange={(event) => setBindingEnvironmentId(event.target.value)}>
                      <option value="">No environment</option>
                      {detail.environments.map((environment) => <option key={environment.id} value={environment.id}>{environment.name}</option>)}
                    </Select>
                  </Field>
                </div>
                <Button onClick={saveBinding} loading={busy} disabled={!bindingOrigins.trim()}>Save binding</Button>
              </Card>

              <Card className="space-y-4 p-5">
                <div>
                  <h3 className="font-medium text-white">Named selections</h3>
                  <p className="mt-1 text-xs text-gray-500">Selectors are frozen with the collection, environment, binding, and replay policy digests.</p>
                </div>
                {detail.selections.map((selection) => (
                  <div key={selection.id} className="rounded border border-gray-800 bg-gray-950 p-3 text-sm text-gray-300">
                    <span className="font-medium text-white">{selection.name}</span>
                    <span className="ml-2 text-xs text-gray-500">{selection.selected_request_count} requests · {selection.replay_policy.replaceAll('_', ' ')} · {selection.selection_digest.slice(0, 12)}</span>
                  </div>
                ))}
                {!matchingBindings.length ? (
                  <p className="rounded border border-amber-800 bg-amber-950/20 p-3 text-xs text-amber-200">Save an exact {targetKind} binding before creating a selection.</p>
                ) : (
                  <div className="space-y-3 rounded border border-gray-800 bg-gray-950 p-4">
                    <div className="grid gap-3 md:grid-cols-3">
                      <Field label="Selection name"><Input value={selectionName} onChange={(event) => setSelectionName(event.target.value)} /></Field>
                      <Field label="Binding"><Select value={selectionBindingId} onChange={(event) => setSelectionBindingId(event.target.value)}>{matchingBindings.map((binding) => <option key={binding.id} value={binding.id}>{binding.allowed_origins.join(', ')}</option>)}</Select></Field>
                      <Field label="Replay policy"><Select value={replayPolicy} onChange={(event) => setReplayPolicy(event.target.value as RequestCollectionReplayPolicy)}><option value="discovery_only">Discovery only</option><option value="safe_reads">Safe reads</option><option value="confirmed_active">Confirmed active</option></Select></Field>
                    </div>
                    <div className="grid gap-3 md:grid-cols-2">
                      <Field label="Request IDs"><Textarea rows={2} value={requestIds} onChange={(event) => setRequestIds(event.target.value)} /></Field>
                      <Field label="Folders"><Textarea rows={2} value={folders} onChange={(event) => setFolders(event.target.value)} /></Field>
                      <Field label="Methods"><Input value={methods} onChange={(event) => setMethods(event.target.value)} placeholder="GET, HEAD" /></Field>
                      <Field label="Tags"><Input value={tags} onChange={(event) => setTags(event.target.value)} placeholder="smoke, authenticated" /></Field>
                      <Field label="Path regular expression"><Input value={pathRegex} onChange={(event) => setPathRegex(event.target.value)} placeholder="^/api/" /></Field>
                      <Field label="Maximum requests"><Input type="number" min="1" max="2000" value={maxRequests} onChange={(event) => setMaxRequests(event.target.value)} /></Field>
                    </div>
                    <label className={`flex items-start gap-3 text-sm ${replayPolicy === 'confirmed_active' ? 'text-gray-300' : 'text-gray-600'}`}>
                      <input type="checkbox" checked={safeMethodsOnly} disabled={replayPolicy !== 'confirmed_active'} onChange={(event) => setSafeMethodsOnly(event.target.checked)} />
                      Safe methods only. Turning this off is only valid for confirmed-active selections; execution still requires active testing, state-changing permission, and a target-bound approval.
                    </label>
                    <Button onClick={saveSelection} loading={busy} disabled={!selectionName.trim() || !selectionBindingId}>Save selection</Button>
                  </div>
                )}
              </Card>

              <Card className="overflow-hidden">
                <div className="flex flex-wrap items-center justify-between gap-3 border-b border-gray-800 p-5">
                  <div>
                    <h3 className="font-medium text-white">Redacted request inventory</h3>
                    <p className="mt-1 text-xs text-gray-500">URLs are redacted; headers, bodies, cookies, and environment values are never returned.</p>
                  </div>
                  <span className="text-xs text-gray-500">{inventoryOffset + 1}–{Math.min(inventoryOffset + inventory.length, inventoryTotal)} of {inventoryTotal}</span>
                </div>
                <div className="divide-y divide-gray-800">
                  {inventory.map((item) => (
                    <div key={item.request_id} className="grid gap-2 p-4 text-sm md:grid-cols-[90px_minmax(0,1fr)_180px]">
                      <span className={item.safe_method ? 'text-emerald-300' : 'text-amber-300'}>{item.method}</span>
                      <span className="min-w-0 truncate text-gray-300">{item.name || item.normalized_path || item.redacted_url}</span>
                      <span className="truncate text-xs text-gray-500">{item.tags.join(', ') || item.folder || 'untagged'}</span>
                    </div>
                  ))}
                </div>
                <div className="flex justify-end gap-2 border-t border-gray-800 p-4">
                  <Button variant="secondary" disabled={inventoryOffset === 0} onClick={() => void loadDetail(Math.max(0, inventoryOffset - 100))}><ChevronLeft className="h-4 w-4" /> Previous</Button>
                  <Button variant="secondary" disabled={inventoryOffset + inventory.length >= inventoryTotal} onClick={() => void loadDetail(inventoryOffset + 100)}>Next <ChevronRight className="h-4 w-4" /></Button>
                </div>
              </Card>
            </div>
          )}
        </div>
      )}

      <Modal open={uploaderOpen} onClose={() => setUploaderOpen(false)} title="Upload request collection" size="xl">
        <div className="space-y-4">
          <div className="grid gap-3 md:grid-cols-2">
            <Field label="Collection name"><Input value={uploadName} onChange={(event) => setUploadName(event.target.value)} placeholder="Production API" /></Field>
            <Field label="Format"><Select value={uploadFormat} onChange={(event) => setUploadFormat(event.target.value)}><option value="auto">Detect automatically</option><option value="postman">Postman</option><option value="har">HAR 1.2</option><option value="openapi">OpenAPI / Swagger</option></Select></Field>
          </div>
          <Field label="Collection JSON file">
            <input type="file" accept=".json,.har,application/json" onChange={(event) => void readFile(event.target.files?.[0]).then((value) => { if (value !== null) setDocumentText(value) }).catch((cause) => toast.error(cause instanceof Error ? cause.message : 'Failed to read file'))} className="block w-full text-sm text-gray-400" />
          </Field>
          <Field label="Collection JSON"><Textarea rows={10} value={documentText} onChange={(event) => setDocumentText(event.target.value)} placeholder="Paste a Postman, HAR, OpenAPI, or Swagger JSON document" /></Field>
          <div className="grid gap-3 md:grid-cols-2">
            <Field label="Environment name (optional)"><Input value={environmentName} onChange={(event) => setEnvironmentName(event.target.value)} /></Field>
            <Field label="Environment JSON file (optional)"><input type="file" accept=".json,application/json" onChange={(event) => void readFile(event.target.files?.[0]).then((value) => { if (value !== null) setEnvironmentText(value) }).catch((cause) => toast.error(cause instanceof Error ? cause.message : 'Failed to read file'))} className="block w-full text-sm text-gray-400" /></Field>
          </div>
          <Field label="Environment JSON (optional)"><Textarea rows={5} value={environmentText} onChange={(event) => setEnvironmentText(event.target.value)} /></Field>
          {targetKind === 'device' && <Field label="Device web base URL (optional)"><Input value={baseUrl} onChange={(event) => setBaseUrl(event.target.value)} placeholder="https://device.local:8443" /></Field>}
          <p className="rounded border border-emerald-800 bg-emerald-950/20 p-3 text-xs text-emerald-200">After validation, only encrypted documents and a redacted index are stored. This screen never reads secret-bearing content back.</p>
          <div className="flex justify-end gap-3">
            <Button variant="secondary" onClick={() => setUploaderOpen(false)}>Cancel</Button>
            <Button onClick={uploadCollection} loading={busy} disabled={!documentText.trim()}>Validate and upload</Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}
