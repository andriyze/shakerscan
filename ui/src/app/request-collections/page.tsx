'use client'
import { featureEnabled } from '@/lib/workspaceCapabilities'

import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useUrlFilters } from '@/lib/useUrlFilters'
import { UploadAttempt } from '@/lib/uploadAttempt'
import { Braces, ChevronLeft, ChevronRight, Copy, Pencil, Plus, RefreshCw, Trash2 } from 'lucide-react'
import { getAllTargetAssets, getTargetAsset, type TargetAsset, type AssetOrigin } from '@/lib/targetAssetApi'
import {
  createRequestCollection,
  deactivateRequestCollection,
  deactivateRequestCollectionSelection,
  getRequestCollection,
  listRequestCollectionInventory,
  listRequestCollections,
  upsertRequestCollectionBinding,
  upsertRequestCollectionEnvironment,
  upsertRequestCollectionSelection,
  type RequestCollectionDetail,
  type RequestCollectionInventoryItem,
  type RequestCollectionImportFormat,
  type RequestCollectionReplayPolicy,
  type RequestCollectionTargetKind,
  type SharedRequestCollection,
} from '@/lib/requestCollectionApi'
import {
  Button,
  Card,
  ConfirmDialog,
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
  ownerKind: 'network'
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
    return ['http:', 'https:'].includes(parsed.protocol) ? parsed.origin : ''
  } catch {
    return ''
  }
}

const COLLECTION_TARGET_KINDS: RequestCollectionTargetKind[] = ['web', 'api', 'network', 'device']

export default function RequestCollectionsPage() {
  return (
    <Suspense fallback={null}>
      <RequestCollectionsContent />
    </Suspense>
  )
}

function RequestCollectionsContent() {
  const toast = useToast()
  const [assets, setAssets] = useState<TargetAsset[]>([])
  // The collection owner lives in the URL, so reload, Back and links keep it.
  const { filters, setFilters } = useUrlFilters<{ target_kind?: string; target_id?: string }>()
  const targetKind: RequestCollectionTargetKind = COLLECTION_TARGET_KINDS.includes(filters.target_kind as RequestCollectionTargetKind)
    ? filters.target_kind as RequestCollectionTargetKind
    : 'network'
  const targetId = filters.target_id || ''
  const setTargetId = useCallback((id: string) => setFilters({ target_id: id || undefined }), [setFilters])
  const setTargetKind = useCallback((kind: RequestCollectionTargetKind) => setFilters({
    target_kind: kind,
  }), [setFilters])
  const latestCollectionsRequest = useRef(0)
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
  const [deleting, setDeleting] = useState<SharedRequestCollection | null>(null)

  const [uploadName, setUploadName] = useState('')
  const uploadAttempt = useRef(new UploadAttempt())
  const [uploadFormat, setUploadFormat] = useState<RequestCollectionImportFormat>('auto')
  const [documentText, setDocumentText] = useState('')
  const [environmentText, setEnvironmentText] = useState('')
  const [environmentName, setEnvironmentName] = useState('')
  const [baseUrl, setBaseUrl] = useState('')
  const [uploadErrors, setUploadErrors] = useState<{ document?: string; environment?: string; form?: string }>({})

  const [bindingOrigins, setBindingOrigins] = useState('')
  const [executionTargetId, setExecutionTargetId] = useState('')
  const [assetOrigins, setAssetOrigins] = useState<AssetOrigin[]>([])
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
    getAllTargetAssets().then((items) => {
      if (!cancelled) setAssets(items)
    })
      .catch((cause) => {
        if (!cancelled) setError(cause instanceof Error ? cause.message : 'Failed to load targets')
      })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [])

  const choices = useMemo<Choice[]>(() => assets.map((asset) => ({
    id:asset.id,label:asset.name || asset.locator,detail:asset.locator,locator:asset.url,ownerKind:'network',
  })),[assets])
  const selectedChoice = choices.find((choice) => choice.id === targetId)
  useEffect(() => {
    setExecutionTargetId(targetId); setAssetOrigins([]); setBindingOrigins('')
    if (!targetId) return
    const controller = new AbortController()
    getTargetAsset(targetId,controller.signal).then((result) => {
      if (!controller.signal.aborted) setAssetOrigins(result.origins.filter((origin) => origin.is_active && origin.current_membership))
    }).catch((cause) => {if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Could not load application origins')})
    return () => controller.abort()
  },[targetId])
  const executionOrigin = assetOrigins.find((origin) => origin.id === executionTargetId)
  const executionKind: RequestCollectionTargetKind = executionOrigin ? 'web' : 'network'
  const availableBindingTargets = useMemo(() => new Set([targetId,...assetOrigins.map((origin) => origin.id)]),[targetId,assetOrigins])
  useEffect(() => {
    if (loading || !targetId || assets.some((asset) => asset.id === targetId)) return
    let cancelled = false
    getTargetAsset(targetId).then((result) => {
      if (cancelled) return
      if (!result.target.is_active) {setError('The linked target is retired');return}
      setAssets((current) => current.some((asset) => asset.id === result.target.id) ? current : [...current,result.target])
      setTargetId(result.target.id)
    }).catch((cause) => {if (!cancelled) setError(cause instanceof Error ? cause.message : 'Target not found')})
    return () => {cancelled = true}
  },[assets,loading,setTargetId,targetId])

  const loadCollections = useCallback(async () => {
    // Only the latest request may fill the list, so a slow answer never shows another target's collections.
    const request = ++latestCollectionsRequest.current
    if (!targetId) {
      setCollections([])
      setSelectedId('')
      return
    }
    try {
      const result = await listRequestCollections(targetId)
      if (request !== latestCollectionsRequest.current) return
      setCollections(result.collections || [])
      setSelectedId((current) => (
        result.collections.some((item) => item.id === current)
          ? current
          : result.collections[0]?.id || ''
      ))
      setError(null)
    } catch (cause) {
      if (request !== latestCollectionsRequest.current) return
      // The previous target's collections must not stay on screen under this target.
      setCollections([])
      setSelectedId('')
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
    availableBindingTargets.has(binding.target_id)
  )), [detail?.bindings, availableBindingTargets])

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
    uploadAttempt.current.reset()
    setUploadName('')
    setUploadFormat('auto')
    setDocumentText('')
    setEnvironmentText('')
    setEnvironmentName('')
    setBaseUrl(defaultOrigin(selectedChoice))
    setUploadErrors({})
    setUploaderOpen(true)
  }

  async function uploadCollection() {
    if (!targetId || !documentText.trim()) return
    let document: unknown
    let environment: unknown
    try {
      document = parseJson(documentText, 'Collection document')
    } catch (cause) {
      setUploadErrors({ document: cause instanceof Error ? cause.message : 'Collection document must be valid JSON.', form: 'Fix the highlighted collection document before uploading.' })
      return
    }
    if (environmentText.trim()) {
      try {
        environment = parseJson(environmentText, 'Environment document')
      } catch (cause) {
        setUploadErrors({ environment: cause instanceof Error ? cause.message : 'Environment document must be valid JSON.', form: 'Fix the highlighted environment document before uploading.' })
        return
      }
    }
    setUploadErrors({})
    setBusy(true)
    try {
      const payload = {
        target_id: targetId,
        name: uploadName.trim() || undefined,
        format: uploadFormat,
        document,
        environment,
        environment_name: environmentName.trim() || undefined,
        base_url: baseUrl.trim() || undefined,
      }
      const retryKey = await uploadAttempt.current.keyFor(payload)
      const created = await createRequestCollection(payload, retryKey)
      uploadAttempt.current.reset()
      setUploaderOpen(false)
      await loadCollections()
      setSelectedId(created.id)
      toast.success('Encrypted request collection uploaded and indexed')
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : 'Collection upload failed'
      setUploadErrors({ form: message })
      toast.error(message)
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
        target_kind: executionKind,
        target_id: executionTargetId,
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

  function loadSelectionForEdit(selection: RequestCollectionDetail['selections'][number], clone: boolean) {
    setSelectionName(clone ? `${selection.name} copy` : selection.name)
    setSelectionBindingId(selection.binding_id)
    setReplayPolicy(selection.replay_policy)
    setRequestIds(selection.selector.request_ids.join('\n'))
    setFolders(selection.selector.folders.join('\n'))
    setMethods(selection.selector.methods.join(', '))
    setTags(selection.selector.tags.join(', '))
    setPathRegex(selection.selector.path_regex || '')
    setSafeMethodsOnly(selection.selector.safe_methods_only)
    setMaxRequests(String(selection.selector.max_requests || 500))
    toast.info(clone ? 'Loaded a copy. Rename or adjust it, then save.' : 'Loaded for replacement. Saving the same name creates a new digest.')
  }

  async function deleteCollection() {
    if (!deleting) return
    setBusy(true)
    try {
      const result = await deactivateRequestCollection(deleting.id)
      setDeleting(null)
      setDetail(null)
      setSelectedId('')
      await loadCollections()
      toast.success(result.revoked_selections > 0
        ? `Request collection deleted; ${result.revoked_selections} saved selection(s) revoked`
        : 'Request collection deleted')
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : 'Collection deletion failed')
    } finally {
      setBusy(false)
    }
  }

  async function deactivateSelection(selectionId: string) {
    if (!detail || !window.confirm('Deactivate this saved selection? Existing historical scan records are retained.')) return
    setBusy(true)
    try {
      await deactivateRequestCollectionSelection(detail.collection.id, selectionId)
      await loadDetail(inventoryOffset)
      toast.success('Request selection deactivated')
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : 'Selection deactivation failed')
    } finally {
      setBusy(false)
    }
  }

  if (loading) return <div className="p-6 text-sm text-gray-400">Loading collection targets…</div>
  if (error && !assets.length) return <ErrorState message={error} />

  return (
    <div className="mx-auto max-w-7xl space-y-6 p-6">
      <PageHeader
        title="Request Collections"
        description="Upload once for an asset, bind the same collection to its exact application origins, and attach immutable selection IDs to Scan or Hunt. Documents and environment values stay encrypted."
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
            <option value="network">Asset / network</option>
            {featureEnabled('devices') && <option value="device">Connected device</option>}
          </Select>
        </Field>
        <Field label="Collection owner">
          <Select value={targetId} onChange={(event) => setTargetId(event.target.value)}>
            <option value="">{choices.length ? 'Choose a target…' : 'No active targets'}</option>
            {choices.map((choice) => (
              <option key={choice.id} value={choice.id}>{choice.label} · {choice.detail}</option>
            ))}
          </Select>
        </Field>
      </Card>

      {error && <p className="rounded-lg border border-amber-800 bg-amber-950/20 p-3 text-sm text-amber-200">{error}</p>}

      {!collections.length ? (
        <EmptyState
          message={targetId ? 'No shared request collections for this target' : 'Choose a collection owner'}
          hint={targetId
            ? 'Upload a Postman, HAR, OpenAPI, or Swagger JSON document to begin.'
            : 'Select the exact asset record that owns this collection. Binding then permits explicit scheme + hostname + port origins on that owner hostname.'}
          action={targetId ? { label: 'Upload collection', onClick: openUploader } : undefined}
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
                  <div className="flex items-center gap-2">
                    <span className="rounded-sm bg-emerald-500/10 px-2 py-1 text-xs text-emerald-300">
                      encrypted · digest {detail.collection.payload_sha256.slice(0, 12)}
                    </span>
                    <Button variant="danger" size="sm" onClick={() => setDeleting(detail.collection)} disabled={busy}><Trash2 className="h-3.5 w-3.5" /> Delete</Button>
                  </div>
                </div>
              </Card>

              <Card className="space-y-4 p-5">
                <div>
                  <h3 className="font-medium text-white">Environments</h3>
                  <p className="mt-1 text-xs text-gray-500">Stored separately and decrypted only by the assigned worker.</p>
                </div>
                {detail.environments.map((environment) => (
                  <div key={environment.id} className="rounded-sm border border-gray-800 bg-gray-950 p-3 text-sm text-gray-300">
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
                  <p className="mt-1 text-xs text-gray-500">
                    The asset owns one document. Choose a host or application service for execution; application bindings retain the exact scheme, hostname, and port.
                  </p>
                  {selectedChoice && <p className="mt-1 text-xs text-blue-300">Owner: {selectedChoice.label} · hostname source {selectedChoice.locator}</p>}
                </div>
                {matchingBindings.map((binding) => (
                  <div key={binding.id} className="rounded-sm border border-gray-800 bg-gray-950 p-3 text-xs text-gray-300">
                    {binding.target_id === targetId ? 'Host' : 'Application service'} · {binding.allowed_origins.join(', ')} · {binding.environment_id ? 'environment attached' : 'no environment'}
                  </div>
                ))}
                <Field label="Execution target / service">
                  <Select value={executionTargetId} onChange={(event) => {
                    const next = event.target.value
                    setExecutionTargetId(next)
                    const origin = assetOrigins.find((item) => item.id === next)
                    setBindingOrigins(origin ? new URL(origin.url).origin : '')
                  }}>
                    <option value={targetId}>Host asset · {selectedChoice?.label || targetId}</option>
                    {assetOrigins.map((origin) => <option key={origin.id} value={origin.id}>{origin.url}</option>)}
                  </Select>
                </Field>
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
                  <div key={selection.id} className="flex flex-wrap items-center justify-between gap-3 rounded-sm border border-gray-800 bg-gray-950 p-3 text-sm text-gray-300">
                    <div>
                      <span className="font-medium text-white">{selection.name}</span>
                      <span className="ml-2 text-xs text-gray-500">{selection.selected_request_count} requests · {selection.replay_policy.replaceAll('_', ' ')} · {selection.selection_digest.slice(0, 12)}</span>
                    </div>
                    <div className="flex gap-2">
                      <Button variant="secondary" size="sm" onClick={() => loadSelectionForEdit(selection, false)}><Pencil className="h-3.5 w-3.5" /> Replace</Button>
                      <Button variant="secondary" size="sm" onClick={() => loadSelectionForEdit(selection, true)}><Copy className="h-3.5 w-3.5" /> Clone</Button>
                      <Button variant="danger" size="sm" onClick={() => void deactivateSelection(selection.id)} disabled={busy}><Trash2 className="h-3.5 w-3.5" /> Deactivate</Button>
                    </div>
                  </div>
                ))}
                {!matchingBindings.length ? (
                  <p className="rounded-sm border border-amber-800 bg-amber-950/20 p-3 text-xs text-amber-200">Save an exact {targetKind} binding before creating a selection.</p>
                ) : (
                  <div className="space-y-3 rounded-sm border border-gray-800 bg-gray-950 p-4">
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
                    <p className="text-xs text-gray-500">Saving an existing name replaces its selector and digest; changing the name creates a clone. Historical scan bindings remain immutable.</p>
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

      <ConfirmDialog
        open={Boolean(deleting)}
        title={deleting ? `Delete "${deleting.name}"?` : 'Delete request collection?'}
        message="The collection disappears from this list and its saved selections, bindings and environments are revoked, so no new Scan or Hunt can use it. Historical scan records keep their immutable selection digests; the encrypted document is erased when the owning target's records are deleted."
        confirmLabel="Delete"
        danger
        busy={busy}
        onConfirm={() => void deleteCollection()}
        onCancel={() => setDeleting(null)}
      />

      <Modal open={uploaderOpen} onClose={() => setUploaderOpen(false)} title="Upload request collection" size="xl">
        <div className="space-y-4">
          {uploadErrors.form && (
            <div role="alert" className="rounded-sm border border-red-900/60 bg-red-950/30 p-3 text-sm text-red-300">
              {uploadErrors.form}
            </div>
          )}
          <div className="grid gap-3 md:grid-cols-2">
            <Field label="Collection name"><Input value={uploadName} onChange={(event) => setUploadName(event.target.value)} placeholder="Production API" /></Field>
            <Field label="Format"><Select value={uploadFormat} onChange={(event) => setUploadFormat(event.target.value as RequestCollectionImportFormat)}><option value="auto">Detect automatically</option><option value="postman_collection">Postman</option><option value="har">HAR 1.2</option><option value="openapi">OpenAPI / Swagger</option></Select></Field>
          </div>
          <Field label="Collection JSON file">
            <input type="file" accept=".json,.har,application/json" onChange={(event) => void readFile(event.target.files?.[0]).then((value) => { if (value !== null) { setDocumentText(value); setUploadErrors({}) } }).catch((cause) => setUploadErrors({ document: cause instanceof Error ? cause.message : 'Failed to read file', form: 'The collection file could not be read.' }))} className="block w-full text-sm text-gray-400" />
          </Field>
          <Field label="Collection JSON" error={uploadErrors.document} required><Textarea rows={10} value={documentText} onChange={(event) => { setDocumentText(event.target.value); setUploadErrors({}) }} placeholder="Paste a Postman, HAR, OpenAPI, or Swagger JSON document" /></Field>
          <div className="grid gap-3 md:grid-cols-2">
            <Field label="Environment name (optional)"><Input value={environmentName} onChange={(event) => setEnvironmentName(event.target.value)} /></Field>
            <Field label="Environment JSON file (optional)"><input type="file" accept=".json,application/json" onChange={(event) => void readFile(event.target.files?.[0]).then((value) => { if (value !== null) { setEnvironmentText(value); setUploadErrors({}) } }).catch((cause) => setUploadErrors({ environment: cause instanceof Error ? cause.message : 'Failed to read file', form: 'The environment file could not be read.' }))} className="block w-full text-sm text-gray-400" /></Field>
          </div>
          <Field label="Environment JSON (optional)" error={uploadErrors.environment}><Textarea rows={5} value={environmentText} onChange={(event) => { setEnvironmentText(event.target.value); setUploadErrors({}) }} /></Field>
          {<Field label="Application base URL (optional)"><Input value={baseUrl} onChange={(event) => setBaseUrl(event.target.value)} placeholder="https://device.local:8443" /></Field>}
          <p className="rounded-sm border border-emerald-800 bg-emerald-950/20 p-3 text-xs text-emerald-200">After validation, only encrypted documents and a redacted index are stored. This screen never reads secret-bearing content back.</p>
          <div className="flex justify-end gap-3">
            <Button variant="secondary" onClick={() => setUploaderOpen(false)}>Cancel</Button>
            <Button onClick={uploadCollection} loading={busy} disabled={!documentText.trim()}>Validate and upload</Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}
