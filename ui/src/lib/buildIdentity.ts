export type HealthBuildIdentity = {
  scanner_version?: string
  fleet?: {
    enabled?: boolean
    configured?: boolean
    supported?: boolean
    status?: 'enabled' | 'disabled' | 'unsupported'
    host_platform?: string
    reason?: string | null
  }
  worker_build?: {
    available?: boolean
    expected_count?: number | null
    reported_count?: number
    stale_count?: number
    pending_count?: number
    fleet_uniform?: boolean
    scanner_version?: string | null
  }
  device_worker?: { enabled?: boolean; status?: string; worker_count?: number }
  agent_tool_worker?: { status?: string; worker_count?: number }
}

export type BuildIdentity = {
  ui?: string
  api?: string
  workers?: string
  skew: boolean
}

export function comparableBuildVersion(value?: string | null): string | undefined {
  return value?.replace(/-dirty$/, '')
}

export function buildVersionsMatch(left?: string | null, right?: string | null): boolean {
  const normalizedLeft = comparableBuildVersion(left)
  const normalizedRight = comparableBuildVersion(right)
  if (!normalizedLeft || !normalizedRight) return normalizedLeft === normalizedRight
  if (normalizedLeft === normalizedRight) return true

  // Different components may obtain the same Git identity through `git rev-parse --short`
  // implementations configured for different abbreviation lengths. Treat unambiguous Git
  // prefixes of at least seven hexadecimal characters as the same commit. Release labels and
  // other human versions still require an exact match.
  if (!/^[0-9a-f]+$/i.test(normalizedLeft) || !/^[0-9a-f]+$/i.test(normalizedRight)) return false
  const sharedLength = Math.min(normalizedLeft.length, normalizedRight.length)
  return sharedLength >= 7 && normalizedLeft.slice(0, sharedLength) === normalizedRight.slice(0, sharedLength)
}

export function deriveBuildIdentity(
  bakedVersion: string | undefined,
  health: HealthBuildIdentity | null,
): BuildIdentity {
  const apiVersion = typeof health?.scanner_version === 'string' ? health.scanner_version : undefined
  const workerBuild = health?.worker_build
  const auxiliaryMismatchCount = (
    ((health?.agent_tool_worker?.worker_count || 0) > 0
      && health?.agent_tool_worker?.status !== 'ready' ? 1 : 0)
    + (health?.device_worker?.enabled === true
      && (health.device_worker.worker_count || 0) > 0
      && health.device_worker.status !== 'ready' ? 1 : 0)
  )
  const normalWorkerLabel = workerBuild?.available
    ? workerBuild.fleet_uniform
      ? workerBuild.scanner_version || apiVersion
      : workerBuild.expected_count == null
        ? `unverified (${workerBuild.reported_count || 0} reported)`
        : `mixed/stale (${(workerBuild.stale_count || 0) + (workerBuild.pending_count || 0)})`
    : undefined
  const workerLabel = auxiliaryMismatchCount > 0 && workerBuild?.fleet_uniform
    ? `mixed/stale (${auxiliaryMismatchCount} specialized)`
    : normalWorkerLabel

  // Raw docker compose intentionally bakes "dev" because Compose cannot discover Git. It is an
  // unknown UI label, not evidence of a stale image. scanner.sh and release installs bake a real
  // commit/tag, so they retain exact UI-vs-API mismatch detection.
  const displayedUiVersion = bakedVersion === 'dev' && apiVersion ? apiVersion : bakedVersion
  const uiApiSkew = Boolean(
    bakedVersion
      && bakedVersion !== 'dev'
      && apiVersion
      && !buildVersionsMatch(bakedVersion, apiVersion),
  )
  const workerSkew = Boolean(
    (workerBuild?.available && !workerBuild.fleet_uniform) || auxiliaryMismatchCount > 0,
  )
  return {
    ui: displayedUiVersion,
    api: apiVersion,
    workers: workerLabel,
    skew: uiApiSkew || workerSkew,
  }
}

export function formatBuildIdentity(identity: BuildIdentity): string {
  const componentVersions = [identity.ui, identity.api, identity.workers].filter(
    (value): value is string => Boolean(value),
  )
  const comparableVersions = componentVersions.map(comparableBuildVersion)
  const knownVersionsMatch = Boolean(
    !identity.skew
      && componentVersions.length > 0
      && comparableVersions.every((value) => buildVersionsMatch(value, comparableVersions[0])),
  )
  if (knownVersionsMatch) {
    const commonVersion = componentVersions.find((value) => value.endsWith('-dirty'))
      || identity.api
      || componentVersions[0]
    return `Version ${commonVersion}`
  }
  return [
    identity.ui && `UI ${identity.ui}`,
    identity.api && `API ${identity.api}`,
    identity.workers && `Workers ${identity.workers}`,
  ].filter(Boolean).join(' · ')
}
