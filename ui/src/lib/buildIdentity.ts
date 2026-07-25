export type HealthBuildIdentity = {
  scanner_version?: string
  worker_build?: {
    available?: boolean
    expected_count?: number | null
    reported_count?: number
    stale_count?: number
    pending_count?: number
    fleet_uniform?: boolean
    scanner_version?: string | null
  }
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

export function deriveBuildIdentity(
  bakedVersion: string | undefined,
  health: HealthBuildIdentity | null,
): BuildIdentity {
  const apiVersion = typeof health?.scanner_version === 'string' ? health.scanner_version : undefined
  const workerBuild = health?.worker_build
  const workerLabel = workerBuild?.available
    ? workerBuild.fleet_uniform
      ? workerBuild.scanner_version || apiVersion
      : workerBuild.expected_count == null
        ? `unverified (${workerBuild.reported_count || 0} reported)`
        : `mixed/stale (${(workerBuild.stale_count || 0) + (workerBuild.pending_count || 0)})`
    : undefined

  // Raw docker compose intentionally bakes "dev" because Compose cannot discover Git. It is an
  // unknown UI label, not evidence of a stale image. scanner.sh and release installs bake a real
  // commit/tag, so they retain exact UI-vs-API mismatch detection.
  const displayedUiVersion = bakedVersion === 'dev' && apiVersion ? apiVersion : bakedVersion
  const uiApiSkew = Boolean(
    bakedVersion
      && bakedVersion !== 'dev'
      && apiVersion
      && comparableBuildVersion(bakedVersion) !== comparableBuildVersion(apiVersion),
  )
  const workerSkew = Boolean(workerBuild?.available && !workerBuild.fleet_uniform)
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
      && comparableVersions.every((value) => value === comparableVersions[0]),
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
