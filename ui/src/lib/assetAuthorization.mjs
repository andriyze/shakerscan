// The authorization a Targets row states, from the same authority the scan path resolves.
//
// A host asset's standing authorization covers the web apps that inherit it. A web app can
// also hold its own standing receipt: the scan flow records it on the web address, and scans
// of that address run under it whether or not the host is authorized. The list once read only
// the host's receipt, so an asset whose web app was authorized and actively scanned was shown
// as "Not authorized" and offered a second authorization.

/** @returns {{ state: 'authorized' | 'partial' | 'web_apps' | 'none', label: string, title: string }} */
export function assetAuthorizationStatus(asset) {
  const item = asset && typeof asset === 'object' ? asset : {}
  const webApps = (Array.isArray(item.origins) ? item.origins : []).filter((origin) => origin && origin.is_active)
  const total = Math.max(webApps.length, Number(item.origin_count) || 0)
  const known = Number.isFinite(Number(item.authorized_origin_count))
  const covered = known
    ? Number(item.authorized_origin_count)
    : webApps.filter((origin) => origin.authorized === true).length
  const plural = (count) => `${count} web app${count === 1 ? '' : 's'}`
  if (item.authorized) {
    if (known && total > 0 && covered < total) {
      return {
        state: 'partial',
        label: `Authorized · ${covered} of ${plural(total)}`,
        title: `The host is authorized, but ${plural(total - covered)} ${total - covered === 1 ? 'has' : 'have'} its own authorization revoked and ${total - covered === 1 ? 'runs' : 'run'} passive checks only`,
      }
    }
    return { state: 'authorized', label: 'Authorized', title: 'Standing authorization recorded: scans and Hunts can test this target' }
  }
  if (covered > 0) {
    return {
      state: 'web_apps',
      label: total > covered ? `${covered} of ${plural(total)} authorized` : covered === 1 ? 'Web app authorized' : `${plural(covered)} authorized`,
      title: 'Scans of the authorized web address run under its own standing authorization. The host itself and its other services are not authorized; authorize the asset to cover them too.',
    }
  }
  return { state: 'none', label: 'Not authorized', title: 'No standing authorization: only passive checks run until you authorize it' }
}
