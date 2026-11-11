// A discovery run maps a target's hosts and endpoints with active testing off. It is stored as a
// scan row, the Scans list hides it by default, and it is not the target's application result.
// The roles match api/scan/discovery_runs.py.

export const DISCOVERY_SCAN_ROLES = ['asm_recon', 'parallel_discovery']

/** True for a discovery run. */
export function isDiscoveryRun(scan) {
  return DISCOVERY_SCAN_ROLES.includes(String(scan?.scan_role || ''))
}

/**
 * What the Scans list says about the runs it leaves out, or null when it hides none.
 * `hidden` is the API's count of discovery and internal runs matching the current filters.
 */
export function hiddenRunsNote(hidden) {
  const count = Number(hidden)
  if (!Number.isFinite(count) || count <= 0) return null
  return `${count} discovery or internal run${count === 1 ? '' : 's'} not shown`
}

/** "Showing ..." for the Scans list: the rows listed, out of the total the filters match. */
export function scansShownText(total, page, pageSize) {
  if (total <= pageSize) return `Showing ${total} scan${total === 1 ? '' : 's'}`
  return `Showing ${(page - 1) * pageSize + 1}-${Math.min(page * pageSize, total)} of ${total}`
}
