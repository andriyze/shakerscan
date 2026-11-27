/** Keep operational details out of the normal target workflow. */
export function networkReadinessPresentation(readiness) {
  const status = readiness?.status || 'checking'
  if (status === 'ready') return null
  const starting = status === 'starting' || status === 'checking'
  return {
    role: starting || status === 'disabled' ? 'status' : 'alert',
    starting,
    message: readiness?.message || (status === 'checking'
      ? 'Checking network scanning availability…'
      : starting
      ? 'Network scanning is starting. This page will update automatically.'
      : status === 'disabled'
        ? 'Network scanning is disabled on this installation.'
        : 'Network scanning is unavailable. Your saved targets and results are still accessible.'),
    remedy: starting ? null : readiness?.remedy || null,
  }
}
