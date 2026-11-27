/**
 * A target that web / scan workflows can act on: an http(s) URL that is not a
 * Model Intake artifact. Use this to keep model-artifact "targets" out of
 * web-target pickers (Auto Hunt, Leads, Manual Test, Schedules).
 */
export function isWebTarget(target: { url?: string | null; discovery_source?: string | null }): boolean {
  return /^https?:\/\//i.test(target.url ?? '') && target.discovery_source !== 'model-intake'
}
