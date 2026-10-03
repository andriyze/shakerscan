// Pure presentation helpers for Hunt history rows.

/** host://example.test#retired=<uuid> -> example.test; https://x/ -> https://x */
export function cleanTargetLocator(url) {
  const value = String(url || '').trim()
  if (!value) return ''
  return value.replace(/^host:\/\//i, '').replace(/#retired=[0-9a-f-]+$/i, '').replace(/\/+$/, '')
}

/** Whether the target row behind this Hunt has since been retired. */
export function targetRetired(url) {
  return /#retired=/i.test(String(url || ''))
}

/** The name an operator gave the target, else its cleaned locator. */
export function huntTargetTitle(hunt) {
  const name = String(hunt?.target_name || '').trim()
  return name || cleanTargetLocator(hunt?.target_url) || hunt?.target_id || 'Unknown target'
}

/** Requests, actions and candidates a Hunt spent, from its settled budget usage. */
export function huntActivity(hunt) {
  const used = hunt?.budget_used || {}
  return {
    requests: Number(used.http_requests || 0),
    actions: Number(used.agent_actions || 0),
    candidates: Number(used.candidates || 0),
    browser: Number(used.browser_actions || 0),
    ports: Number(used.tcp_ports_attempted || 0) + Number(used.udp_ports_attempted || 0),
  }
}
