// Pure helpers for the Discovered secrets card: the terminal fallback command and the grouping
// that keeps a long list readable. No React.

const SAFE_WORD = /^[A-Za-z0-9_@%+=:,./-]+$/

/** One shell word, single-quoted unless it is plainly safe. Any text stays one inert word. */
export function shellQuote(value) {
  const text = String(value ?? '')
  if (text && SAFE_WORD.test(text)) return text
  return `'${text.replace(/'/g, `'"'"'`)}'`
}

/**
 * The terminal command that makes a step-up decision, with what the person already chose in the
 * browser. A choice not made yet keeps its placeholder.
 */
export function secretsCommand(action, targetId, ref, choices = {}) {
  const words = ['shakerscan', 'secrets', action, shellQuote(targetId), shellQuote(ref)]
  if (action === 'grant') {
    const to = String(choices.to ?? '').trim()
    words.push('--to', to ? shellQuote(to) : '<target-id>')
  } else if (action === 'promote') {
    const name = String(choices.name ?? '').trim()
    const kind = String(choices.authKind ?? '').trim()
    const header = String(choices.headerName ?? '').trim()
    words.push('--name', name ? shellQuote(name) : '<name>', '--auth-kind', kind ? shellQuote(kind) : '<kind>')
    if (header) words.push('--header-name', shellQuote(header))
  }
  return words.join(' ')
}

/** Secrets of the same kind and field name, in the order their first member appears. */
export function groupSecrets(rows) {
  const groups = new Map()
  for (const row of rows || []) {
    const label = String(row.label || '').trim()
    const key = `${row.kind}\u0000${label}\u0000${row.found_on}`
    let group = groups.get(key)
    if (!group) {
      group = { key, kind: row.kind, label: label || 'unnamed field', foundOn: row.found_on, rows: [] }
      groups.set(key, group)
    }
    group.rows.push(row)
  }
  return [...groups.values()]
}

/** How many secrets a page of the card shows at a time. */
export const SECRETS_PAGE_SIZE = 10
