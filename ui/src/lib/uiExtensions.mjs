// ui-extensions/v1 (docs/ui-extensions.md): what a managed deployment adds to this UI: sidebar
// entries, pages of its own shown inside the UI's shell, panels in named places of a page, and
// an account block. The UI does not know what any entry means; it draws them.
//
// Everything is validated here. An entry that fails a check is dropped, a block with another
// schema is ignored whole, and unknown members are ignored, so no declaration can make the UI
// leave its own origin, render markup, or grow an unbounded menu. The declaration arrives with
// the managed workspace policy, which the deployment itself serves: these checks contain
// mistakes and keep the UI's own guarantees; they are not a boundary against the deployment.

export const SCHEMA = 'shakerscan.ui-extensions/v1'

export const LIMITS = Object.freeze({
  sections: 4, pages: 12, nav: 12, slotPanels: 2, accountLinks: 6, text: 60, path: 256, query: 2048,
})

// The places in the UI's own pages that take panels, with the placeholders each one fills.
export const SLOTS = Object.freeze({ 'finding.detail': Object.freeze(['finding_id']) })

// Icon names a sidebar entry may ask for; any other name gets `DEFAULT_ICON`.
export const DEFAULT_ICON = 'puzzle'
export const ICON_NAMES = Object.freeze([
  'bell', 'bug', 'calendar', 'calendar-clock', 'chart', 'clipboard-check', 'clock', 'file-text',
  'flag', 'gauge', 'globe', 'inbox', 'key', 'layers', 'link', 'list-checks', 'puzzle', 'refresh',
  'shield-check', 'tag', 'ticket', 'users', 'wrench',
])

// The name a hosted page's route carries until the browser knows the declared title.
export const HOSTED_PAGE_TITLE = 'Page'

// Where an entry goes when the section it names does not exist in this UI.
export const FALLBACK_SECTION = 'More'

export const NO_EXTENSIONS = Object.freeze({
  sections: Object.freeze([]), pages: Object.freeze([]), nav: Object.freeze([]),
  slots: Object.freeze({}), account: null,
})

const ID = /^[a-z0-9-]{1,32}$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
// Unreserved characters, the path and query delimiters and percent-encoding; nothing else.
const PATH_CHARACTERS = /^[A-Za-z0-9\-._~/?#=&%+:@,]*$/
const ENCODED_SEPARATOR = /%(?:2e|2f|5c)/i
const CONTROL = /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/

const isObject = (value) => Boolean(value) && typeof value === 'object' && !Array.isArray(value)
const list = (value, limit) => (Array.isArray(value) ? value.slice(0, limit) : [])

/** Display text: a string of 1 to 60 characters after trimming, without control characters. */
export function safeText(value) {
  if (typeof value !== 'string') return null
  const text = value.trim()
  return text && text.length <= LIMITS.text && !CONTROL.test(text) ? text : null
}

/**
 * A path on the UI's own origin: starts with one "/", at most 256 characters from a fixed set,
 * no "//", no ".." segment, no encoded dot, slash or backslash in the path. A query and a
 * fragment are allowed. `placeholders` names the "{name}" markers this path may carry.
 */
export function safePath(value, placeholders = []) {
  if (typeof value !== 'string' || !value || value.length > LIMITS.path) return null
  let bare = value
  for (const name of placeholders) bare = bare.replaceAll(`{${name}}`, 'x')
  if (!bare.startsWith('/') || !PATH_CHARACTERS.test(bare)) return null
  const path = bare.split(/[?#]/, 1)[0]
  if (path.includes('//') || ENCODED_SEPARATOR.test(path)) return null
  if (path.split('/').some((segment) => segment === '..')) return null
  return value
}

/**
 * The path as this origin's URL would spell it, or null when it resolves anywhere else. Called
 * with the page's own origin right before a path is used.
 */
export function sameOriginPath(path, origin) {
  if (safePath(path) === null || typeof origin !== 'string') return null
  try {
    const url = new URL(path, origin)
    if (url.origin !== new URL(origin).origin) return null
    return `${url.pathname}${url.search}${url.hash}`
  } catch {
    return null
  }
}

function uniqueById(entries) {
  const seen = new Set()
  return entries.filter((entry) => !seen.has(entry.id) && Boolean(seen.add(entry.id)))
}

function framed(entry, placeholders) {
  if (!isObject(entry) || typeof entry.id !== 'string' || !ID.test(entry.id)) return null
  const title = safeText(entry.title)
  const src = safePath(entry.src, placeholders)
  return title && src ? { id: entry.id, title, src } : null
}

function section(entry) {
  if (!isObject(entry) || typeof entry.id !== 'string' || !ID.test(entry.id)) return null
  const label = safeText(entry.label)
  if (!label) return null
  const after = safeText(entry.after)
  return after ? { id: entry.id, label, after } : { id: entry.id, label }
}

function navEntry(entry, pageIds) {
  if (!isObject(entry)) return null
  const label = safeText(entry.label)
  if (!label) return null
  const hasPage = entry.page !== undefined, hasHref = entry.href !== undefined
  if (hasPage === hasHref) return null // one destination, not none and not two
  const out = { label, icon: ICON_NAMES.includes(entry.icon) ? entry.icon : DEFAULT_ICON }
  if (hasPage) {
    if (typeof entry.page !== 'string' || !pageIds.has(entry.page)) return null
    out.page = entry.page
    out.href = `/ext/${entry.page}`
  } else {
    const href = safePath(entry.href)
    if (!href) return null
    out.href = href
  }
  const sectionName = safeText(entry.section)
  if (sectionName) out.section = sectionName
  const after = safePath(entry.after)
  if (after) out.after = after
  return out
}

function account(value) {
  if (!isObject(value)) return null
  const name = safeText(value.name)
  if (!name) return null
  const links = list(value.links, LIMITS.accountLinks).map((link) => {
    const label = isObject(link) ? safeText(link.label) : null
    const href = isObject(link) ? safePath(link.href) : null
    return label && href ? { label, href } : null
  }).filter(Boolean)
  return { name, detail: safeText(value.detail), links, sign_out: safePath(value.sign_out) }
}

/** The declared block, normalized; anything that is not this contract is no extensions at all. */
export function parseUiExtensions(block) {
  if (!isObject(block) || block.schema !== SCHEMA) return NO_EXTENSIONS
  const pages = uniqueById(list(block.pages, LIMITS.pages).map((entry) => framed(entry, [])).filter(Boolean))
  const pageIds = new Set(pages.map((page) => page.id))
  const slots = {}
  if (isObject(block.slots)) {
    for (const [name, placeholders] of Object.entries(SLOTS)) {
      const panels = uniqueById(list(block.slots[name], LIMITS.slotPanels)
        .map((entry) => framed(entry, placeholders)).filter(Boolean))
      if (panels.length) slots[name] = panels
    }
  }
  return {
    sections: uniqueById(list(block.sections, LIMITS.sections).map(section).filter(Boolean)),
    pages,
    nav: list(block.nav, LIMITS.nav).map((entry) => navEntry(entry, pageIds)).filter(Boolean),
    slots,
    account: account(block.account),
  }
}

/**
 * The framed address of a hosted page: its `src` with the outer page's query string added. The
 * query is passed as the browser encoded it; one longer than 2,048 characters, or carrying a
 * "#", is not passed.
 */
export function hostedPageSrc(src, search = '') {
  const query = String(search || '').replace(/^\?/, '')
  if (!query || query.length > LIMITS.query || query.includes('#')) return src
  const [beforeHash, hash] = src.split('#', 2)
  const joined = `${beforeHash}${beforeHash.includes('?') ? '&' : '?'}${query}`
  return hash === undefined ? joined : `${joined}#${hash}`
}

/**
 * A slot panel's address with its placeholders filled. Every value must be an identifier the
 * UI already holds (a UUID); a missing or malformed one means the panel is not shown.
 */
export function slotPanelSrc(src, values = {}) {
  let out = src
  for (const [name, value] of Object.entries(values)) {
    if (!out.includes(`{${name}}`)) continue
    if (typeof value !== 'string' || !UUID.test(value)) return null
    out = out.replaceAll(`{${name}}`, value.toLowerCase())
  }
  return out.includes('{') || out.includes('}') ? null : out
}

/**
 * The sidebar's groups with the declared sections and entries placed. `groups` is the UI's own
 * list ({ heading, items: [{ href, ... }] }); the result is a new list, the input is untouched.
 * A declared section goes after the heading it names (or last). An entry goes into the section
 * it names (a heading of the UI, or a declared section's id), after the entry whose href it
 * names (or last); an entry naming no section this UI has goes under "More".
 */
export function placeNavigation(groups, extensions) {
  const out = groups.map((group) => ({ ...group, items: [...group.items] }))
  if (!extensions || (!extensions.sections.length && !extensions.nav.length)) return out
  const declared = new Map()
  for (const entry of extensions.sections) {
    const group = { heading: entry.label, items: [], extension: true }
    declared.set(entry.id, group)
    const anchor = entry.after ? out.findIndex((candidate) => candidate.heading === entry.after) : -1
    if (anchor === -1) out.push(group)
    else out.splice(anchor + 1, 0, group)
  }
  for (const entry of extensions.nav) {
    let group = entry.section
      ? declared.get(entry.section) ?? out.find((candidate) => candidate.heading === entry.section)
      : undefined
    if (!group) {
      group = out.find((candidate) => candidate.extension && candidate.heading === FALLBACK_SECTION)
      if (!group) {
        group = { heading: FALLBACK_SECTION, items: [], extension: true }
        out.push(group)
      }
    }
    const item = { href: entry.href, label: entry.label, icon: entry.icon, extension: true, hosted: Boolean(entry.page) }
    let index = entry.after ? group.items.findIndex((candidate) => candidate.href === entry.after && !candidate.extension) : -1
    if (index === -1) {
      group.items.push(item)
      continue
    }
    // Entries that name the same anchor keep their declared order.
    while (group.items[index + 1]?.extension && group.items[index + 1].anchor === entry.after) index += 1
    group.items.splice(index + 1, 0, { ...item, anchor: entry.after })
  }
  return out.filter((group) => !group.extension || group.items.length > 0)
}
