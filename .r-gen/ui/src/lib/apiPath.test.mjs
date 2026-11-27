import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

import { pathSegment, queryString } from './apiPath.mjs'

const BASE = 'https://engine.example'

function resolved(template) {
  return new URL(template, BASE).pathname
}

// An ID taken from the address bar or a link reached fetch() unencoded. "../../settings" (or
// "%2e%2e") moved a credentialed request to another API route, and "x?y" started a query.
test('a hostile ID stays inside its path segment or is refused', () => {
  for (const hostile of ['../admin', 'a/b', 'x?scope=all', 'x#frag', '%2e%2e', 'a\\b']) {
    const path = resolved(`/targets/${pathSegment(hostile)}/asm/policy`)
    assert.ok(path.startsWith('/targets/'), `${hostile} -> ${path}`)
    assert.ok(path.endsWith('/asm/policy'), `${hostile} -> ${path}`)
    assert.equal(path.split('/').length, 5, `${hostile} -> ${path}`)
  }
  for (const dot of ['.', '..', '']) {
    assert.throws(() => pathSegment(dot), /dot path segment/)
  }
})

test('ordinary IDs are unchanged', () => {
  assert.equal(pathSegment('5f0c2b1e-3a4d-4e5f-9a8b-7c6d5e4f3a2b'), '5f0c2b1e-3a4d-4e5f-9a8b-7c6d5e4f3a2b')
  assert.equal(pathSegment(42), '42')
  assert.equal(pathSegment('scan.v2'), 'scan.v2')
})

// Every value interpolated into a path position of an API URL in api.ts goes through
// pathSegment(); a new call site that interpolates an ID directly fails here.
test('api.ts builds every API path segment with pathSegment', () => {
  const source = readFileSync(new URL('./api.ts', import.meta.url), 'utf8')
  const raw = []
  for (const [index, line] of source.split('\n').entries()) {
    if (!line.includes('${API_URL}')) continue
    const path = line.split('?')[0]
    for (const match of path.matchAll(/\/\$\{([^}]*)\}/g)) {
      if (match[1] === 'API_URL' || /^pathSegment\([\w.]+\)$/.test(match[1])) continue
      raw.push(`${index + 1}: ${match[0]}`)
    }
  }
  assert.deepEqual(raw, [])
})


// Review sweep L3 (and its re-check): the rule held only in api.ts; about forty API calls elsewhere
// used plain encodeURIComponent (".." passes) or interpolated an ID raw, and a line-based check was
// easy to evade (a multi-line template, `API_URL + '/x/' + id`, an alias of API_URL, `x-${id}`,
// `${pathSegment(a)}${id}`, `${pathSegment(a) + String(id)}`, `?target=${target}`). Every source
// file is scanned whole: every template literal that builds an API URL is checked part by part.
const SRC = fileURLToPath(new URL('..', import.meta.url))
// Path text the code chooses itself, never a value from the address bar, a link or a record:
// file -> expressions (HttpArchiveExport's 'scans' | 'hunts'; ai-gate's REDTEAM_RESOURCE_LINKS).
const CODE_CHOSEN = { 'components/HttpArchiveExport.tsx': ['ownerPath'], 'app/ai-gate/page.tsx': ['item.path'] }
// The query string at the end of an API path, built by queryString(URLSearchParams) (apiPath.mjs).
const QUERY_SUFFIX = /^queryString\(.+\)$/s
const REFERENCE = String.raw`[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*`
const PATH_SEGMENT = new RegExp(String.raw`^pathSegment\(${REFERENCE}\)$`)
const QUERY_VALUE = new RegExp(String.raw`^(?:encodeURIComponent\(${REFERENCE}\)|${REFERENCE}\s*\?\s*'[\w-]*'\s*:\s*'[\w-]*')$`)
// A whole query string the code built (URLSearchParams), placed right after `?` or `&`.
const QUERY_STRING = new RegExp(String.raw`^(?:${REFERENCE}|${REFERENCE}\.toString\(\)|new URLSearchParams\([^\`]*\))$`)

function sources(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name)
    if (entry.isDirectory()) return sources(path)
    return /\.(ts|tsx|mjs)$/.test(entry.name) && !/\.test\./.test(entry.name) && !entry.name.endsWith('.d.ts')
      ? [path] : []
  })
}

// A small JavaScript/TypeScript lexer: comments, quoted strings, regular expressions and template
// literals (with nested `${...}` code and nested templates). Returns every template as its literal
// and expression parts, and the source with comments and string contents blanked (`code`).
const REGEX_BEFORE = new Set('(,=:[!&|?{};+-*%<>~^'.split(''))
export function lexTemplates(source) {
  const templates = []
  const code = source.split('')
  const blank = (from, to) => { for (let i = from; i < to; i++) if (code[i] !== '\n') code[i] = ' ' }
  const previous = (i) => { let j = i - 1; while (j >= 0 && /\s/.test(source[j])) j--; return j < 0 ? '' : source[j] }
  const word = (i) => { const m = /([A-Za-z_$][\w$]*)\s*$/.exec(source.slice(Math.max(0, i - 20), i)); return m ? m[1] : '' }
  function quoted(i, quote) {
    let j = i + 1
    while (j < source.length && source[j] !== quote && source[j] !== '\n') j += source[j] === '\\' ? 2 : 1
    blank(i + 1, j)
    return j + 1
  }
  function regex(i) {
    let j = i + 1, inClass = false
    while (j < source.length && source[j] !== '\n') {
      if (source[j] === '\\') { j += 2; continue }
      if (source[j] === '[') inClass = true
      else if (source[j] === ']') inClass = false
      else if (source[j] === '/' && !inClass) break
      j++
    }
    blank(i + 1, j)
    return j + 1
  }
  function templateAt(i) {
    const parts = []
    const line = source.slice(0, i).split('\n').length
    let j = i + 1, literal = ''
    while (j < source.length && source[j] !== '`') {
      if (source[j] === '\\') { literal += source.slice(j, j + 2); blank(j, j + 2); j += 2; continue }
      if (source[j] === '$' && source[j + 1] === '{') {
        parts.push({ kind: 'literal', text: literal }); literal = ''
        blank(j, j + 2)
        const start = j + 2
        j = codeUntilBrace(start)
        parts.push({ kind: 'expression', text: source.slice(start, j).trim(), start, end: j })
        blank(j, j + 1)
        j += 1
        continue
      }
      literal += source[j]; blank(j, j + 1); j++
    }
    parts.push({ kind: 'literal', text: literal })
    templates.push({ line, parts })
    return j + 1
  }
  // Code up to the `}` that closes the current `${`; returns its index.
  function codeUntilBrace(i) {
    let depth = 0
    while (i < source.length) {
      const next = step(i)
      if (next !== null) { i = next; continue }
      const ch = source[i]
      if (ch === '{') depth++
      else if (ch === '}') { if (depth === 0) return i; depth-- }
      i++
    }
    return i
  }
  // One lexical element starting at i, or null for an ordinary character.
  function step(i) {
    const ch = source[i]
    if (ch === '/' && source[i + 1] === '/') { const e = source.indexOf('\n', i); const end = e < 0 ? source.length : e; blank(i, end); return end }
    if (ch === '/' && source[i + 1] === '*') { const e = source.indexOf('*/', i + 2); const end = e < 0 ? source.length : e + 2; blank(i, end); return end }
    if (ch === '`') return templateAt(i)
    const before = previous(i)
    if ((ch === '"' || ch === "'") && (before === '' || REGEX_BEFORE.has(before) || ['return', 'case', 'in', 'of'].includes(word(i)))) {
      return quoted(i, ch)
    }
    if (ch === '/' && (before === '' || REGEX_BEFORE.has(before) || ['return', 'case', 'typeof'].includes(word(i)))) return regex(i)
    return null
  }
  let i = 0
  while (i < source.length) { const next = step(i); i = next === null ? i + 1 : next }
  return { templates, code: code.join('') }
}

function importsApiUrl(source) {
  return /import\s*\{[^}]*\bAPI_URL\b[^}]*\}\s*from/.test(source) || /\bconst API_URL = getApiUrl\(\)/.test(source)
}

export function apiUrlFindings(file, source) {
  const where = relative(SRC, file)
  const inLib = where.startsWith('lib/')
  const apiModule = importsApiUrl(source)
  const { templates, code } = lexTemplates(source)
  const found = []
  const allowedApiUrl = new Set()
  for (const { line, parts } of templates) {
    const first = parts[1]
    const leadingApiUrl = first && first.kind === 'expression' && parts[0].text === '' && first.text === 'API_URL'
    const leadingRun = first && first.kind === 'expression' && parts[0].text === '' && /^runPath\(/.test(first.text)
    if (leadingApiUrl) allowedApiUrl.add(first.start)
    const api = leadingApiUrl || leadingRun || (inLib && apiModule && parts[0].text.startsWith('/'))
    if (!api) continue
    // A lib request helper's `${API_URL}${path}`: its relative paths are templates checked here too.
    if (inLib && leadingApiUrl && parts.length === 5 && parts[2].text === '' && parts[3].text === 'path'
        && parts[4].text === '') continue
    const chosen = CODE_CHOSEN[where] || []
    let inQuery = false
    for (let index = 0; index < parts.length; index++) {
      const part = parts[index]
      if (part.kind === 'literal') { if (/[?#]/.test(part.text)) inQuery = true; continue }
      if (index === 1 && (leadingApiUrl || leadingRun)) continue
      const before = parts[index - 1].text
      const after = parts[index + 1] ? parts[index + 1].text : ''
      const report = () => found.push(`${where}:${line}: \${${part.text}}`)
      if (!inQuery) {
        const last = index === parts.length - 2 && after === ''
        if (chosen.includes(part.text)) continue
        if (last && QUERY_SUFFIX.test(part.text)) { inQuery = true; continue }
        const queryNext = index === parts.length - 4 && after === '' && parts[parts.length - 1].text === ''
          && QUERY_SUFFIX.test(parts[index + 2].text)
        const wholeSegment = before.endsWith('/') && (after === '' ? last || queryNext : /^[/?#]/.test(after))
        if (!wholeSegment || !PATH_SEGMENT.test(part.text)) report()
      } else if (before.endsWith('=')) {
        if (!QUERY_VALUE.test(part.text)) report()
      } else if (/[?&]$/.test(before)) {
        if (!QUERY_STRING.test(part.text)) report()
      } else {
        report()
      }
    }
  }
  // API_URL itself: only imported, defined, or the start of an API template; never concatenated
  // (`API_URL + '/x/' + id`) or handed to another name.
  for (const match of code.matchAll(/\bAPI_URL\b/g)) {
    const at = match.index
    const lineText = code.slice(code.lastIndexOf('\n', at) + 1, code.indexOf('\n', at) < 0 ? code.length : code.indexOf('\n', at))
    if (/^\s*import\b/.test(lineText) || /\bexport const API_URL = getApiUrl\(\)/.test(lineText)
        || /^\s*const API_URL = getApiUrl\(\)\s*$/.test(lineText)) continue
    if ([...allowedApiUrl].some((start) => start <= at && at < start + 'API_URL'.length + 2)) continue
    if (/^\s*(?:\}|,)?\s*(?:API_URL\s*,|.*\{[^}]*\bAPI_URL\b[^}]*\}\s*from)/.test(lineText)) continue  // a multi-line import list
    found.push(`${where}:${code.slice(0, at).split('\n').length}: API_URL used outside an API template`)
  }
  for (const match of code.matchAll(/\bgetApiUrl\(\)/g)) {
    const at = match.index
    const lineText = code.slice(code.lastIndexOf('\n', at) + 1, code.indexOf('\n', at))
    if (/\bconst API_URL = getApiUrl\(\)/.test(lineText) || /\bAPI_URL\b/.test(lineText) || where === 'lib/apiConfig.ts') continue
    found.push(`${where}:${code.slice(0, at).split('\n').length}: getApiUrl() aliased`)
  }
  return found
}

test('every API URL in the UI builds its path segments with pathSegment', () => {
  const found = sources(SRC).flatMap((file) => apiUrlFindings(file, readFileSync(file, 'utf8')))
  assert.deepEqual(found, [])
})

test('the source rule catches the shapes the reviews found', () => {
  const lib = join(SRC, 'lib', 'example.ts')
  const component = join(SRC, 'components', 'Example.tsx')
  const flagged = (file, text) => apiUrlFindings(file, `import { API_URL } from './apiConfig'\n${text}`).length
  assert.equal(flagged(component, 'fetch(`${API_URL}/devices/${encodeURIComponent(deviceId)}`)'), 1)
  assert.equal(flagged(component, 'const url = `${API_URL}/findings/${findingId}?scan_id=${scanId}`'), 2)
  assert.equal(flagged(lib, "request(`/targets/${encodeURIComponent(id)}/asset`)"), 1)
  assert.equal(flagged(lib, "fetch(`${runPath(huntId)}/investigations/${proposalId}`)"), 1)
  assert.equal(flagged(component, 'fetch(`${API_URL}\n  /findings/\n  ${id}`)'), 1)  // multi-line
  assert.equal(flagged(component, "fetch(API_URL + '/x/' + id)"), 1)
  assert.equal(flagged(component, 'const base = API_URL\nfetch(`${base}/x/${pathSegment(id)}`)'), 1)
  assert.equal(flagged(component, 'fetch(`${API_URL}/x/${pathSegment(a)}${id}`)'), 2)
  assert.equal(flagged(component, 'fetch(`${API_URL}/x/x-${id}`)'), 1)
  assert.equal(flagged(component, 'fetch(`${API_URL}/x/${pathSegment(a) + String(id)}`)'), 1)
  assert.equal(flagged(component, 'fetch(`${API_URL}/x?target=${target}`)'), 1)
  assert.equal(flagged(component, 'fetch(`${API_URL}/x${suffix}`)'), 1)
  assert.equal(flagged(component, 'fetch(`${API_URL}/x${queryString(search)}`)'), 0)
  assert.equal(flagged(component, 'fetch(`${API_URL}/x${queryString(search)}/${id}`)'), 2)
  assert.equal(flagged(component, 'const u = { base: getApiUrl() }'), 1)
  assert.equal(flagged(component, 'fetch(`${API_URL}/findings/${pathSegment(f.id)}?${new URLSearchParams({ a: b })}`)'), 0)
  assert.equal(flagged(component, 'fetch(`${API_URL}/x?limit=${encodeURIComponent(limit)}&on=${on ? \'true\' : \'false\'}`)'), 0)
  assert.equal(flagged(component, '<Link href={`/targets/${encodeURIComponent(id)}/asset`}>don\'t</Link>'), 0)  // a UI link
})

test('queryString takes only URLSearchParams', () => {
  assert.equal(queryString(new URLSearchParams()), '')
  assert.equal(queryString(new URLSearchParams({ target: 'a&b=c', limit: '5' })), '?target=a%26b%3Dc&limit=5')
  assert.throws(() => queryString('target=x'), /URLSearchParams/)
})
