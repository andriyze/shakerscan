import assert from 'node:assert/strict'
import test from 'node:test'

import {
  TARGET_LINK_MAX_PAGES, TARGET_SEARCH_MAX_PAGES, collectAcceptedTargets, resolveTargetByOrigin, targetSearchNoteText,
  targetSearchProvesEmpty,
} from './targetSearchModel.mjs'

const row = (id, url) => ({ id, url })
/** An inventory whose rows come in pages of `size`, positions by index. */
function inventory(rows, size) {
  const reads = []
  return {
    reads,
    fetchPage: async (position) => {
      const start = position ?? 0
      reads.push(start)
      const targets = rows.slice(start, start + size)
      const next = start + size < rows.length ? start + size : null
      return { targets, hasMore: next !== null, next }
    },
  }
}
const web = (asset) => asset.url.startsWith('https://')

// Review: pickers filtered one page of 25 matches in the browser, so a page of hosts read as "no
// targets" (and hid the search box) while web targets existed further on.
test('a filter that rejects a whole page reads on until it finds choices', async () => {
  const rows = [...Array.from({ length: 30 }, (_, i) => row(`h${i}`, `host://h${i}`)), row('w1', 'https://a.test'), row('w2', 'https://b.test')]
  const source = inventory(rows, 25)
  const result = await collectAcceptedTargets({ fetchPage: source.fetchPage, accept: web, limit: 25 })
  assert.deepEqual(result.matches.map((asset) => asset.id), ['w1', 'w2'])
  assert.deepEqual(source.reads, [0, 25])
  assert.equal(result.hasMore, false)
  assert.equal(result.scanned, 32)
})

test('reading on is bounded and then says how far it looked, never "none exist"', async () => {
  const rows = Array.from({ length: 1000 }, (_, i) => row(`h${i}`, `host://h${i}`))
  const source = inventory(rows, 25)
  const result = await collectAcceptedTargets({ fetchPage: source.fetchPage, accept: web, limit: 25 })
  assert.equal(source.reads.length, TARGET_SEARCH_MAX_PAGES)
  assert.equal(result.matches.length, 0)
  assert.equal(result.hasMore, true)
  const note = targetSearchNoteText({ assets: result.matches, hasMore: result.hasMore, error: null, query: '', scanned: result.scanned, filtered: true })
  assert.equal(note, 'No matches on the first 100 targets searched; type to narrow')
  assert.equal(targetSearchProvesEmpty({ ready: true, loading: false, error: null, query: '', hasMore: result.hasMore, assets: result.matches }), false)
})

test('without a filter one page is read; a full page stops the reading', async () => {
  const source = inventory(Array.from({ length: 60 }, (_, i) => row(`w${i}`, `https://w${i}.test`)), 25)
  const result = await collectAcceptedTargets({ fetchPage: source.fetchPage, limit: 25 })
  assert.deepEqual(source.reads, [0])
  assert.equal(result.matches.length, 25)
  assert.equal(result.hasMore, true)
  assert.equal(result.filtered, false)
})

test('only a complete answer to an empty query proves there is nothing to choose', () => {
  const base = { ready: true, loading: false, error: null, query: '', hasMore: false, assets: [] }
  assert.equal(targetSearchProvesEmpty(base), true)
  assert.equal(targetSearchProvesEmpty({ ...base, query: 'shop' }), false, 'a typed query keeps the search box')
  assert.equal(targetSearchProvesEmpty({ ...base, loading: true }), false)
  assert.equal(targetSearchProvesEmpty({ ...base, error: 'down' }), false)
  assert.equal(targetSearchProvesEmpty({ ...base, ready: false }), false)
  assert.equal(targetSearchProvesEmpty({ ...base, hasMore: true }), false)
})

test('notes', () => {
  const n = (over) => targetSearchNoteText({ assets: [], hasMore: false, error: null, query: '', ...over })
  assert.equal(n({ error: 'busy' }), 'Search failed: busy')
  assert.equal(n({ assets: [1, 2], hasMore: true }), 'Showing the first 2 matches; type to narrow')
  assert.equal(n({ query: 'x', filtered: true }), 'No matching target of this kind')
  assert.equal(n({}), 'No targets yet')
  assert.equal(n({ assets: [1] }), '1 match')
})

// Review (2.11): a ?target=URL link read one search page for its host and reported "not found"
// whenever the exact origin sorted after the first page of substring matches (an apex domain with
// many discovered subdomains), although the target existed.
const subdomains = (count) => Array.from({ length: count }, (_, i) => row(`s${i}`, `https://app${i}.corp.example`))
/** list/v1-style pages: cursors are opaque strings, `null` asks for the first page. */
function cursorInventory(rows, size) {
  const reads = []
  return {
    reads,
    fetchPage: async (position) => {
      reads.push(position)
      const start = position === null ? 0 : Number(String(position).slice(1))
      const targets = rows.slice(start, start + size)
      const hasMore = start + size < rows.length
      return { targets, hasMore, next: hasMore ? `c${start + size}` : null }
    },
  }
}

test('a link resolves on the first page without reading further', async () => {
  const source = cursorInventory([row('exact', 'https://corp.example'), ...subdomains(300)], 200)
  const result = await resolveTargetByOrigin({ fetchPage: source.fetchPage, url: 'https://corp.example/' })
  assert.equal(result.status, 'found')
  assert.equal(result.target.id, 'exact')
  assert.deepEqual(source.reads, [null])
})

test('a link whose origin sorts after the first page reads on with the cursor until it is found', async () => {
  const source = cursorInventory([...subdomains(300), row('exact', 'https://corp.example'), ...subdomains(50)], 200)
  const result = await resolveTargetByOrigin({ fetchPage: source.fetchPage, url: 'https://corp.example/' })
  assert.equal(result.status, 'found')
  assert.equal(result.target.id, 'exact')
  assert.deepEqual(source.reads, [null, 'c200'], 'the second read continues from the first page\'s cursor')
})

test('the same host on another port or scheme is a different origin and never matches', async () => {
  const decoys = [row('port', 'https://corp.example:8443'), row('scheme', 'http://corp.example'), row('host', 'host://corp.example')]
  const source = cursorInventory([...decoys, ...subdomains(10)], 200)
  const result = await resolveTargetByOrigin({ fetchPage: source.fetchPage, url: 'https://corp.example/' })
  assert.equal(result.status, 'missing')
  assert.equal(result.target, null)
  const port = await resolveTargetByOrigin({ fetchPage: cursorInventory(decoys, 200).fetchPage, url: 'https://corp.example:8443/path' })
  assert.equal(port.target?.id, 'port', 'an explicit port names its own origin')
})

test('"missing" only after every matching page was read', async () => {
  const source = cursorInventory(subdomains(450), 200)
  const result = await resolveTargetByOrigin({ fetchPage: source.fetchPage, url: 'https://corp.example/' })
  assert.equal(result.status, 'missing')
  assert.deepEqual(source.reads, [null, 'c200', 'c400'])
})

test('reaching the page bound with more pages left is "unconfirmed", never "missing"', async () => {
  const source = cursorInventory(subdomains(5000), 200)
  const result = await resolveTargetByOrigin({ fetchPage: source.fetchPage, url: 'https://corp.example/' })
  assert.equal(result.status, 'unconfirmed')
  assert.equal(result.target, null)
  assert.equal(source.reads.length, TARGET_LINK_MAX_PAGES)
  assert.equal(result.scanned, TARGET_LINK_MAX_PAGES * 200)
})

test('an abort between pages stops further requests', async () => {
  const controller = new AbortController()
  const source = cursorInventory(subdomains(1000), 200)
  const fetchPage = async (position) => {
    const page = await source.fetchPage(position)
    controller.abort()
    return page
  }
  await assert.rejects(
    resolveTargetByOrigin({ fetchPage, url: 'https://corp.example/', signal: controller.signal }),
    (error) => error.name === 'AbortError',
  )
  assert.deepEqual(source.reads, [null])
})

test('a link that is not an http(s) URL is missing without a search', async () => {
  const source = cursorInventory(subdomains(10), 200)
  for (const url of ['host://corp.example', 'not a url', '']) {
    const result = await resolveTargetByOrigin({ fetchPage: source.fetchPage, url })
    assert.equal(result.status, 'missing', url)
  }
  assert.deepEqual(source.reads, [])
})
