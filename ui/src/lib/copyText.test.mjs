import test from 'node:test'
import assert from 'node:assert/strict'
import { asyncClipboardUsable, copyText, findingLink, legacyCopy } from './copyText.ts'

// Unit fixture: a fake browser surface, not a real DOM.
function fakeEnv({ secure = true, clipboard = 'ok', execResult = true, execThrows = false } = {}) {
  const calls = { writeText: [], exec: [], appended: 0, removed: 0, focused: [], scrolledTo: null, ranges: null }
  const previous = { focus: (opts) => calls.focused.push(['previous', opts]) }
  const savedRange = { id: 'user-range' }
  const selection = {
    rangeCount: 1,
    getRangeAt: () => savedRange,
    removeAllRanges() { calls.ranges = [] },
    addRange(range) { calls.ranges.push(range) },
  }
  const win = {
    isSecureContext: secure,
    scrollX: 0,
    scrollY: 400,
    scrollTo(x, y) { calls.scrolledTo = [x, y] },
    getSelection: () => selection,
  }
  const doc = {
    activeElement: previous,
    body: {
      appendChild() { calls.appended += 1; win.scrollY = 0 },
    },
    createElement() {
      return {
        value: '',
        style: {},
        attrs: {},
        setAttribute(name, value) { this.attrs[name] = value },
        focus(opts) { calls.focused.push(['textarea', opts]) },
        select() {},
        setSelectionRange() {},
        remove() { calls.removed += 1 },
      }
    },
    execCommand(command) {
      calls.exec.push(command)
      if (execThrows) throw new Error('blocked')
      return execResult
    },
  }
  let nav = {}
  if (clipboard === 'ok') nav = { clipboard: { writeText: async (text) => { calls.writeText.push(text) } } }
  if (clipboard === 'reject') nav = { clipboard: { writeText: async () => { throw new Error('NotAllowedError') } } }
  return { env: { window: win, navigator: nav, document: doc }, calls }
}

test('secure context with a clipboard uses navigator.clipboard and skips the fallback', async () => {
  const { env, calls } = fakeEnv()
  assert.equal(asyncClipboardUsable(env), true)
  const result = await copyText('http://10.0.0.5/findings/abc', env)
  assert.deepEqual(result, { ok: true, method: 'clipboard' })
  assert.deepEqual(calls.writeText, ['http://10.0.0.5/findings/abc'])
  assert.equal(calls.exec.length, 0)
})

test('insecure context (no navigator.clipboard) falls back to execCommand copy', async () => {
  const { env, calls } = fakeEnv({ secure: false, clipboard: 'none' })
  assert.equal(asyncClipboardUsable(env), false)
  const result = await copyText('link', env)
  assert.deepEqual(result, { ok: true, method: 'execCommand' })
  assert.deepEqual(calls.exec, ['copy'])
  assert.equal(calls.appended, 1)
  assert.equal(calls.removed, 1, 'temporary textarea is removed')
})

test('a clipboard object present in an insecure context is not trusted', async () => {
  const { env, calls } = fakeEnv({ secure: false, clipboard: 'ok' })
  const result = await copyText('link', env)
  assert.equal(result.ok, true)
  assert.equal(result.method, 'execCommand')
  assert.equal(calls.writeText.length, 0)
})

test('a rejected clipboard write falls back to execCommand', async () => {
  const { env, calls } = fakeEnv({ clipboard: 'reject' })
  const result = await copyText('link', env)
  assert.deepEqual(result, { ok: true, method: 'execCommand' })
  assert.deepEqual(calls.exec, ['copy'])
})

test('fallback restores focus, selection and scroll position', () => {
  const { env, calls } = fakeEnv({ secure: false, clipboard: 'none' })
  assert.equal(legacyCopy('x', env), true)
  assert.deepEqual(calls.focused, [['textarea', { preventScroll: true }], ['previous', { preventScroll: true }]])
  assert.deepEqual(calls.ranges, [{ id: 'user-range' }])
  assert.deepEqual(calls.scrolledTo, [0, 400])
})

test('both paths failing returns a visible-fallback result with the text, never throws', async () => {
  const { env } = fakeEnv({ clipboard: 'reject', execResult: false })
  const result = await copyText('the text', env)
  assert.equal(result.ok, false)
  assert.equal(result.text, 'the text')
  assert.match(result.reason, /NotAllowedError/)
})

test('execCommand throwing is a failure result, and the textarea is still removed', async () => {
  const { env, calls } = fakeEnv({ secure: false, clipboard: 'none', execThrows: true })
  const result = await copyText('t', env)
  assert.equal(result.ok, false)
  assert.equal(calls.removed, 1)
})

test('no document at all (server render) is a failure result', async () => {
  const result = await copyText('t', { window: { isSecureContext: false }, navigator: {} })
  assert.equal(result.ok, false)
})

test('findingLink builds an absolute finding URL on the given origin', () => {
  assert.equal(findingLink('abc-123', 'http://192.168.1.20:3000'), 'http://192.168.1.20:3000/findings/abc-123')
  assert.equal(findingLink('a/b', 'https://gw.example'), 'https://gw.example/findings/a%2Fb')
})

test('no UI source calls navigator.clipboard directly; everything goes through copyText', async () => {
  const fs = await import('node:fs')
  const path = await import('node:path')
  const root = path.resolve(import.meta.dirname, '..')
  const offenders = []
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name)
      if (entry.isDirectory()) walk(full)
      else if (/\.(tsx?|mjs)$/.test(entry.name) && !/\.test\.mjs$/.test(entry.name) && !full.endsWith(path.join('lib', 'copyText.ts'))) {
        if (/navigator\??\.clipboard|execCommand\(/.test(fs.readFileSync(full, 'utf8'))) offenders.push(path.relative(root, full))
      }
    }
  }
  walk(root)
  assert.deepEqual(offenders, [])
})
