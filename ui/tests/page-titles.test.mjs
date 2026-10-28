import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { createRequire } from 'node:module'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { editionTitle, PRODUCT_NAME, productEdition, TITLE_SEPARATOR, TITLE_TEMPLATE } from '../src/lib/pageTitle.ts'

// Next.js's own title resolver (the function its metadata merge calls for every segment), so this
// test resolves a route's title the way the server does.
const { resolveTitle } = createRequire(import.meta.url)('next/dist/lib/metadata/resolvers/resolve-title.js')

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const app = path.join(root, 'src/app')
const read = (file) => readFileSync(file, 'utf8')
const readIfAny = (file) => {
  try {
    return read(file)
  } catch {
    return undefined
  }
}

// The title a layout or page source declares, as the value Next.js receives: segmentTitle(name)
// (a default plus the template for child segments), rootPageTitle(name) (a full title) or a plain
// string (which passes no template on).
function declaredTitle(source) {
  if (source === undefined) return undefined
  const helper = source.match(/export const metadata: Metadata = (segmentTitle|rootPageTitle)\('([^']+)'\)/)
  if (helper?.[1] === 'segmentTitle') return { default: helper[2], template: TITLE_TEMPLATE }
  if (helper?.[1] === 'rootPageTitle') return { absolute: `${helper[2]}${TITLE_SEPARATOR}${PRODUCT_NAME}` }
  return source.match(/export const metadata: Metadata = \{ title: '([^']+)' \}/)?.[1]
}

const ROOT_TITLE = { template: TITLE_TEMPLATE, default: PRODUCT_NAME }

// What Next.js 16 does with one metadata item per segment, root layout first and the page last
// (accumulateMetadata in next/dist/lib/metadata/resolve-metadata.js): each title is resolved
// against the template stashed so far, and the stash is refreshed after every item except the
// last two, so a layout's template never reaches a page of its own segment.
function resolveRouteTitle(items) {
  let template = null
  let resolved
  items.forEach((title, index) => {
    if (title !== undefined) resolved = resolveTitle(title, template)
    if (index < items.length - 2) template = resolved?.template || null
  })
  return resolved?.absolute
}

function pages(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const resolved = path.join(directory, entry.name)
    if (entry.isDirectory()) return pages(resolved)
    return entry.name === 'page.tsx' ? [resolved] : []
  })
}

// The metadata items of a page's route: the root layout, every segment directory down to the
// page (its layout, or nothing), then the page.
function routeItems(page) {
  const segments = path.relative(app, path.dirname(page)).split(path.sep).filter(Boolean)
  const items = [ROOT_TITLE]
  for (let depth = 1; depth <= segments.length; depth += 1) {
    items.push(declaredTitle(readIfAny(path.join(app, ...segments.slice(0, depth), 'layout.tsx'))))
  }
  items.push(declaredTitle(read(page)))
  return items
}

// A page that only redirects never renders, so it never shows a title of its own.
const redirectsOnly = (source) => /\bredirect\(/.test(source) && !/'use client'/.test(source) && !/return\s*[(<]/.test(source)

test('every rendered route, nested ones included, resolves to "Page · ShakerScan"', () => {
  const titles = new Map()
  for (const page of pages(app)) {
    if (redirectsOnly(read(page))) continue
    const route = `/${path.relative(app, path.dirname(page)).split(path.sep).join('/')}`.replace(/\/$/, '') || '/'
    titles.set(route, resolveRouteTitle(routeItems(page)))
  }
  const unnamed = [...titles].filter(([, title]) => !title?.endsWith(`${TITLE_SEPARATOR}${PRODUCT_NAME}`))
  assert.deepEqual(unnamed, [], 'name the page with `export const metadata: Metadata = segmentTitle(...)` in the page or its segment layout')

  assert.equal(titles.get('/'), 'Dashboard · ShakerScan')
  assert.equal(titles.get('/findings'), 'Findings · ShakerScan')
  assert.equal(titles.get('/findings/[id]'), 'Finding · ShakerScan')
  assert.equal(titles.get('/findings/candidates'), 'Investigation candidates · ShakerScan')
  assert.equal(titles.get('/scans/[id]'), 'Scan · ShakerScan')
  assert.equal(titles.get('/scan/new'), 'New scan · ShakerScan')
  assert.equal(titles.get('/deep-hunt/runs/[id]'), 'Autonomous run · ShakerScan')
  assert.equal(titles.get('/targets/[id]/graph'), 'Application graph · ShakerScan')
  assert.equal(titles.get('/settings/policy-profiles'), 'Policy profiles · ShakerScan')
  assert.equal(titles.get('/docs'), 'Docs · ShakerScan')
})

test('a layout title carries the template; a plain string would leave nested routes bare', () => {
  const plain = []
  for (const page of pages(app)) {
    for (let directory = path.dirname(page); directory.startsWith(app) && directory !== app; directory = path.dirname(directory)) {
      const file = path.join(directory, 'layout.tsx')
      if (typeof declaredTitle(readIfAny(file)) === 'string') plain.push(path.relative(app, file))
    }
  }
  assert.deepEqual([...new Set(plain)], [], 'use segmentTitle(...) in a layout')
  // Why: with a plain parent, Next.js resolves the child bare.
  assert.equal(resolveRouteTitle([ROOT_TITLE, 'Findings', 'Finding', undefined]), 'Finding')
  assert.equal(resolveRouteTitle([ROOT_TITLE, declaredTitle("export const metadata: Metadata = segmentTitle('Findings')"), 'Finding', undefined]), 'Finding · ShakerScan')
})

test('the root layout puts the page first and keeps the bare product name for unnamed pages', () => {
  const layout = read(path.join(app, 'layout.tsx'))
  assert.match(layout, /template: TITLE_TEMPLATE,/)
  assert.match(layout, /default: PRODUCT_NAME,/)
  assert.match(layout, /<EditionTitle \/>/)
  assert.equal(TITLE_TEMPLATE, '%s · ShakerScan')
  // A URL that matches no route renders the root layout alone: not "Dashboard · ShakerScan".
  assert.equal(resolveRouteTitle([ROOT_TITLE, undefined]), 'ShakerScan')
  // The dashboard page is a server component that names itself; its body is a client component.
  const home = read(path.join(app, 'page.tsx'))
  assert.doesNotMatch(home, /'use client'/)
  assert.match(home, /rootPageTitle\('Dashboard'\)/)
})

test('an edition label that names Enterprise extends the product name in the title', () => {
  assert.equal(productEdition(undefined), undefined)
  assert.equal(productEdition('Open Source Edition'), undefined)
  assert.equal(productEdition('Enterprise Edition'), 'Enterprise')
  assert.equal(productEdition('ShakerScan enterprise'), 'Enterprise')
  assert.equal(productEdition('Enterprises Ltd hosted'), undefined, 'a whole word only')

  assert.equal(editionTitle('Findings · ShakerScan', undefined), 'Findings · ShakerScan')
  assert.equal(editionTitle('Findings · ShakerScan', 'Enterprise'), 'Findings · ShakerScan Enterprise')
  assert.equal(editionTitle('ShakerScan', 'Enterprise'), 'ShakerScan Enterprise')
  assert.equal(editionTitle('Findings · ShakerScan Enterprise', 'Enterprise'), 'Findings · ShakerScan Enterprise', 'idempotent')
  assert.equal(editionTitle('404: This page could not be found.', 'Enterprise'), '404: This page could not be found.')
})
