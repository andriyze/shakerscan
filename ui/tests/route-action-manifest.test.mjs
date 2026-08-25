import assert from 'node:assert/strict'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const manifest = JSON.parse(readFileSync(path.join(root, 'test-manifests/ui-route-action-manifest.json'), 'utf8'))

function pageSources(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const resolved = path.join(directory, entry.name)
    if (entry.isDirectory()) return pageSources(resolved)
    if (entry.isFile() && entry.name === 'page.tsx') {
      return [path.relative(root, resolved).split(path.sep).join('/')]
    }
    return []
  })
}

test('route manifest covers every App Router page with an owned state assertion', () => {
  assert.equal(manifest.schemaVersion, 'ui-route-action-manifest/v1')
  const actual = pageSources(path.join(root, 'src/app')).sort()
  const declared = manifest.routes.map((entry) => entry.source).sort()
  assert.deepEqual(declared, actual)
  assert.equal(new Set(manifest.routes.map((entry) => entry.route)).size, manifest.routes.length)
  for (const route of manifest.routes) {
    assert.match(route.route, /^\//)
    assert.ok(route.owner?.trim(), `${route.route} has no owner`)
    assert.match(route.caseId, /^[A-Z]+-\d{3}$/)
    assert.ok(route.stateAssertion?.trim().length > 20, `${route.route} has no meaningful state assertion`)
    if (route.smokePath) assert.match(route.smokePath, /^\//)
  }
})

test('every internal sidebar destination is represented in the route manifest', () => {
  const sidebar = readFileSync(path.join(root, 'src/components/Sidebar.tsx'), 'utf8')
  const hrefs = [...sidebar.matchAll(/href(?:=|:)\s*["']([^"']+)["']/g)]
    .map((match) => match[1])
    .filter((href) => href.startsWith('/'))
  const routes = new Set(manifest.routes.map((entry) => entry.route))
  for (const href of hrefs) assert.ok(routes.has(href), `sidebar route ${href} is not declared`)
})

test('all 38 audited work-start paths retain a source marker and outcome assertion', () => {
  const expected = Array.from({ length: 38 }, (_, index) => `START-${String(index + 1).padStart(3, '0')}`)
  assert.deepEqual(manifest.workActions.map((entry) => entry.caseId).sort(), expected)
  for (const action of manifest.workActions) {
    const sourcePath = path.join(root, action.source)
    assert.ok(existsSync(sourcePath), `${action.caseId} source is missing: ${action.source}`)
    const source = readFileSync(sourcePath, 'utf8')
    assert.ok(source.includes(action.marker), `${action.caseId} marker drifted: ${action.marker}`)
    assert.ok(action.assertion?.trim().length > 20, `${action.caseId} has no meaningful outcome assertion`)
    assert.ok(manifest.routes.some((route) => route.route === action.route), `${action.caseId} route is undeclared`)
  }
})
