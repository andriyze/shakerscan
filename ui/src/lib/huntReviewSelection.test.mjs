import assert from 'node:assert/strict'
import test from 'node:test'
import { readFileSync } from 'node:fs'
import ts from 'typescript'

const source = readFileSync(new URL('./huntReviewModel.ts', import.meta.url), 'utf8')
const { outputText } = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.ESNext } })
const { reconcileReviewSelection } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString('base64')}`)

test('history replacement removes a selection from a discarded page', () => {
  assert.equal(reconcileReviewSelection('later-page', ['first-page']), 'first-page')
})
test('empty history clears selection', () => {
  assert.equal(reconcileReviewSelection('old', []), '')
})
test('refresh retains an existing visible selection', () => {
  assert.equal(reconcileReviewSelection('second', ['first', 'second']), 'second')
})
test('appending history preserves a later-page selection', () => {
  assert.equal(reconcileReviewSelection('second', ['first', 'second', 'third']), 'second')
})
