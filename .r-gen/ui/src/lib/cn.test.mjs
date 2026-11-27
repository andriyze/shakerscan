import test from 'node:test'
import assert from 'node:assert/strict'
import { cn } from './cn.ts'

test('cn joins truthy class strings with single spaces', () => {
  assert.equal(cn('a', 'b', 'c'), 'a b c')
})

test('cn drops falsy entries (false, null, undefined, empty)', () => {
  assert.equal(cn('a', false, null, undefined, '', 'b'), 'a b')
})

test('cn returns empty string when nothing is truthy', () => {
  assert.equal(cn(false, null, undefined), '')
})

test('cn supports the conditional-class idiom', () => {
  const active = true
  const error = false
  assert.equal(cn('base', active && 'ring-2', error && 'border-red-500'), 'base ring-2')
})
