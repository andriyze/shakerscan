/**
 * Filter state read from the address bar. The query string is attacker-controlled (anyone can
 * send a link), so its names never become property writes on an ordinary object: "__proto__"
 * would reach the prototype setter and "constructor"/"prototype" would shadow built-ins that
 * other code reads. Those names are dropped, and the rest are collected as own data properties
 * (Object.fromEntries and spread define properties; they never call a setter).
 */
const RESERVED_NAMES = new Set(['__proto__', 'constructor', 'prototype'])

export function isFilterName(name) {
  return typeof name === 'string' && name !== '' && !RESERVED_NAMES.has(name)
}

export function parseFilterParams(searchParams, defaults = {}) {
  const entries = []
  for (const [key, value] of searchParams) {
    if (!isFilterName(key)) continue
    if (key === 'page') {
      // Page is 1-based; treat 0 and invalid values as page 1 for backwards compatibility
      const parsed = parseInt(value, 10)
      entries.push([key, parsed >= 1 ? parsed : 1])
    } else {
      entries.push([key, value])
    }
  }
  return { ...defaults, ...Object.fromEntries(entries) }
}

export function parseReturnParams(searchParams) {
  const entries = []
  for (const [key, value] of searchParams) {
    if (!key.startsWith('return_')) continue
    const name = key.replace('return_', '')
    if (isFilterName(name)) entries.push([name, value])
  }
  return Object.fromEntries(entries)
}
