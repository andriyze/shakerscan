// Property-based fuzzing of the hand-written check-request grammar against JSON.parse.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { parseCheckRequest } from '../src/request.ts';
import { PublicError } from '../src/response.ts';
import { runs } from './helpers.ts';

const selector = fc.stringMatching(/^[a-zA-Z0-9](?:[a-zA-Z0-9_-]{0,20}[a-zA-Z0-9])?$/);
const path = fc.array(fc.stringMatching(/^[a-zA-Z0-9_~.-]{1,10}$/).filter(s => s !== '.' && s !== '..'), { maxLength: 5 })
  .chain(segments => fc.constantFrom(`/${segments.join('/')}`, `/${segments.join('/')}/`)).filter(p => !p.includes('//'));
const whitespace = fc.stringMatching(/^[ \t\r\n]{0,3}$/);
/** A JSON string literal with an arbitrary choice of \u escapes. */
const literal = (value: string, escapes: boolean[]) => `"${value.split('').map((ch, i) => escapes[i % Math.max(1, escapes.length)] ?
  `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}` : JSON.stringify(ch).slice(1, -1)).join('')}"`;
const request = fc.record({
  target: fc.oneof(fc.string({ unit: 'binary', maxLength: 60 }), fc.domain()),
  dkim_selector: fc.option(selector, { nil: undefined }), path: fc.option(path, { nil: undefined }),
  order: fc.array(fc.nat(), { minLength: 3, maxLength: 3 }), gaps: fc.array(whitespace, { minLength: 16, maxLength: 16 }),
  escapes: fc.array(fc.boolean(), { maxLength: 8 })
});
type Request = typeof request extends fc.Arbitrary<infer T> ? T : never;
function serialize(r: Request): string {
  const entries = ([['target', r.target], ['dkim_selector', r.dkim_selector], ['path', r.path]] as const)
    .map((entry, i) => [entry, r.order[i]!] as const).filter(([[, v]]) => v !== undefined).sort((a, b) => a[1] - b[1]).map(([entry]) => entry);
  let gap = 0;
  const ws = () => r.gaps[gap++ % r.gaps.length]!;
  return `${ws()}{${entries.map(([k, v]) => `${ws()}${literal(k, r.escapes)}${ws()}:${ws()}${literal(v!, r.escapes)}${ws()}`).join(',')}}${ws()}`;
}

test('fuzz: serialized requests parse back to the same fields', () => {
  fc.assert(fc.property(request, r => {
    assert.deepEqual(parseCheckRequest(serialize(r), true, true), { target: r.target,
      ...(r.dkim_selector === undefined ? {} : { dkim_selector: r.dkim_selector.toLowerCase() }), ...(r.path === undefined ? {} : { path: r.path }) });
  }), { numRuns: runs(5000) });
});

test('fuzz: the request grammar accepts only what JSON.parse reads the same way', () => {
  const token = fc.constantFrom('{', '}', '"', ':', ',', ' ', '\\', '\\"', '\\u0067', '\\ud800', 'target', '"target"', '"dkim_selector"', '"path"',
    '"example.com"', '"/a"', '"Mail"', '"\\u0000"', '\n', '\u2028', '\ufeff', 'null', '[', ']', '1', 'x', '"__proto__"', '"constructor"');
  const text = fc.oneof(
    fc.string({ unit: 'binary', maxLength: 80 }),
    fc.json(),
    fc.array(token, { maxLength: 25 }).map(parts => parts.join('')),
    { weight: 2, arbitrary: request.map(serialize) },
    // Valid requests with one character replaced, inserted or removed.
    { weight: 3, arbitrary: fc.tuple(request, fc.nat(), fc.constantFrom('', '"', '\\', ',', '}', '{', ':', ' ', 'x', '\u0000')).map(([r, at, ch]) => {
      const s = serialize(r), i = at % (s.length + 1);
      return at % 3 === 0 ? s.slice(0, i) + ch + s.slice(i + 1) : at % 3 === 1 ? s.slice(0, i) + ch + s.slice(i) : s.slice(0, i) + s.slice(i + 1);
    }) });
  fc.assert(fc.property(text, fc.boolean(), fc.boolean(), (input, allowSelector, allowPath) => {
    let parsed: ReturnType<typeof parseCheckRequest>;
    try { parsed = parseCheckRequest(input, allowSelector, allowPath); }
    catch (error) { assert.ok(error instanceof PublicError && error.code === 'invalid_request', `unexpected ${String(error)}`); return; }
    const json = JSON.parse(input) as Record<string, unknown>;
    assert.ok(json && typeof json === 'object' && !Array.isArray(json));
    const allowed = ['target', ...(allowSelector ? ['dkim_selector'] : []), ...(allowPath ? ['path'] : [])];
    assert.ok(Object.keys(json).every(key => allowed.includes(key) && typeof json[key] === 'string'), input);
    assert.equal(parsed.target, json.target);
    assert.equal(parsed.dkim_selector, (json.dkim_selector as string | undefined)?.toLowerCase());
    assert.equal(parsed.path, json.path);
    if (parsed.dkim_selector !== undefined) assert.match(parsed.dkim_selector, /^[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?$/);
    if (parsed.path !== undefined) assert.ok(parsed.path.length <= 256 && parsed.path.startsWith('/') && !parsed.path.includes('//') && !/(?:^|\/)\.\.?(?:\/|$)/.test(parsed.path));
  }), { numRuns: runs(5000) });
});
