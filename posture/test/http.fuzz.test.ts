// Property-based fuzzing of HTTP response handling: header parsing, redirect classification
// and the header/CORS evidence derived from a target's responses.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { CORS_PROBE_ORIGIN, corsCheck, headerCheck } from '../src/checks/policy.ts';
import { parseHead, redirectKind, type Head } from '../src/http.ts';
import { cacheAccepts, runs } from './helpers.ts';

const POSTURE = ['location', 'strict-transport-security', 'content-security-policy', 'x-content-type-options', 'referrer-policy',
  'permissions-policy', 'access-control-allow-origin', 'access-control-allow-credentials'];
const OTHER = ['x-frame-options', 'cross-origin-opener-policy', 'cross-origin-resource-policy', 'access-control-allow-methods', 'vary', 'server', 'x-custom'];
const token = fc.oneof(fc.constantFrom(...POSTURE, ...OTHER), fc.stringMatching(/^[!#$%&'*+.^_`|~0-9a-zA-Z-]{1,12}$/));
// Header values as a server may send them: printable ASCII and tabs, plus policy-shaped values.
const value = fc.oneof(
  fc.string({ unit: fc.oneof(fc.integer({ min: 0x20, max: 0x7e }).map(c => String.fromCharCode(c)), fc.constant('\t')), maxLength: 40 }),
  fc.array(fc.constantFrom('max-age=31536000', 'max-age="0"', 'max-age=99999999999999999999', 'includeSubDomains', 'preload', "script-src 'self'", "default-src *",
    "'unsafe-inline'", "'unsafe-eval'", "'nonce-abc'", "'sha256-x'", "'strict-dynamic'", 'http:', 'object-src none', 'frame-ancestors https://a.example',
    'nosniff', 'no-referrer-when-downgrade', 'DENY', CORS_PROBE_ORIGIN, '*', 'true', 'origin', 'GET, POST', ';', ' ', '\t', ','), { maxLength: 12 }).map(p => p.join('')),
  // Around the 4096-character value limit.
  fc.tuple(fc.stringMatching(/^[\x20-\x7e\t]{1,8}$/), fc.integer({ min: 4090, max: 4100 })).map(([s, n]) => s.repeat(Math.ceil(n / s.length)).slice(0, n)));
const headers = fc.array(fc.tuple(fc.mixedCase(token), fc.constantFrom(':', ': ', ':\t', ':  '), value), { maxLength: 12 });
const statusLine = fc.oneof(fc.integer({ min: 200, max: 599 }).map(s => `HTTP/1.1 ${s} OK`), fc.constantFrom('HTTP/1.0 302', 'HTTP/1.1 199 x', 'HTTP/2 200', 'HTTP/1.1 600'));
const rawHead = fc.tuple(statusLine, headers).map(([status, list]) => [status, ...list.map(([k, sep, v]) => `${k}${sep}${v}`)].join('\r\n'));

test('fuzz: parsed heads keep the status, first values and duplicate-header refusal', () => {
  fc.assert(fc.property(fc.integer({ min: 200, max: 599 }), fc.stringMatching(/^[\x20-\x7e]{0,20}$/), headers, (status, reason, list) => {
    const text = [`HTTP/1.1 ${status}${reason ? ` ${reason}` : ''}`, ...list.map(([k, sep, v]) => `${k}${sep}${v}`)].join('\r\n');
    const expected = new Map<string, string>();
    let duplicate = false, oversized = false;
    for (const [k, , v] of list) {
      const key = k.toLowerCase();
      if (v.replace(/^[ \t]+/, '').length > 4096) oversized = true;
      if (expected.has(key)) duplicate ||= POSTURE.includes(key);
      else expected.set(key, v.trim());
    }
    if (text.length > 16384 || oversized || duplicate) { assert.throws(() => parseHead(text)); return; }
    assert.deepEqual(parseHead(text), { status, headers: expected });
  }), { numRuns: runs(4000) });
});

test('fuzz: header parsing refuses or yields bounded fields for any input', () => {
  const text = fc.oneof(rawHead, fc.string({ unit: 'binary-ascii', maxLength: 200 }), fc.tuple(rawHead, fc.nat(), fc.constantFrom('\r', '\n', '\r\n', '\0', '\u0080', ':', ' ')).map(([s, at, ch]) => {
    const i = at % (s.length + 1); return s.slice(0, i) + ch + s.slice(i);
  }));
  fc.assert(fc.property(text, input => {
    let head: Head;
    try { head = parseHead(input); }
    catch (error) { assert.ok(error instanceof Error && ['Invalid headers', 'Invalid status', 'Invalid header', 'Duplicate posture header'].includes(error.message)); return; }
    assert.ok(Number.isInteger(head.status) && head.status >= 200 && head.status <= 599);
    assert.ok(head.headers.size <= 100);
    for (const [key, v] of head.headers) assert.ok(/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(key) && v.length <= 4096 && v === v.trim() && !/[\r\n]/.test(v), key);
  }), { numRuns: runs(4000) });
});

// Redirect targets assembled from the parts that differ between URL parsers and naive checks.
const location = fc.oneof(
  fc.tuple(fc.constantFrom('', 'http:', 'https:', 'HTTPS:', 'hTtP:', 'ftp:', 'javascript:', 'data:'), fc.constantFrom('', '/', '//', '///', '/\\'),
    fc.constantFrom('', 'user@', 'user:pass@', ':@', '@'),
    fc.constantFrom('example.com', 'EXAMPLE.com', 'example.com.', 'www.example.com', 'example.com.evil.net', 'evil.net', 'ｅｘａｍｐｌｅ.com', 'ex\u0430mple.com',
      '93.184.216.34', '0x5db8d822', '93.184.216.034', '[::1]', '127.0.0.1', 'localhost', '%65xample.com', 'example%2ecom', ''),
    fc.constantFrom('', ':', ':443', ':80', ':8443', ':0', ':0443', ':65536'), fc.constantFrom('', '/', '/login', '?q=1', '#f', '/a/../b'))
    .map(parts => parts.join('')),
  fc.webUrl({ withQueryParameters: true, withFragments: true }),
  fc.string({ unit: 'binary-ascii', maxLength: 40 }));

for (const host of ['example.com', '93.184.216.34']) {
  test(`fuzz: a same-host redirect classification matches where the URL really points (${host})`, () => {
    fc.assert(fc.property(location, fc.boolean(), (target, https) => {
      const kind = redirectKind(target, host, https);
      assert.ok(['missing', 'refused', 'same_host_http', 'same_host_https'].includes(kind));
      if (!kind.startsWith('same_host')) return;
      const url = new URL(target, `${https ? 'https' : 'http'}://${host}/`);
      assert.equal(url.protocol, kind === 'same_host_https' ? 'https:' : 'http:', target);
      assert.equal(url.username + url.password, '', target);
      assert.equal(url.port, '', target);
      assert.equal(url.hostname.replace(/\.$/, ''), host, target);
    }), { numRuns: runs(5000) });
  });
}

test('regressions found by fuzzing redirects and header evidence', () => {
  // Ports in spellings without '//' were missed and classified as same-host.
  assert.equal(redirectKind('http:example.com:0', 'example.com', true), 'refused');
  assert.equal(redirectKind('https:example.com:8443/', 'example.com', false), 'refused');
  assert.equal(redirectKind('///example.com:8443/', 'example.com', false), 'refused');
  assert.equal(redirectKind('///0x5db8d822:8443', '93.184.216.34', false), 'refused');
  assert.equal(redirectKind('https:example.com/login', 'example.com', false), 'same_host_https');
  // A tab inside a header value reached the evidence, which the cached schema refuses.
  const head = parseHead('HTTP/1.1 200 OK\r\nX-Frame-Options: DENY\tx\r\nAccess-Control-Allow-Methods: GET,\tPOST');
  assert.equal(headerCheck(head).evidence!.x_frame_options, 'deny x');
  assert.ok(cacheAccepts(headerCheck(head)));
  assert.equal(corsCheck(head, '/', head).evidence!.preflight_methods, 'GET, POST');
  assert.ok(cacheAccepts(corsCheck(head, '/', head)));
});

test('fuzz: header and CORS evidence from any parsed response is bounded and cacheable', () => {
  const path = fc.constantFrom('/', '/api', '/a/b~c_d.e-f');
  fc.assert(fc.property(rawHead, fc.option(rawHead), path, (text, preflightText, corsPath) => {
    let head: Head, preflight: Head | undefined;
    try { head = parseHead(text); preflight = preflightText === null ? undefined : parseHead(preflightText); } catch { return; }
    const headersCheck = headerCheck(head), cors = corsCheck(head, corsPath, preflight);
    assert.ok(['pass', 'warn'].includes(headersCheck.status) && ['pass', 'warn', 'unknown'].includes(cors.status));
    assert.ok(cacheAccepts(headersCheck), JSON.stringify(headersCheck.evidence));
    assert.ok(cacheAccepts(cors), JSON.stringify(cors.evidence));
  }), { numRuns: runs(5000) });
});
