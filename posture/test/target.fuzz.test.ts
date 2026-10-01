// Property-based fuzzing of the target and destination safety decisions: hostname normalization,
// IP-literal targets and the address policy. Each decision must hold for every equivalent
// spelling of a name or address, not only the canonical one.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isIP } from 'node:net';
import fc from 'fast-check';
import { parseIpTarget, reverseName } from '../src/checks/iptarget.ts';
import { isRestrictedTarget } from '../src/checks/restricted.ts';
import { PublicError } from '../src/response.ts';
import { configureTargetPolicy, isPublicAddress, type TargetPolicy } from '../src/safety.ts';
import { normalizeTarget } from '../src/target.ts';
import { encodeQuery } from '../src/wire.ts';
import { runs } from './helpers.ts';

const POLICIES: TargetPolicy[] = ['public', 'any'];
function under<T>(policy: TargetPolicy, run: () => T): T {
  configureTargetPolicy(policy);
  try { return run(); } finally { configureTargetPolicy('public'); }
}
/** The normalized target, or 'refused' when the engine rejects it with a public error. */
function outcome(run: () => string): string {
  try { return run(); }
  catch (error) {
    assert.ok(error instanceof PublicError && ['invalid_request', 'target_not_allowed'].includes(error.code), `unexpected ${String(error)}`);
    return 'refused';
  }
}

// IPv4 addresses as integers, biased to the edges of special-use blocks.
const BLOCKS: [string, number][] = [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4], ['8.8.8.0', 24]];
const toInt = (dotted: string) => dotted.split('.').reduce((n, part) => n * 256 + Number(part), 0);
const octets = (n: number) => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
const dotted = (n: number) => octets(n).join('.');
const v4 = fc.oneof(
  fc.integer({ min: 0, max: 0xffffffff }),
  fc.tuple(fc.constantFrom(...BLOCKS), fc.integer({ min: 0, max: 0xffffffff }), fc.integer({ min: -1, max: 1 })).map(([[base, prefix], host, edge]) => {
    const start = toInt(base), size = 2 ** (32 - prefix);
    return (2 ** 32 + (edge < 0 ? start - 1 : edge > 0 ? start + size : start + (host % size))) % 2 ** 32;
  }),
  fc.constantFrom(...['169.254.169.254', '127.0.0.1', '0.0.0.0', '255.255.255.255', '224.0.0.1', '1.1.1.1'].map(toInt)));

// Legacy numeric IPv4 spellings: one to four parts, the last covering the remaining bytes,
// each part decimal, octal or hexadecimal.
const v4Style = fc.record({ parts: fc.constantFrom(1, 2, 3, 4), radix: fc.array(fc.constantFrom('dec', 'oct', 'hex', 'HEX'), { minLength: 4, maxLength: 4 }),
  zeros: fc.array(fc.integer({ min: 0, max: 2 }), { minLength: 4, maxLength: 4 }) });
function spellV4(n: number, style: typeof v4Style extends fc.Arbitrary<infer T> ? T : never): string {
  const bytes = octets(n);
  const values = [...bytes.slice(0, style.parts - 1), bytes.slice(style.parts - 1).reduce((a, b) => a * 256 + b, 0)];
  return values.map((v, i) => style.radix[i] === 'dec' ? String(v) : style.radix[i] === 'oct' ? '0'.repeat(1 + style.zeros[i]!) + v.toString(8) :
    (style.radix[i] === 'hex' ? '0x' : '0X') + '0'.repeat(style.zeros[i]!) + v.toString(16)).join('.');
}

// IPv6 addresses as 16 bytes: random, special prefixes, and IPv4 embedded by mapping,
// NAT64, 6to4 and the deprecated compatible form.
const PREFIXES = [[], [0xfe, 0x80], [0xfc], [0xfd, 0x00, 0x0e, 0xc2], [0xff, 0x02], [0x20, 0x01, 0x0d, 0xb8], [0x20, 0x01, 0x00, 0x00], [0x20, 0x01, 0x01, 0xff],
  [0x20, 0x01, 0x02, 0x00], [0x20, 0x02], [0x3f, 0xff], [0x01, 0, 0, 0, 0, 0, 0, 0], [0x26, 0x06, 0x47, 0x00], [0x2a, 0x00], [0x00, 0x64, 0xff, 0x9b]];
const zeros = (count: number) => new Array<number>(count).fill(0);
const v6 = fc.oneof(
  fc.array(fc.integer({ min: 0, max: 255 }), { minLength: 16, maxLength: 16 }),
  fc.tuple(fc.constantFrom(...PREFIXES), fc.array(fc.integer({ min: 0, max: 255 }), { minLength: 16, maxLength: 16 }), fc.boolean())
    .map(([prefix, rest, sparse]) => [...prefix, ...(sparse ? [...zeros(16 - prefix.length - 2), ...rest.slice(0, 2)] : rest.slice(prefix.length))]),
  fc.tuple(fc.constantFrom([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff], [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0], zeros(12)), v4)
    .map(([prefix, n]) => [...prefix, ...octets(n)]),
  v4.map(n => [0x20, 0x02, ...octets(n), ...zeros(10)]));
const v6Style = fc.record({ compress: fc.nat(), pad: fc.boolean(), upper: fc.boolean(), embed: fc.boolean() });
function spellV6(bytes: number[], style: typeof v6Style extends fc.Arbitrary<infer T> ? T : never): string {
  const groups = Array.from({ length: style.embed ? 6 : 8 }, (_, i) => (bytes[2 * i]! << 8) | bytes[2 * i + 1]!);
  const text = groups.map(g => style.pad ? g.toString(16).padStart(4, '0') : g.toString(16));
  const tail = style.embed ? [bytes.slice(12).join('.')] : [];
  // Compress any run of zero groups, not only the longest one.
  const zeroRuns: [number, number][] = [];
  for (let i = 0; i < groups.length; i++) {
    if (groups[i] !== 0) continue;
    let end = i; while (groups[end + 1] === 0) end++;
    for (let a = i; a <= end; a++) for (let b = a; b <= end; b++) zeroRuns.push([a, b]);
    i = end;
  }
  const pick = style.compress % (zeroRuns.length + 1);
  let out = [...text, ...tail].join(':');
  if (pick < zeroRuns.length) {
    const [a, b] = zeroRuns[pick]!;
    out = `${text.slice(0, a).join(':')}::${[...text.slice(b + 1), ...tail].join(':')}`;
  }
  return style.upper ? out.toUpperCase() : out;
}
/** The address as the WHATWG URL parser reads it: an independent canonical form. */
const whatwg = (address: string) => new URL(`http://[${address}]/`).hostname.slice(1, -1);
const canonicalV6 = (bytes: number[]) => whatwg(Array.from({ length: 8 }, (_, i) => ((bytes[2 * i]! << 8) | bytes[2 * i + 1]!).toString(16)).join(':'));

// Hostname spellings that UTS #46 and the engine treat as the same name.
const IGNORED = ['\u00ad', '\u034f', '\u180b', '\u200b', '\u2060', '\ufe00', '\ufe0f', '\ufeff', '\u{1bca0}'];
const DOTS = ['.', '\u3002', '\uff0e', '\uff61'];
const spelling = fc.record({ chars: fc.array(fc.nat(), { maxLength: 300 }), ignored: fc.array(fc.tuple(fc.nat(), fc.constantFrom(...IGNORED)), { maxLength: 3 }),
  trailingDot: fc.boolean(), space: fc.constantFrom('', ' ', '\t', '\r\n', ' \n ') });
function respell(host: string, s: typeof spelling extends fc.Arbitrary<infer T> ? T : never): string {
  const chars = [...host].map((ch, i) => {
    const choice = (s.chars[i] ?? 0) % 4;
    if (ch === '.') return DOTS[choice]!;
    if (!/[a-z0-9-]/.test(ch) || choice === 0) return ch;
    if (choice === 1 && /[a-z]/.test(ch)) return ch.toUpperCase();
    return String.fromCodePoint(ch.charCodeAt(0) - 0x21 + 0xff01); // fullwidth form
  });
  for (const [at, ch] of s.ignored) chars.splice(at % (chars.length + 1), 0, ch);
  return `${s.space}${chars.join('')}${s.trailingDot ? DOTS[(s.chars[0] ?? 0) % 4] : ''}${s.space}`;
}
const asciiLabel = fc.stringMatching(/^[a-z0-9](?:[a-z0-9-]{0,14}[a-z0-9])?$/);
const label = fc.oneof({ weight: 4, arbitrary: asciiLabel }, { weight: 1, arbitrary: fc.constantFrom('bücher', 'faß', 'пример', 'ελληνικά', 'ς', '日本', 'xn--bcher-kva', 'xn--', 'a--b', '-a', 'שלום', '0', '0x7f', 'local', 'gov') });
const hostname = fc.array(label, { minLength: 1, maxLength: 4 }).map(l => l.join('.'));
// Raw input: arbitrary strings and hostnames assembled from awkward fragments.
const fragment = fc.constantFrom('a', 'z', '0', '9', '-', '_', '.', '..', 'xn--', 'ü', 'ß', 'ς', 'İ', 'ﬀ', '\u3002', '\uff0e', '\uff21', '\uff10', '\u00ad', '\u200d',
  '\u0663', 'א', '\u0301', ' ', '\t', '/', ':', '%', '@', '127', '0x', 'local', 'gov', 'com', '.com', 'example', '\u2024', '\u2488');
const rawTarget = fc.oneof(fc.string({ unit: 'binary', maxLength: 40 }), fc.array(fragment, { maxLength: 16 }).map(f => f.join('')), fc.domain(), hostname,
  fc.string({ unit: 'binary-ascii', minLength: 1000, maxLength: 1100 }));

for (const policy of POLICIES) {
  test(`fuzz: normalized targets are idempotent, bounded DNS names (${policy} policy)`, () => under(policy, () => {
    fc.assert(fc.property(rawTarget, input => {
      const host = outcome(() => normalizeTarget(input));
      if (host === 'refused') return;
      assert.equal(normalizeTarget(host), host);
      assert.ok(host.length <= 253 && /^[a-z0-9_.-]+$/.test(host) && host.split('.').every(l => l.length >= 1 && l.length <= 63), host);
      // Never an address literal, and never a name WHATWG would read as a numeric IPv4 address.
      assert.ok(isIP(host) === 0 && !/^(?:\d+|0x[0-9a-f]*)$/.test(host.split('.').at(-1)!), host);
      if (policy === 'public') assert.ok(host.includes('.'), host);
    }), { numRuns: runs(5000) });
  }));

  test(`fuzz: equivalent hostname spellings normalize identically (${policy} policy)`, () => under(policy, () => {
    fc.assert(fc.property(hostname, spelling, (host, s) => {
      assert.equal(outcome(() => normalizeTarget(respell(host, s))), outcome(() => normalizeTarget(host)));
    }), { numRuns: runs(5000) });
  }));

  test(`fuzz: legacy numeric IPv4 spellings are never accepted as hostnames (${policy} policy)`, () => under(policy, () => {
    fc.assert(fc.property(v4, v4Style, spelling, (n, style, s) => {
      assert.equal(outcome(() => normalizeTarget(respell(spellV4(n, style), s))), 'refused');
    }), { numRuns: runs(5000) });
  }));

  test(`fuzz: no IPv4 or IPv6 spelling is more permissive than the address it denotes (${policy} policy)`, () => under(policy, () => {
    fc.assert(fc.property(v4, v4Style, v6Style, (n, style, style6) => {
      const allowed = isPublicAddress(dotted(n));
      for (const spelled of [spellV4(n, style), spellV6([...zeros(10), 0xff, 0xff, ...octets(n)], style6)]) {
        if (isPublicAddress(spelled)) assert.ok(allowed, spelled);
      }
    }), { numRuns: runs(5000) });
    fc.assert(fc.property(v6, v6Style, (bytes, style) => {
      const spelled = spellV6(bytes, style), canonical = whatwg(spelled);
      // The hosted policy decides the same for every spelling; the instance policy may only be stricter.
      if (policy === 'public') assert.equal(isPublicAddress(spelled), isPublicAddress(canonical), spelled);
      else if (isPublicAddress(spelled)) assert.ok(isPublicAddress(canonical), spelled);
    }), { numRuns: runs(5000) });
    fc.assert(fc.property(fc.string({ unit: 'binary', maxLength: 50 }), value => { assert.equal(typeof isPublicAddress(value), 'boolean'); }), { numRuns: runs(1000) });
  }));

  test(`fuzz: an IP-literal target is either refused or a canonical connectable address (${policy} policy)`, () => under(policy, () => {
    const decide = (input: string) => outcome(() => parseIpTarget(input) ?? normalizeTarget(input));
    const wrap = fc.constantFrom((v: string) => v, (v: string) => `[${v}]`, (v: string) => ` ${v}\t`, (v: string) => `[${v}`);
    fc.assert(fc.property(v4, v4Style, spelling, wrap, (n, style, s, around) => {
      for (const input of [around(dotted(n)), around(spellV4(n, style)), respell(spellV4(n, style), s)]) {
        const target = decide(input);
        if (target !== 'refused') { assert.equal(target, dotted(n), input); assert.ok(isPublicAddress(target), input); }
      }
    }), { numRuns: runs(5000) });
    fc.assert(fc.property(v6, v6Style, wrap, (bytes, style, around) => {
      const spelled = spellV6(bytes, style), target = decide(around(spelled));
      if (target !== 'refused') { assert.equal(target, whatwg(spelled), spelled); assert.ok(isPublicAddress(target), spelled); }
    }), { numRuns: runs(5000) });
  }));
}

test('regressions found by fuzzing the address policy', () => under('any', () => {
  // An IPv4-mapped spelling of a broadcast, unspecified or multicast address was connectable.
  for (const value of ['::ffff:255.255.255.255', '::ffff:ffff:ffff', '::ffff:0.0.0.0', '::FFFF:E000:1']) assert.equal(isPublicAddress(value), false, value);
  for (const value of ['::ffff:10.0.0.1', '::ffff:127.0.0.1', '10.0.0.1']) assert.equal(isPublicAddress(value), true, value);
}));

test('fuzz: the hosted policy refuses special-use names in every spelling', () => {
  const SPECIAL = ['localhost', 'local', 'internal', 'intranet', 'lan', 'home', 'test', 'invalid', 'example', 'onion', 'arpa', 'home.arpa',
    'metadata.google.internal', '254.169.254.169.in-addr.arpa'];
  fc.assert(fc.property(fc.array(asciiLabel, { maxLength: 2 }), fc.constantFrom(...SPECIAL), spelling, (prefix, suffix, s) => {
    assert.equal(outcome(() => normalizeTarget(respell([...prefix, suffix].join('.'), s))), 'refused');
  }), { numRuns: runs(5000) });
});

test('fuzz: government targets stay restricted in every spelling', () => {
  const RESTRICTED = ['gov', 'mil', 'int', '政府', 'gov.uk', 'gouv.fr', 'gob.mx', 'go.jp', 'govt.nz', 'mil.br', 'fed.us', 'gc.ca', 'canada.ca',
    'bund.de', 'admin.ch', 'europa.eu', 'usps.com', 'si.edu', 'state.ca.us', 'ci.boston.ma.us', 'co.travis.tx.us'];
  fc.assert(fc.property(fc.array(label, { minLength: 1, maxLength: 2 }), fc.constantFrom(...RESTRICTED), spelling, (prefix, suffix, s) => {
    const host = outcome(() => normalizeTarget(respell([...prefix, suffix].join('.'), s)));
    if (host !== 'refused') assert.ok(isRestrictedTarget(host), host);
  }), { numRuns: runs(5000) });
});

test('fuzz: reverse DNS names round-trip and are valid queries', () => {
  fc.assert(fc.property(fc.oneof(v4.map(dotted), v6.map(canonicalV6)), ip => {
    const owner = reverseName(ip);
    assert.ok(encodeQuery(owner, 'PTR', 1).length > 0);
    const labels = owner.split('.');
    if (isIP(ip) === 4) {
      assert.deepEqual(labels.slice(4), ['in-addr', 'arpa']);
      assert.equal(labels.slice(0, 4).reverse().join('.'), ip);
    } else {
      assert.deepEqual(labels.slice(32), ['ip6', 'arpa']);
      const hex = labels.slice(0, 32).reverse().join('');
      assert.equal(whatwg(hex.match(/.{4}/g)!.join(':')), ip);
    }
  }), { numRuns: runs(3000) });
});
