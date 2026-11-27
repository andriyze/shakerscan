// Property-based fuzzing of the DNS wire codec and the answer-chain and address-safety decisions
// built on it. Every resolver reply is untrusted input.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { answers, validateAddressEvidence, type Result, type Results } from '../src/dns.ts';
import { PublicError } from '../src/response.ts';
import { configureTargetPolicy, isPublicAddress } from '../src/safety.ts';
import { decodeAnswer, encodeQuery, TYPES, type DnsAnswer, type QueryType, type RecordData } from '../src/wire.ts';
import { packet, rr, runs } from './helpers.ts';

const QUERY_TYPES = ['A', 'AAAA', 'NS', 'SOA', 'PTR', 'CAA', 'MX', 'TXT', 'DS', 'DNSKEY', 'HTTPS'] as const satisfies QueryType[];
const SECTIONS = ['answer', 'authority', 'additional'] as const;
const u16 = (v: number) => [(v >> 8) & 255, v & 255];
const u32 = (v: number) => [...u16(v >>> 16), ...u16(v & 0xffff)];
const ascii = (bytes: number[]) => String.fromCharCode(...bytes);
const byte = fc.integer({ min: 0, max: 255 });
const bytes = (maxLength: number, minLength = 0) => fc.array(byte, { minLength, maxLength });

// Label bytes the decoder accepts: printable ASCII except '.' and '\'. Case is mixed on the
// wire and must come back lowercased.
const label = fc.array(fc.integer({ min: 33, max: 126 }).filter(b => b !== 46 && b !== 92), { minLength: 1, maxLength: 12 });
const dnsName = fc.array(label, { maxLength: 4 });
// A name reference is either explicit labels or null: a compression pointer to the question.
type NameRef = number[][] | null;
const nameRef = fc.option(dnsName, { freq: 4 });
const wireName = (labels: number[][]) => [...labels.flatMap(l => [l.length, ...l]), 0];
const nameText = (labels: number[][]) => labels.map(ascii).join('.').toLowerCase();

type Param = { key: number; alpn?: number[][]; raw?: number[] };
type Spec =
  | { kind: 'A' | 'AAAA'; bytes: number[] }
  | { kind: 'CNAME' | 'NS' | 'PTR'; target: NameRef }
  | { kind: 'MX'; preference: number; target: NameRef }
  | { kind: 'TXT'; strings: number[][] }
  | { kind: 'CAA'; flags: number; tag: string; value: number[] }
  | { kind: 'SOA'; mname: NameRef; rname: NameRef; serial: number; rest: number[] }
  | { kind: 'DS'; keyTag: number; algorithm: number; digestType: number; digest: number[] }
  | { kind: 'DNSKEY'; flags: number; algorithm: number; key: number[] }
  | { kind: 'HTTPS'; priority: number; target: NameRef; params: Param[] }
  | { kind: 'other'; type: number; rdata: number[] };
interface Rec { owner: NameRef; section: 0 | 1 | 2; ttl: number; spec: Spec }

const known = new Set<number>(Object.values(TYPES));
const alpnId = fc.oneof(fc.array(fc.constantFrom(...Buffer.from('abcxyzH0129_.-')), { minLength: 1, maxLength: 8 }), bytes(8, 1));
const param: fc.Arbitrary<Param> = fc.oneof(
  fc.record({ key: fc.constant(1), alpn: fc.array(alpnId, { maxLength: 3 }) }),
  fc.record({ key: fc.constantFrom(3, 5), raw: bytes(4) }),
  fc.record({ key: fc.integer({ min: 0, max: 65535 }).filter(key => key !== 1), raw: bytes(6) }));
const spec: fc.Arbitrary<Spec> = fc.oneof(
  fc.record({ kind: fc.constant('A' as const), bytes: bytes(4, 4) }),
  fc.record({ kind: fc.constant('AAAA' as const), bytes: bytes(16, 16) }),
  fc.record({ kind: fc.constantFrom('CNAME' as const, 'NS' as const, 'PTR' as const), target: nameRef }),
  fc.record({ kind: fc.constant('MX' as const), preference: fc.integer({ min: 0, max: 65535 }), target: fc.oneof(nameRef, fc.constant<NameRef>([])) }),
  fc.record({ kind: fc.constant('TXT' as const), strings: fc.array(bytes(255), { maxLength: 3 }) }),
  fc.record({ kind: fc.constant('CAA' as const), flags: byte, tag: fc.string({ unit: fc.constantFrom(...'issueIODEFwild09'), minLength: 1, maxLength: 15 }), value: fc.oneof(fc.array(fc.integer({ min: 32, max: 126 }), { maxLength: 40 }), bytes(40)) }),
  fc.record({ kind: fc.constant('SOA' as const), mname: nameRef, rname: nameRef, serial: fc.integer({ min: 0, max: 0xffffffff }), rest: bytes(16, 16) }),
  fc.record({ kind: fc.constant('DS' as const), keyTag: fc.integer({ min: 0, max: 65535 }), algorithm: byte, digestType: byte, digest: bytes(32) }),
  fc.record({ kind: fc.constant('DNSKEY' as const), flags: fc.integer({ min: 0, max: 65535 }), algorithm: byte, key: bytes(32) }),
  fc.record({ kind: fc.constant('HTTPS' as const), priority: fc.integer({ min: 0, max: 65535 }), target: fc.oneof(nameRef, fc.constant<NameRef>([])),
    params: fc.uniqueArray(param, { selector: p => p.key, maxLength: 5 }).map(list => list.sort((a, b) => a.key - b.key)) }),
  fc.record({ kind: fc.constant('other' as const), type: fc.integer({ min: 0, max: 65535 }).filter(t => !known.has(t)), rdata: bytes(20) }));
const rec: fc.Arbitrary<Rec> = fc.record({ owner: nameRef, section: fc.constantFrom(0 as const, 1 as const, 2 as const), ttl: fc.integer({ min: 0, max: 0xffffffff }), spec });

/** Encodes one record's RDATA and the fields the decoder must report for it. */
function rdata(s: Spec, question: number[][]): { type: number; data: number[]; expect: Partial<RecordData> } {
  const ref = (n: NameRef) => n ? { wire: wireName(n), text: nameText(n) } : { wire: [0xc0, 12], text: nameText(question) };
  switch (s.kind) {
    case 'A': return { type: TYPES.A, data: s.bytes, expect: { value: s.bytes.join('.') } };
    case 'AAAA': return { type: TYPES.AAAA, data: s.bytes, expect: { value: Array.from({ length: 8 }, (_, i) => ((s.bytes[2 * i]! << 8) | s.bytes[2 * i + 1]!).toString(16)).join(':') } };
    case 'CNAME': case 'NS': case 'PTR': { const t = ref(s.target); return { type: TYPES[s.kind], data: t.wire, expect: { value: t.text } }; }
    case 'MX': { const t = ref(s.target); return { type: TYPES.MX, data: [...u16(s.preference), ...t.wire], expect: { preference: s.preference, value: t.text } }; }
    case 'TXT': return { type: TYPES.TXT, data: s.strings.flatMap(v => [v.length, ...v]), expect: { value: ascii(s.strings.flat()) } };
    case 'CAA': {
      const printable = s.value.every(b => b >= 32 && b <= 126);
      return { type: TYPES.CAA, data: [s.flags, s.tag.length, ...Buffer.from(s.tag), ...s.value], expect: { flags: s.flags, tag: s.tag.toLowerCase(), ...(printable ? { value: ascii(s.value) } : {}) } };
    }
    case 'SOA': return { type: TYPES.SOA, data: [...ref(s.mname).wire, ...ref(s.rname).wire, ...u32(s.serial), ...s.rest], expect: { serial: s.serial } };
    case 'DS': return { type: TYPES.DS, data: [...u16(s.keyTag), s.algorithm, s.digestType, ...s.digest], expect: { keyTag: s.keyTag, algorithm: s.algorithm } };
    case 'DNSKEY': return { type: TYPES.DNSKEY, data: [...u16(s.flags), 3, s.algorithm, ...s.key], expect: { algorithm: s.algorithm } };
    case 'HTTPS': {
      const t = ref(s.target);
      const data = [...u16(s.priority), ...t.wire], params: string[] = [];
      for (const p of s.params) {
        const value = p.alpn ? p.alpn.flatMap(id => [id.length, ...id]) : p.raw!;
        data.push(...u16(p.key), ...u16(value.length), ...value);
        params.push(p.alpn ? `alpn=${p.alpn.map(ascii).filter(id => /^[a-zA-Z0-9_.-]{1,32}$/.test(id)).join(',')}` :
          p.key === 3 && value.length === 2 ? `port=${(value[0]! << 8) | value[1]!}` : p.key === 5 ? 'ech=present' : `key${p.key}=present`);
      }
      return { type: TYPES.HTTPS, data, expect: { preference: s.priority, value: t.text || '.', params } };
    }
    case 'other': return { type: s.type, data: s.rdata, expect: {} };
  }
}

const response = fc.record({
  id: fc.integer({ min: 0, max: 65535 }), qtype: fc.constantFrom(...QUERY_TYPES), question: dnsName,
  // QR is set; opcode, TC and CD stay clear; AA, RD, RA, Z, AD and any RCODE vary.
  flags: fc.integer({ min: 0, max: 65535 }).map(f => 0x8000 | (f & ~0x7a10)),
  records: fc.array(rec, { maxLength: 10 }),
  opt: fc.option(fc.record({ size: fc.integer({ min: 0, max: 65535 }), flags: fc.integer({ min: 0, max: 65535 }),
    options: fc.array(fc.tuple(fc.integer({ min: 0, max: 65535 }), bytes(6)), { maxLength: 3 }) }))
});
type Response = typeof response extends fc.Arbitrary<infer T> ? T : never;

/** Assembles a well-formed reply and the DnsAnswer the decoder must return for it. */
function assemble(r: Response): { data: Uint8Array; expected: { host: string; type: QueryType; id: number }; answer: DnsAnswer } {
  const sorted = [...r.records].sort((a, b) => a.section - b.section);
  const counts = [0, 0, 0];
  const body: number[] = [...wireName(r.question), ...u16(TYPES[r.qtype]), 0, 1];
  const records: RecordData[] = [];
  for (const { owner, section, ttl, spec: s } of sorted) {
    const { type, data, expect } = rdata(s, r.question);
    body.push(...(owner ? wireName(owner) : [0xc0, 12]), ...u16(type), 0, 1, ...u32(ttl), ...u16(data.length), ...data);
    records.push({ name: owner ? nameText(owner) : nameText(r.question), type, section: SECTIONS[section], ttl, ...expect });
    counts[section]!++;
  }
  if (r.opt) {
    const options = r.opt.options.flatMap(([code, data]) => [...u16(code), ...u16(data.length), ...data]);
    body.push(0, ...u16(TYPES.OPT), ...u16(r.opt.size), 0, 0, ...u16(r.opt.flags), ...u16(options.length), ...options);
    counts[2]!++;
  }
  const data = new Uint8Array([...u16(r.id), ...u16(r.flags), 0, 1, ...counts.flatMap(u16), ...body]);
  const host = nameText(r.question) || '.';
  return { data, expected: { host, type: r.qtype, id: r.id },
    answer: { state: 'ok', rcode: r.flags & 15, ad: Boolean(r.flags & 0x20), aa: Boolean(r.flags & 0x400), records } };
}

/** Malformed input is refused with the codec's one error; anything accepted stays within its bounds. */
function decodesOrRefuses(data: Uint8Array, expected: { host: string; type: QueryType; id: number }) {
  let answer: DnsAnswer;
  try { answer = decodeAnswer(data, expected); }
  catch (error) { assert.ok(error instanceof Error && error.message === 'invalid_dns', `unexpected ${String(error)}`); return; }
  assert.ok(answer.records.length <= 128);
  assert.ok(answer.rcode >= 0 && answer.rcode <= 15);
  for (const record of answer.records) {
    assert.ok(record.name.length <= 253 && record.name === record.name.toLowerCase() && !/[^\x21-\x7e]/.test(record.name), record.name);
    assert.notEqual(record.type, TYPES.OPT);
    if (record.type === TYPES.TXT) assert.ok(record.value!.length <= 4096);
    if (record.tag !== undefined) assert.match(record.tag, /^[\x21-\x7e]*$/);
    if (record.type === TYPES.CAA && record.value !== undefined) assert.ok(record.value.length <= 512 && /^[\x20-\x7e]*$/.test(record.value));
    if (record.params) assert.ok(record.params.length <= 16);
  }
}

const mutation = fc.oneof(
  fc.record({ op: fc.constant('set' as const), at: fc.nat(), value: byte }),
  fc.record({ op: fc.constant('pointer' as const), at: fc.nat(), value: fc.integer({ min: 0, max: 0x3fff }) }),
  fc.record({ op: fc.constant('insert' as const), at: fc.nat(), bytes: bytes(8, 1) }),
  fc.record({ op: fc.constant('delete' as const), at: fc.nat(), value: fc.integer({ min: 1, max: 8 }) }),
  fc.record({ op: fc.constant('truncate' as const), at: fc.nat() }));
function mutate(data: Uint8Array, steps: (typeof mutation extends fc.Arbitrary<infer T> ? T : never)[]): Uint8Array {
  let out = [...data];
  for (const step of steps) {
    const at = out.length ? step.at % out.length : 0;
    if (step.op === 'set') out[at] = step.value;
    else if (step.op === 'pointer') out.splice(at, 2, 0xc0 | (step.value >> 8), step.value & 255);
    else if (step.op === 'insert') out.splice(at, 0, ...step.bytes);
    else if (step.op === 'delete') out.splice(at, step.value);
    else out = out.slice(0, at);
  }
  return new Uint8Array(out);
}

test('fuzz: well-formed replies decode to exactly the records they encode', () => {
  fc.assert(fc.property(response, r => {
    const { data, expected, answer } = assemble(r);
    assert.deepEqual(decodeAnswer(data, expected), answer);
  }), { numRuns: runs(3000) });
});

test('fuzz: mutated replies are decoded within bounds or refused as invalid_dns', () => {
  fc.assert(fc.property(response, fc.array(mutation, { minLength: 1, maxLength: 4 }), (r, steps) => {
    const { data, expected } = assemble(r);
    decodesOrRefuses(mutate(data, steps), expected);
  }), { numRuns: runs(5000) });
});

test('fuzz: arbitrary bytes behind a matching header never escape the decoder', () => {
  const header = fc.record({ id: fc.integer({ min: 0, max: 65535 }), flags: fc.oneof(fc.integer({ min: 0, max: 65535 }), fc.integer({ min: 0, max: 65535 }).map(f => 0x8000 | (f & ~0x7a10))),
    qd: fc.oneof(fc.constant(1), fc.integer({ min: 0, max: 65535 })), counts: fc.array(fc.integer({ min: 0, max: 70 }), { minLength: 3, maxLength: 3 }) });
  fc.assert(fc.property(header, dnsName, fc.constantFrom(...QUERY_TYPES), bytes(300), (h, question, type, tail) => {
    const data = new Uint8Array([...u16(h.id), ...u16(h.flags), ...u16(h.qd), ...h.counts.flatMap(u16), ...wireName(question), ...u16(TYPES[type]), 0, 1, ...tail]);
    decodesOrRefuses(data, { host: nameText(question) || '.', type, id: h.id });
  }), { numRuns: runs(5000) });
  fc.assert(fc.property(fc.uint8Array({ maxLength: 600 }), fc.integer({ min: 0, max: 65535 }), (data, id) => {
    decodesOrRefuses(data, { host: 'example.com', type: 'A', id });
  }), { numRuns: runs(2000) });
});

test('regressions found by fuzzing the codec', () => {
  // Names the decoder can never match were encoded instead of refused, some of them malformed.
  for (const host of ['\u0161example.com', 'a\u{1F600}.com', 'Example.com', 'a\\b.com', 'a b.com', '\u0000']) assert.throws(() => encodeQuery(host, 'A', 1), /invalid_dns/, host);
  assert.ok(encodeQuery('_dmarc.example.com', 'TXT', 1).length > 0);
  // A CAA tag with a NUL or a space was reported verbatim and reached the displayed evidence.
  for (const tag of [[0], [...Buffer.from('iodef x')]]) {
    const reply = packet('example.com', 'CAA', 7, [rr(TYPES.CAA, [0, tag.length, ...tag, ...Buffer.from('a@b')])]);
    const [record] = decodeAnswer(reply, { host: 'example.com', type: 'CAA', id: 7 }).records;
    assert.equal(record!.tag, undefined); assert.equal(record!.value, 'a@b');
  }
});

test('fuzz: every query the encoder emits can be matched by the decoder', () => {
  const host = fc.oneof(
    fc.string({ unit: 'binary', maxLength: 80 }),
    fc.string({ unit: fc.constantFrom(...'aZ09-_.\\ éā\u{1F600}'), maxLength: 30 }),
    fc.domain(),
    fc.array(fc.string({ unit: fc.constantFrom('a', 'b'), minLength: 60, maxLength: 64 }), { minLength: 1, maxLength: 5 }).map(l => l.join('.')),
    dnsName.map(nameText));
  fc.assert(fc.property(host, fc.constantFrom(...QUERY_TYPES), fc.integer({ min: 0, max: 65535 }), (name, type, id) => {
    let query: Uint8Array;
    try { query = encodeQuery(name, type, id); }
    catch (error) { assert.equal((error as Error).message, 'invalid_dns'); return; }
    assert.ok(query.length <= 12 + 255 + 4 + 11);
    // The same message with QR set is a reply carrying the question and the EDNS OPT record.
    const reply = query.slice(); reply[2] = reply[2]! | 0x80;
    assert.deepEqual(decodeAnswer(reply, { host: name, type, id }).records, []);
  }), { numRuns: runs(5000) });
});

// CNAME chains: a small name pool makes loops, forks and conflicting data common.
const POOL = ['example.com', 'a.example.com', 'b.example.net', 'c.example.org', 'd.example.com'];
const chainRecord = fc.record({
  name: fc.constantFrom(...POOL), type: fc.constantFrom(TYPES.A, TYPES.A, TYPES.CNAME, TYPES.CNAME, TYPES.SOA, TYPES.TXT),
  section: fc.constantFrom(...SECTIONS), value: fc.option(fc.constantFrom(...POOL, '1.1.1.1', ''), { freq: 8, nil: undefined })
}).map(({ value, ...r }): RecordData => value === undefined ? r : { ...r, value });
const okResult = (records: RecordData[], rcode = 0): Result => ({ state: 'ok', rcode, ad: false, aa: false, records });

test('fuzz: alias chains resolve only along one unambiguous bounded path', () => {
  fc.assert(fc.property(fc.array(chainRecord, { maxLength: 14 }), records => {
    let found: RecordData[];
    try { found = answers(okResult(records), 'example.com', TYPES.A); }
    catch (error) { assert.ok(error instanceof PublicError && error.code === 'dns_unavailable'); return; }
    const inAnswer = (name: string, type: number) => records.filter(r => r.section === 'answer' && r.name === name && r.type === type);
    // Walk the justification: each hop has exactly one alias and no competing data.
    let name = 'example.com', hops = 0;
    while (inAnswer(name, TYPES.CNAME).length) {
      assert.equal(inAnswer(name, TYPES.CNAME).length, 1);
      assert.equal(inAnswer(name, TYPES.A).length, 0);
      name = inAnswer(name, TYPES.CNAME)[0]!.value!;
      assert.ok(++hops <= 8);
    }
    assert.deepEqual(found, inAnswer(name, TYPES.A));
    if (!found.length) assert.ok(records.some(r => r.type === TYPES.SOA && r.section === 'authority'));
  }), { numRuns: runs(5000) });
});

// Address values in decoder format, biased toward special-use ranges and malformed strings.
const v4Value = fc.oneof(
  bytes(4, 4).map(b => b.join('.')),
  fc.constantFrom('127.0.0.1', '10.1.2.3', '169.254.169.254', '100.64.0.1', '192.168.0.1', '0.0.0.0', '255.255.255.255', '224.0.0.1', '8.8.8.8', '93.184.216.34'),
  fc.string({ maxLength: 12 }));
const v6Value = fc.oneof(
  fc.array(fc.integer({ min: 0, max: 65535 }), { minLength: 8, maxLength: 8 }).map(g => g.map(x => x.toString(16)).join(':')),
  fc.constantFrom('0:0:0:0:0:0:0:1', '0:0:0:0:0:ffff:7f00:1', 'fe80:0:0:0:0:0:0:1', 'fd00:ec2:0:0:0:0:0:254', '2001:db8:0:0:0:0:0:1', '2606:4700:4700:0:0:0:0:1111', '64:ff9b:0:0:0:0:a00:1'));
const addressRecord = fc.oneof(
  fc.record({ name: fc.constantFrom(...POOL), type: fc.constant(TYPES.A), section: fc.constantFrom(...SECTIONS), value: v4Value }),
  fc.record({ name: fc.constantFrom(...POOL), type: fc.constant(TYPES.AAAA), section: fc.constantFrom(...SECTIONS), value: v6Value }),
  chainRecord);
const result: fc.Arbitrary<Result> = fc.oneof(
  fc.constantFrom({ state: 'timeout' as const }, { state: 'unavailable' as const }),
  { weight: 2, arbitrary: fc.tuple(fc.array(addressRecord, { maxLength: 6 }), fc.constantFrom(0, 3)).map(([records, rcode]) => okResult(records, rcode)) });
const results = fc.record({ A: result, AAAA: result, NS: result, CAA: result, MX: result, TXT: result, DMARC: result }) as fc.Arbitrary<Results>;

for (const policy of ['public', 'any'] as const) {
  test(`fuzz: an unconnectable address anywhere in DNS evidence refuses the target (${policy} policy)`, () => {
    configureTargetPolicy(policy);
    try {
      fc.assert(fc.property(results, all => {
        const addresses = Object.values(all).flatMap(r => r.state === 'ok' ? r.records : []).filter(r => r.type === TYPES.A || r.type === TYPES.AAAA);
        const unsafe = addresses.some(r => !isPublicAddress(r.value ?? ''));
        try { validateAddressEvidence(all, 'example.com'); }
        catch (error) {
          assert.ok(error instanceof PublicError, String(error));
          if (unsafe) assert.equal(error.code, 'target_not_allowed');
          return;
        }
        assert.equal(unsafe, false);
        assert.ok(all.A.state === 'ok' && all.AAAA.state === 'ok');
      }), { numRuns: runs(4000) });
    } finally { configureTargetPolicy('public'); }
  });
}
