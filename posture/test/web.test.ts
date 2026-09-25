// The check page (web/) renders engine documents in the browser. These tests run its view
// logic against documents the engine itself produces, so a schema change that the page does
// not understand fails here rather than on the published page.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { Budget } from '../src/budget.ts';
import { query } from '../src/dns.ts';
import { parseCheckRequest } from '../src/request.ts';
import { ERRORS } from '../src/response.ts';
import type { Check, Fetcher, Observation } from '../src/types.ts';
import { TYPES } from '../src/wire.ts';
import { factualResponse } from '../src/checks/factual.ts';
import { ipObservation } from '../src/checks/iptarget.ts';
import { handle } from '../src/checks/service.ts';
import { spfTree } from '../src/checks/spf.ts';
import { unlimitedStore } from '../src/checks/store.ts';
import { mockDns, packet, queryInfo, rr } from './helpers.ts';

type Doc = ReturnType<typeof factualResponse>;
type Item = Doc['observations'][number];
type Row = { key: string; label: string; text?: string; chips?: string[]; lines?: string[] };
interface View {
  ERROR_HINTS: Record<string, string>;
  parseTarget(value: string): { target: string; path?: string };
  buildRequest(value: string, selector?: string): Record<string, string>;
  requestOf(doc: unknown): Record<string, string>;
  cliCommand(request: Record<string, string>): string;
  validateDocument(doc: unknown): Doc;
  hasData(observation: unknown): boolean;
  summarize(doc: unknown): { total: number; observed: number; groups: Array<{ id: string; total: number; observed: number }> };
  reviewHints(observations: unknown[]): Array<{ id: string; name: string; text: string }>;
  describe(observation: unknown): { headline: string; rows: Row[]; tables: Array<{ columns: string[]; rows: string[][] }>;
    sections: Array<{ title: string; rows: Row[] }> };
  describeError(status: number, body: unknown, retryAfter?: string | null): { code: string; message: string; hint: string; retryAfter: number | null };
}

const web = (file: string) => readFileSync(new URL(`../web/${file}`, import.meta.url), 'utf8');
vm.runInThisContext(web('view.js'), { filename: 'web/view.js' });
const view = (globalThis as unknown as { ShakerScanView: View }).ShakerScanView;
const plain = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

async function engineDocument(target: string): Promise<Doc> {
  const response = await handle({ version: '2.0', rawPath: '/v1/check', rawQueryString: '', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ target }), requestContext: { http: { method: 'POST', sourceIp: '192.0.2.1' } } },
  unlimitedStore(), 'test-only-secret-at-least-32-characters', true, mockDns({ A: [], AAAA: [] }));
  assert.equal(response.statusCode, 200);
  return JSON.parse(response.body) as Doc;
}

// SPF evidence produced by the engine's own include/redirect walk over these TXT records.
async function spfObservation(records: Record<string, string>): Promise<Item> {
  const base = mockDns();
  const fetcher: Fetcher = async (url, init) => {
    const { host, type, id } = queryInfo(init.body);
    const value = type === 'TXT' ? records[host] : undefined;
    if (value === undefined) return base(url, init);
    return new Response(packet(host, type, id, [rr(TYPES.TXT, [value.length, ...Buffer.from(value)], host)]),
      { headers: { 'Content-Type': 'application/dns-message' } });
  };
  const budget = new Budget(8000, undefined, 100);
  try {
    const check = await spfTree('mail.example.net', await query('mail.example.net', 'TXT', budget, fetcher), budget, fetcher);
    const data: Observation = { schema_version: '1', target: 'mail.example.net', checked_at: new Date().toISOString(),
      summary: '', checks: [check], limitations: [] };
    return factualResponse(data, false, 'spf')!.observations[0]!;
  } finally { budget.close(); }
}

test('the page reads a real engine document for a hostname', async () => {
  const doc = view.validateDocument(await engineDocument('example.com'));
  const summary = plain(view.summarize(doc));
  assert.equal(summary.total, doc.observations.length);
  assert.deepEqual(summary.groups.map(group => group.id), ['dns', 'mail', 'http', 'tls', 'ip']);
  for (const observation of doc.observations) {
    const context = observation.result && Object.keys(observation.result).every(key => ['path', 'selector'].includes(key));
    assert.equal(view.hasData(observation), observation.result !== null && !context, observation.id);
  }
  // With no addresses the CORS result only restates the requested path: nothing was observed.
  assert.deepEqual(doc.observations.find(o => o.id === 'http.cors')?.result, { path: '/' });
  assert.equal(view.cliCommand(view.requestOf(doc)), 'shakerscan check example.com --json');
});

test('the committed sample has the shape the engine emits today', async () => {
  const sample = view.validateDocument(JSON.parse(web('sample.json')));
  const engine = await engineDocument('example.com');
  const shape = (doc: Doc) => doc.observations.map(o => [o.id, o.group, o.name, o.scope]);
  assert.deepEqual(shape(sample), shape(engine));
  assert.deepEqual(sample.limitations, engine.limitations);
  // Illustrative data only: documentation addresses (RFC 5737, RFC 3849) and ASNs (RFC 5398).
  const text = JSON.stringify(sample);
  for (const ip of text.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) ?? []) assert.match(ip, /^(?:192\.0\.2|198\.51\.100|203\.0\.113)\./);
  for (const ip of text.match(/"[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7}"/gi) ?? []) assert.match(ip, /^"2001:db8:/i);
  for (const asn of text.match(/AS\d+/g) ?? []) assert.ok(Number(asn.slice(2)) >= 64496 && Number(asn.slice(2)) <= 64511, asn);
});

test('review hints say what shakerscan check says', () => {
  // The client's own fixture (client/tests/test_public.py) and the lines its Review section prints.
  const facts = [
    { id: 'mail.spf', name: 'SPF', group: 'mail', result: { record_count: 1, all_qualifier: '?' } },
    { id: 'mail.dmarc', name: 'DMARC', group: 'mail', result: { applied_policy: 'none' } },
    { id: 'mail.dkim', name: 'DKIM', group: 'mail', result: null },
    { id: 'tls.handshake', name: 'TLS handshake', group: 'tls', result: { certificate_days_remaining: 12, certificate_verified: true } }
  ];
  assert.deepEqual(plain(view.reviewHints(facts)).map(hint => `${hint.name}: ${hint.text}`), [
    'SPF: SPF ends with neutral ?all, which authorizes nothing',
    'DMARC: DMARC policy is p=none (monitoring only)',
    'TLS handshake: certificate expires in 12 days'
  ]);
  assert.deepEqual(plain(view.reviewHints([
    { id: 'dns.dnssec', name: 'DNSSEC', result: { local_validation: 'bogus' } },
    { id: 'tls.handshake', name: 'TLS handshake', result: { certificate_verified: false, certificate_days_remaining: 90 } },
    { id: 'mail.spf', name: 'SPF', result: { record_count: 1, all_qualifier: '+' } }
  ])).map(hint => hint.text), ['DNSSEC validation failed', 'certificate was not verified', 'SPF +all lets any server send as this domain']);
});

test('an SPF record whose policy comes from redirect= is not flagged', async () => {
  const redirect = await spfObservation({ 'mail.example.net': 'v=spf1 redirect=_spf.example.net', '_spf.example.net': 'v=spf1 ip4:192.0.2.0/24 -all' });
  assert.equal(redirect.result?.all_qualifier, 'absent');
  assert.deepEqual(redirect.result?.checked_domains, ['mail.example.net', '_spf.example.net']);
  assert.deepEqual(plain(view.reviewHints([redirect])), []);
  const bare = await spfObservation({ 'mail.example.net': 'v=spf1 ip4:192.0.2.0/24' });
  assert.deepEqual(plain(view.reviewHints([bare])).map(hint => hint.text), ['SPF has no terminal all/redirect policy']);
});

test('an IP-address target shows its network and not-applicable DNS and email checks', async () => {
  const budget = new Budget();
  const ip = '203.0.113.7';
  try {
    const data = await ipObservation(ip, { addresses: [{ ip, family: 'IPv4', sampled: true, asn: 'AS64501', as_name: 'Example Transit' }],
      total_address_count: 1, cname_chain: [], enrichment: 'available', provider: 'ipinfo_lite', reverse_dns: ['edge.example.org'] },
    budget, '/', async (_host, _addresses, _budget, _path, onFacts) => {
      onFacts?.([{ ip, status_code: 404, tls_protocol: 'TLSv1.3', certificate: { ip_address_match: false, subject: 'edge.example.org' } }]);
      return [] as Check[];
    }, async () => ({ id: 'http.security_txt', name: 'Security contact', group: 'http', scope: 'fixed', result: null }));
    const doc = factualResponse(data, false, 'ip');
    // The stubbed probes return no web checks, so HTTP holds only security.txt and the connection.
    const groups = Object.fromEntries(plain(view.summarize(doc)).groups.map(group => [group.id, `${group.observed}/${group.total}`]));
    assert.deepEqual(groups, { dns: '1/5', mail: '0/6', http: '1/2', ip: '1/1' });
    const network = view.describe(doc.observations.find(o => o.id === 'ip.network'));
    assert.equal(network.headline, '1 address · AS64501 Example Transit');
    assert.deepEqual(plain(network.tables[0]!.rows), [[ip, 'AS64501 Example Transit', '—', '—', 'yes']]);
    assert.deepEqual(plain(network.rows.find(row => row.key === 'reverse_dns')?.chips), ['edge.example.org']);
    const connection = view.describe(doc.observations.find(o => o.id === 'http.connections')).sections[0]!;
    assert.equal(connection.title, ip);
    assert.equal(connection.rows.find(row => row.key === 'ip_address_match')?.text, 'no');
  } finally { budget.close(); }
});

test('the page sends only requests the engine accepts', () => {
  const cases: Array<[string, string, Record<string, string>]> = [
    ['Example.COM.', '', { target: 'example.com' }],
    ['https://Example.com/api/v1?x=1#top', '', { target: 'example.com', path: '/api/v1' }],
    ['example.com', 'Selector1', { target: 'example.com', dkim_selector: 'selector1' }],
    ['1.1.1.1', '', { target: '1.1.1.1' }],
    ['https://[2001:db8::1]/', '', { target: '2001:db8::1' }]
  ];
  for (const [input, selector, expected] of cases) {
    const request = plain(view.buildRequest(input, selector));
    assert.deepEqual(request, expected, input);
    assert.deepEqual(parseCheckRequest(JSON.stringify(request), true, true), expected, input);
  }
  const refused: Array<[string, string]> = [['example.com:8443', ''], ['https://example.com:8443/', ''],
    ['https://user:pw@example.com/', ''], ['ftp://example.com', ''], ['example.com/path', ''], ['https://example.com/a%20b', ''],
    ['', ''], ['1.1.1.1', 'google'], ['example.com', 'bad selector']];
  for (const [input, selector] of refused) assert.throws(() => view.buildRequest(input, selector), `${input} ${selector}`);
  // An opened file may name anything; the suggested command stays plain shell words.
  assert.equal(view.cliCommand({ target: 'example.com', path: '/api/v1', dkim_selector: 'selector1' }),
    'shakerscan check example.com --path /api/v1 --dkim-selector selector1 --json');
  assert.equal(view.cliCommand({ target: '2001:db8::1' }), 'shakerscan check 2001:db8::1 --json');
  for (const target of ['$(id)', 'a;b', '-rf', '~', 'a b', "a'b"]) assert.equal(view.cliCommand({ target }), '', target);
});

test('every engine error code has page guidance', () => {
  for (const [code, [status, message]] of Object.entries(ERRORS)) {
    assert.ok(view.ERROR_HINTS[code], code);
    const problem = view.describeError(status, { error: { code, message }, request_id: 'r' }, status === 429 ? '42' : null);
    assert.equal(problem.code, code);
    assert.equal(problem.message, message);
    assert.equal(problem.retryAfter, status === 429 ? 42 : null);
  }
  assert.equal(view.describeError(401, { detail: 'Missing bearer token' }).message, 'Missing bearer token');
});

test('the page talks only to its endpoint and never parses markup', () => {
  const html = web('index.html');
  const endpoint = /<meta name="shakerscan-check-endpoint" content="([^"]+)">/.exec(html)?.[1];
  const csp = /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/.exec(html)?.[1] ?? '';
  const directive = (name: string) => csp.split(';').map(part => part.trim().split(/\s+/)).find(parts => parts[0] === name)?.slice(1) ?? [];
  assert.ok(endpoint && directive('connect-src').includes(new URL(endpoint).origin), 'connect-src must allow the configured endpoint');
  assert.deepEqual(directive('script-src'), ["'self'"]);
  assert.deepEqual(directive('default-src'), ["'none'"]);
  assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/, 'no inline scripts');
  assert.match(web('_headers'), /frame-ancestors 'none'/);
  for (const file of ['app.js', 'view.js']) {
    assert.doesNotMatch(web(file), /innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function/, file);
  }
});
