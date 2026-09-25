import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Budget } from '../src/budget.ts';
import { ipNetworks, type IpinfoCache } from '../src/checks/ipinfo.ts';

test('IPinfo enriches only validated public addresses and reuses a day-scale IP cache', async () => {
  const stored: Record<string, Record<string, unknown>> = {};
  const cache: IpinfoCache = {
    async get(ips) { return Object.fromEntries(ips.filter(ip => stored[ip]).map(ip => [ip, stored[ip]!])); },
    async put(records) { Object.assign(stored, records); }
  };
  const calls: string[] = [];
  const fetcher = async (url: string, init: RequestInit) => {
    calls.push(url);
    assert.equal(url, 'https://api.ipinfo.io/batch/lite');
    assert.equal(new Headers(init.headers).get('authorization'), 'Bearer test-token');
    assert.deepEqual(JSON.parse(String(init.body)), ['8.8.8.8', '2001:4860:4860::8888']);
    return Response.json({
      '8.8.8.8': { ip: '8.8.8.8', asn: 'AS15169', as_name: 'Google LLC', country_code: 'US' },
      '2001:4860:4860::8888': { ip: '2001:4860:4860::8888', asn: 'AS15169', country_code: 'US' }
    });
  };
  const budget = new Budget();
  try {
    const args: Parameters<typeof ipNetworks> = [['8.8.8.8', '2001:4860:4860::8888', '127.0.0.1', '8.8.8.8'], ['8.8.8.8'],
      { '8.8.8.8': 60 }, ['www.example.com -> example.com'], 'test-token', budget, fetcher, cache];
    const first = await ipNetworks(...args);
    assert.equal(first.enrichment, 'available');
    assert.equal(first.total_address_count, 2);
    assert.deepEqual((first.addresses as Array<Record<string, unknown>>).map(item => item.ip), ['8.8.8.8', '2001:4860:4860::8888']);
    assert.equal((first.addresses as Array<Record<string, unknown>>)[0]?.sampled, true);
    assert.equal((first.addresses as Array<Record<string, unknown>>)[1]?.sampled, false);
    assert.equal((first.addresses as Array<Record<string, unknown>>)[0]?.dns_ttl, 60);
    const second = await ipNetworks(...args);
    assert.equal(second.enrichment, 'available');
    assert.equal(calls.length, 1);
    assert.equal(JSON.stringify(second).includes('test-token'), false);
  } finally { budget.close(); }
});

test('IPinfo failure is explicit and does not discard DNS addresses', async () => {
  const budget = new Budget();
  try {
    const result = await ipNetworks(['1.1.1.1'], [], {}, [], 'test-token', budget, async () => { throw Error('down'); });
    assert.equal(result.enrichment, 'unavailable');
    assert.equal((result.addresses as Array<unknown>).length, 1);
  } finally { budget.close(); }
});

test('IPinfo failure preserves previously cached metadata for one address', async () => {
  const budget = new Budget();
  const cache: IpinfoCache = {
    async get() { return { '1.1.1.1': { ip: '1.1.1.1', asn: 'AS13335', country_code: 'US' } }; },
    async put() { throw Error('cache write unavailable'); }
  };
  try {
    const result = await ipNetworks(['1.1.1.1', '8.8.8.8'], [], {}, [], 'test-token', budget,
      async () => { throw Error('provider down'); }, cache);
    assert.equal(result.enrichment, 'partial');
    assert.equal((result.addresses as Array<Record<string, unknown>>)[0]?.asn, 'AS13335');
    assert.equal((result.addresses as Array<Record<string, unknown>>)[1]?.asn, undefined);
  } finally { budget.close(); }
});

test('IPinfo matches uncompressed IPv6 from the DNS decoder against compressed provider keys', async () => {
  const fetcher = async (_url: string, init: RequestInit) => {
    assert.deepEqual(JSON.parse(String(init.body)), ['2001:4860:4860::8888']);
    return Response.json({ '2001:4860:4860::8888': { ip: '2001:4860:4860::8888', asn: 'AS15169', country_code: 'US' } });
  };
  const budget = new Budget();
  try {
    const result = await ipNetworks(['2001:4860:4860:0:0:0:0:8888'], [], { '2001:4860:4860::8888': 300 }, [], 'test-token', budget, fetcher);
    assert.equal(result.enrichment, 'available');
    assert.deepEqual(result.addresses, [{ ip: '2001:4860:4860::8888', family: 'IPv6', sampled: false, dns_ttl: 300, asn: 'AS15169', country_code: 'US' }]);
  } finally { budget.close(); }
});

test('IPinfo reports no_addresses rather than an outage when there is nothing to enrich', async () => {
  const budget = new Budget();
  try {
    const result = await ipNetworks([], [], {}, [], 'test-token', budget, async () => { throw Error('called'); });
    assert.equal(result.enrichment, 'no_addresses');
  } finally { budget.close(); }
});
