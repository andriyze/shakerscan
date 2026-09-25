import dgram from 'node:dgram';
import { isIP } from 'node:net';
import { answers, query, type Result } from '../dns.ts';
import type { Budget } from '../budget.ts';
import { isPublicAddress } from '../safety.ts';
import type { Check, Fetcher } from '../types.ts';
import { decodeAnswer, encodeQuery, TYPES, type DnsAnswer, type QueryType } from '../wire.ts';

export type Exchange = (ip: string, request: Uint8Array, budget: Budget) => Promise<Uint8Array>;
export const udpExchange: Exchange = (ip, request, budget) => {
  budget.reserve();
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket(isIP(ip) === 6 ? 'udp6' : 'udp4');
    let done = false;
    const finish = (error?: unknown, data?: Uint8Array) => {
      if (done) return;
      done = true; clearTimeout(timer); budget.signal.removeEventListener('abort', abort); socket.close();
      if (error) reject(error); else resolve(data!);
    };
    const abort = () => finish(new Error('timeout'));
    const timer = setTimeout(abort, Math.max(1, Math.min(1200, budget.deadline - Date.now())));
    budget.signal.addEventListener('abort', abort, { once: true });
    socket.once('error', finish);
    socket.once('message', (data, remote) => {
      if (remote.address !== ip || remote.port !== 53 || data.length > 32768) finish(new Error('invalid_dns'));
      else finish(undefined, data);
    });
    socket.connect(53, ip, () => socket.send(request, error => { if (error) finish(error); }));
  });
};

export async function authoritativeQuery(host: string, type: QueryType, ip: string, budget: Budget,
  exchange: Exchange = udpExchange): Promise<DnsAnswer> {
  if (!isPublicAddress(ip) || isIP(ip) !== 4) throw new Error('unsafe destination');
  const id = crypto.getRandomValues(new Uint16Array(1))[0]!;
  const request = encodeQuery(host, type, id);
  request[2] = request[2]! & 0xfe; // Query the server directly without requesting recursion.
  return decodeAnswer(await exchange(ip, request, budget), { host, type, id });
}

function names(result: Result, domain: string): string[] {
  if (result.state !== 'ok') throw new Error('unavailable');
  return [...new Set(answers(result, domain, TYPES.NS).map(record => record.value).filter((v): v is string => Boolean(v)))].sort();
}
function referral(answer: DnsAnswer, zone: string): string[] {
  return [...new Set(answer.records.filter(record => record.type === TYPES.NS && record.name === zone &&
    (record.section === 'authority' || record.section === 'answer')).map(record => record.value).filter((v): v is string => Boolean(v)))].sort();
}
async function resolveServer(name: string, budget: Budget, fetcher: Fetcher): Promise<string | undefined> {
  if (!/^[a-z0-9.-]{1,253}$/.test(name)) return;
  const result = await query(name, 'A', budget, fetcher);
  if (result.state !== 'ok') return;
  try { return answers(result, name, TYPES.A).map(record => record.value).find(ip => ip && isPublicAddress(ip)); }
  catch { return; }
}

export async function nameserverHealth(host: string, initial: Result, budget: Budget, fetcher: Fetcher,
  exchange: Exchange = udpExchange): Promise<Check> {
  const checked = [host];
  let zone = host, child: string[] = [];
  const labels = host.split('.');
  for (let offset = 0; offset < Math.min(labels.length - 1, 8); offset++) {
    zone = labels.slice(offset).join('.');
    const result = offset === 0 ? initial : await query(zone, 'NS', budget, fetcher);
    try { child = names(result, zone); }
    catch { return { id: 'dns.nameservers', name: 'Name servers', group: 'dns', status: 'unknown',
      detail: 'NS discovery was incomplete.', evidence: { checked_names: checked } }; }
    if (child.length) break;
    if (offset < labels.length - 2) checked.push(labels.slice(offset + 1).join('.'));
  }
  if (!child.length) return { id: 'dns.nameservers', name: 'Name servers', group: 'dns', status: 'unknown',
    detail: 'No enclosing NS zone was observed.', evidence: { checked_names: checked, count: 0, names: [] } };
  const sampled = child.slice(0, 2);
  const responding: string[] = [], unresponsive: string[] = [], serials: string[] = [];
  await Promise.all(sampled.map(async name => {
    try {
      const ip = await resolveServer(name, budget, fetcher);
      if (!ip) throw new Error('no address');
      const answer = await authoritativeQuery(zone, 'SOA', ip, budget, exchange);
      const soa = answer.records.find(r => r.name === zone && r.type === TYPES.SOA && r.section === 'answer');
      if (answer.rcode !== 0 || !answer.aa || !soa) throw new Error('not authoritative');
      responding.push(name);
      if (soa.serial !== undefined) serials.push(`${name} ${soa.serial}`);
    } catch { unresponsive.push(name); }
  }));
  responding.sort(); unresponsive.sort();
  const parent = labels.slice(labels.length - zone.split('.').length + 1).join('.');
  let parentNames: string[] = [], delegation: string[] = [];
  const parentSampled: string[] = [];
  if (parent && parent !== zone) {
    try {
      const parentResult = await query(parent, 'NS', budget, fetcher);
      parentNames = names(parentResult, parent);
      for (const name of parentNames.slice(0, 2)) {
        parentSampled.push(name);
        const ip = await resolveServer(name, budget, fetcher);
        if (!ip) continue;
        const response = await authoritativeQuery(zone, 'NS', ip, budget, exchange);
        delegation = referral(response, zone);
        if (delegation.length) break;
      }
    } catch { /* Parent delegation remains unobserved. */ }
  }
  const evidence: NonNullable<Check['evidence']> = { zone, checked_names: checked, count: child.length, names: child.slice(0, 16),
    sampled_names: sampled, untested_names: child.slice(2, 16), responding_names: responding, unresponsive_names: unresponsive,
    soa_serials: serials.sort(), parent_names: parentNames.slice(0, 16), parent_sampled_names: parentSampled,
    parent_untested_names: parentNames.filter(name => !parentSampled.includes(name)).slice(0, 16),
    delegation_names: delegation.slice(0, 16) };
  if (delegation.length) evidence.delegation_matches = JSON.stringify(child) === JSON.stringify(delegation);
  return { id: 'dns.nameservers', name: 'Name servers', group: 'dns', status: responding.length && (!delegation.length || evidence.delegation_matches) ? 'pass' : 'unknown',
    detail: `Queried up to two authoritative NS hosts for ${zone} and up to two parent NS hosts for delegation.`, evidence };
}
