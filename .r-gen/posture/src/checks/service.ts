import { Budget } from '../budget.ts';
import { observation, summarize } from '../check.ts';
import { answers, resolve } from '../dns.ts';
import { TYPES } from '../wire.ts';
import { quotaKey, quotaWindow } from '../quota.ts';
import { readCheckRequest } from '../request.ts';
import { normalizeTarget } from '../target.ts';
import { errorResponse, json, PublicError } from '../response.ts';
import { selectAddressSamples, webChecks, type WebFact } from './probe.ts';
import { dkimCheck } from './dkim.ts';
import { factualResponse } from './factual.ts';
import { caaPolicy } from './caa.ts';
import { dmarcPolicy } from './dmarc.ts';
import { mxTargets } from './mx.ts';
import { spfTree } from './spf.ts';
import { nameserverHealth } from './nameservers.ts';
import { dnssecPublishedKeys, dnssecValidation } from './dnssec.ts';
import { canonicalIp, ipNetworks } from './ipinfo.ts';
import { checkCallerCountry } from './geo.ts';
import { httpsDnsFact, mailTransportFacts, securityTextFact } from './extra.ts';
import { transientResult, type Store } from './store.ts';
import { isRestrictedTarget } from './restricted.ts';
import { ipObservation, parseIpTarget, restrictedNetwork, reverseDns } from './iptarget.ts';
import { isIP } from 'node:net';
import type { Fetcher } from '../types.ts';

export interface Event {
  version: string; rawPath: string; rawQueryString: string;
  headers: Record<string, string | undefined>; body?: string; isBase64Encoded?: boolean;
  requestContext: { http: { method: string; sourceIp: string } };
}
/** Target restrictions the hosted public service applies; a self-hosted instance disables them. */
export interface ServicePolicy {
  /** Refuse government, military and intergovernmental hostnames. */
  restrictTargets: boolean;
  /** Screen IP-address targets by network ownership and PTR before any connection, failing closed. */
  screenIpTargets: boolean;
}
export const HOSTED_POLICY: ServicePolicy = { restrictTargets: true, screenIpTargets: true };
export const INSTANCE_POLICY: ServicePolicy = { restrictTargets: false, screenIpTargets: false };

export async function handle(event: Event, store: Store, secret: string, enabled: boolean, fetcher: Fetcher = fetch,
  ipinfoToken = '', ipinfoFetcher: Fetcher = fetch, geoEnabled = false, policy: ServicePolicy = HOSTED_POLICY) {
  const started = Date.now(), requestId = crypto.randomUUID(), budget = new Budget(8000, undefined, 100);
  const route = event.rawPath === '/health' ? 'health' : event.rawPath === '/v1/check' ? 'check' : 'unknown';
  let response: Response, hit = false, outcome = 'ok', allow: string | undefined;
  try {
    if (event.version !== '2.0') throw new PublicError('invalid_request');
    if (route === 'unknown') throw new PublicError('route_not_found');
    allow = route === 'health' ? 'GET' : 'POST';
    if (event.requestContext.http.method !== allow) throw new PublicError('method_not_allowed');
    if (event.rawQueryString) throw new PublicError('invalid_request');
    if (route === 'health') response = json({ status: 'ok', service: 'shakerscan-public', version: '0.6.0' });
    else {
      // API Gateway supplies this field. Never accept CF-Connecting-IP or XFF.
      const identity = await quotaKey(event.requestContext.http.sourceIp, secret);
      if (geoEnabled) await checkCallerCountry(event.requestContext.http.sourceIp, identity, ipinfoToken, budget, ipinfoFetcher, store.callerCountry);
      const minute = Math.floor(Date.now() / 60000);
      // Per-caller admission covers cache hits and invalid bodies; the stage throttle is global.
      if (!await store.consume(`min:${minute}:${identity}`, 30, (minute + 2) * 60, budget)) throw new PublicError('rate_limited', Math.max(1, 60 - Math.floor(Date.now() / 1000) % 60));
      const now = Date.now(), hour = Math.floor(now / 3600000), hourReset = (hour + 1) * 3600000, { day, reset } = quotaWindow(now);
      if ((event.body?.length ?? 0) > (event.isBase64Encoded ? 2732 : 2048)) throw new PublicError('body_too_large');
      const body = Buffer.from(event.body ?? '', event.isBase64Encoded ? 'base64' : 'utf8');
      if (body.byteLength > 2048) throw new PublicError('body_too_large');
      const headers = new Headers();
      for (const [key, value] of Object.entries(event.headers)) if (value !== undefined && ['content-type', 'content-length', 'content-encoding'].includes(key.toLowerCase())) headers.set(key, value);
      const input = await readCheckRequest(new Request(`https://public.invalid${event.rawPath}`, { method: 'POST', headers, body }), budget, true);
      const ipTarget = parseIpTarget(input.target);
      const target = ipTarget ?? normalizeTarget(input.target);
      if (!ipTarget && policy.restrictTargets && isRestrictedTarget(target)) throw new PublicError('target_restricted');
      if (ipTarget && input.dkim_selector) throw new PublicError('invalid_request');
      const selector = input.dkim_selector;
      const path = input.path ?? '/';
      if (!enabled) throw new PublicError('service_unavailable');
      let data = await store.get(target, selector, budget, path); hit = data !== null;
      if (ipinfoToken && data?.v2_extras?.[0]?.result?.enrichment === 'unconfigured') { data = null; hit = false; }
      if (!data) {
        let screened: Record<string, unknown> | undefined;
        if (ipTarget) {
          // Government and military networks are screened before quota and before any connection.
          const [network, ptr] = await Promise.all([
            ipNetworks([target], isIP(target) === 4 ? [target] : [], {}, [], ipinfoToken, budget, ipinfoFetcher, store.ipinfo),
            reverseDns(target, budget, fetcher)]);
          if (policy.screenIpTargets) {
            // Without ownership evidence the screen cannot run, so the check fails closed.
            if (network.enrichment !== 'available') throw new PublicError('service_unavailable');
            if (restrictedNetwork((network.addresses as Array<Record<string, unknown>>)[0], ptr)) throw new PublicError('target_restricted');
          }
          screened = { ...network, reverse_dns: ptr ?? [], reverse_dns_available: ptr !== null };
        }
        if (!await store.consume(`hour:${hour}:${identity}`, 25, Math.floor(hourReset / 1000) + 3600, budget)) throw new PublicError('hourly_quota_exceeded', Math.max(1, Math.ceil((hourReset - Date.now()) / 1000)));
        if (!await store.consume(`day:${day}:${identity}`, 100, Math.floor(reset / 1000) + 3600, budget)) throw new PublicError('daily_quota_exceeded', Math.max(1, Math.ceil((reset - Date.now()) / 1000)));
        if (screened) data = await ipObservation(target, screened, budget, path);
        else {
          const results = await resolve(target, budget, fetcher);
          data = observation(target, results);
          const ipv4 = answers(results.A, target, TYPES.A).map(r => r.value!).filter(Boolean);
          const addresses = [...ipv4, ...answers(results.AAAA, target, TYPES.AAAA).map(r => r.value!).filter(Boolean).map(canonicalIp)];
          const ttls = Object.fromEntries([results.A, results.AAAA].flatMap(result => result.state === 'ok' ?
            result.records.filter(record => record.section === 'answer' && (record.type === TYPES.A || record.type === TYPES.AAAA) && record.value && record.ttl !== undefined)
              .map(record => [canonicalIp(record.value!), record.ttl!] as const) : []));
          const aliases = results.A.state === 'ok' ? results.A.records.filter(record => record.type === TYPES.CNAME && record.section === 'answer')
            .map(record => `${record.name} -> ${record.value}`).slice(0, 8) : [];
          let webFacts: WebFact[] = [];
          const sampled = selectAddressSamples(addresses).filter((ip): ip is string => Boolean(ip));
          let hasMail = false;
          try { hasMail = results.MX.state === 'ok' && answers(results.MX, target, TYPES.MX)
            .some(record => Boolean(record.value)); } catch { /* Incomplete MX evidence does not justify policy-file probes. */ }
          data.checks[0]!.detail = ipv4.length ? 'Public address records observed; HTTP and HTTPS use validated IPv4 addresses without another DNS lookup.' :
            addresses.length ? 'Only public IPv6 addresses were observed; this Lambda cannot probe them.' : data.checks[0]!.detail;
          const [nameservers, dnssec, caa, mx, spf, dmarc, dkim, web, network, mailTransport, securityText, httpsDns] = await Promise.all([
            nameserverHealth(target, results.NS, budget, fetcher),
            dnssecValidation(target, results, budget, fetcher),
            caaPolicy(target, results.CAA, budget, fetcher),
            mxTargets(target, results.MX, budget, fetcher),
            spfTree(target, results.TXT, budget, fetcher),
            dmarcPolicy(target, results.DMARC, results.A.state === 'ok' && results.A.rcode !== 3, budget, fetcher),
            selector ? dkimCheck(target, selector, budget, fetcher) : Promise.resolve(data.checks[7]!),
            webChecks(target, addresses, budget, path, facts => { webFacts = facts; }),
            ipNetworks(addresses, sampled, ttls, aliases, ipinfoToken, budget, ipinfoFetcher, store.ipinfo),
            mailTransportFacts(target, hasMail, budget, fetcher),
            securityTextFact(target, sampled[0], budget),
            httpsDnsFact(target, budget, fetcher)
          ]);
          await dnssecPublishedKeys(dnssec, String(nameservers.evidence?.zone ?? target), budget, fetcher);
          data.checks[1] = nameservers;
          data.checks[2] = dnssec;
          data.checks[3] = caa;
          data.checks[4] = mx;
          data.checks[5] = spf;
          data.checks[6] = dmarc;
          data.checks[7] = dkim;
          data.checks.push(...web);
          data.v2_extras = JSON.parse(JSON.stringify([
            { id: 'ip.network', name: 'IP network', group: 'ip', scope: 'Validated public A/AAAA answers; IPinfo Lite ASN and country enrichment, up to eight addresses', result: network },
            ...mailTransport, securityText, httpsDns,
            { id: 'http.connections', name: 'Sampled HTTPS connections', group: 'http',
              scope: 'Status, leaf key and signature, certificate chain exposed by Node TLS (up to four entries), and negotiated ALPN from up to two pinned IPv4 HTTPS connections offering HTTP/1.1',
              result: { connections: webFacts } }
          ]));
          data.limitations[0] = 'Up to seven initial HEAD requests, one GET and one OPTIONS CORS probe, fixed-path security.txt and optional MTA-STS GETs, and up to three same-host redirect hops. IPv6 egress is unavailable; negotiated ciphers and protocol versions are samples.';
          data.limitations[1] = selector ? 'The selected DKIM DNS key was checked; no email signature was verified. SPF sender authorization was not evaluated. Name-server reachability and delegation are sampled.' : 'DKIM requires a caller-supplied selector. SPF sender authorization was not evaluated. Name-server reachability and delegation are sampled.';
        }
        data.summary = summarize(data.checks);
        // Sub-checks already degrade on deadline or outbound exhaustion; keep their partial
        // evidence, but cache it only briefly. Oversized results would fail json() on every hit.
        const truncated = budget.signal.aborted || Date.now() >= budget.deadline || budget.operations >= budget.maxOperations;
        const size = Math.max(JSON.stringify(data).length, JSON.stringify(factualResponse(data, false, requestId)).length);
        if (size <= 30000) await store.put(data, selector, budget, path, transientResult(data) || truncated);
      }
      response = json(factualResponse(data, hit, requestId));
    }
  } catch (error) { outcome = error instanceof PublicError ? error.code : 'exception'; response = errorResponse(error, requestId, allow); }
  finally { budget.close(); }
  console.log(JSON.stringify({ request_id: requestId, route, status: response.status, outcome, latency_ms: Date.now() - started, cache_hit: hit, outbound: budget.operations }));
  return { statusCode: response.status, headers: Object.fromEntries(response.headers), body: await response.text(), isBase64Encoded: false };
}
