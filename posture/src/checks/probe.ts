import http from 'node:http';
import https from 'node:https';
import { checkServerIdentity, type TLSSocket } from 'node:tls';
import { X509Certificate } from 'node:crypto';
import { isIP } from 'node:net';
import { Budget } from '../budget.ts';
import { isPublicAddress } from '../safety.ts';
import { normalizeTarget } from '../target.ts';
import { parseHead, redirectKind, type Head } from '../http.ts';
import type { Check } from '../types.ts';
import { CORS_PROBE_ORIGIN, corsCheck, headerCheck } from './policy.ts';

export interface TLSHead extends Head { protocol?: string; cipher?: string; certificateDaysRemaining?: number;
  certificate?: { ip_address_match?: boolean; valid_from?: string; valid_to?: string; issuer?: string; subject?: string; san_names?: string[]; fingerprint256?: string; alpn?: string;
    public_key_type?: string; public_key_bits?: number; public_key_curve?: string; signature_algorithm?: string;
    chain?: Array<{ subject?: string; issuer?: string; valid_to?: string; fingerprint256?: string }> } }
export interface WebFact { ip: string; status_code?: number; tls_protocol?: string; cipher?: string;
  certificate?: TLSHead['certificate'] }
export function selectAddressSamples(addresses: string[]): [string | undefined, string | undefined] {
  // This Lambda has IPv4 egress only. Never open an IPv6 socket that the
  // runtime cannot route; preserve the AAAA evidence as untested instead.
  const ipv4 = [...new Set(addresses.filter(ip => isIP(ip) === 4))];
  return [ipv4[0], ipv4[1]];
}
export function httpsResponseStatus(statuses: number[]): Check['status'] {
  return statuses.some(status => status >= 500) ? 'warn' : statuses.length ? 'pass' : 'unknown';
}
// No resolver is consulted by the socket. The hostname remains the authority for
// HTTP Host, TLS SNI and Node's default certificate/hostname verification.
type Probe = 'default' | 'tls12' | 'tls13' | 'cors' | 'preflight' | 'file';
// An IP-address target is its own pinned address: no SNI is sent (TLS forbids IP SNI), and
// the chain is still verified while the IP identity result is recorded, not enforced.
export function pinnedOptions(host: string, ip: string, secure: boolean, probe: Probe = 'default', path = '/'): https.RequestOptions {
  const ipTarget = isIP(host) !== 0;
  if ((ipTarget ? host !== ip : normalizeTarget(host) !== host) || !isPublicAddress(ip)) throw new Error('Unsafe destination');
  if (path.length > 512 || !path.startsWith('/') || path.startsWith('//') || /[\x00-\x20\x7f#\\]/.test(path)) throw new Error('Unsafe path');
  return { hostname: host, port: secure ? 443 : 80, method: probe === 'cors' || probe === 'file' ? 'GET' : probe === 'preflight' ? 'OPTIONS' : 'HEAD', path,
    agent: false, ...(ipTarget ? {} : { servername: host }), rejectUnauthorized: true, minVersion: 'TLSv1.2',
    ...(secure ? { ALPNProtocols: ['http/1.1'] } : {}),
    ...(probe === 'tls12' ? { maxVersion: 'TLSv1.2' as const } : {}),
    ...(probe === 'tls13' ? { minVersion: 'TLSv1.3' as const, maxVersion: 'TLSv1.3' as const } : {}),
    family: isIP(ip),
    lookup: (_name, _options, callback) => callback(null, ip, isIP(ip)),
    maxHeaderSize: 16384, headers: { Host: isIP(host) === 6 ? `[${host}]` : host, 'User-Agent': 'ShakerScan-Public/0.4', Accept: '*/*', Connection: 'close',
      ...(['cors', 'preflight'].includes(probe) ? { Origin: CORS_PROBE_ORIGIN } : {}),
      ...(probe === 'preflight' ? { 'Access-Control-Request-Method': 'GET' } : {}) } };
}
export async function pinnedHead(host: string, ip: string, secure: boolean, budget: Budget, probe: Probe = 'default', path = '/'): Promise<TLSHead> {
  const options = pinnedOptions(host, ip, secure, probe, path);
  let identityMatched: boolean | undefined;
  if (secure && isIP(host)) options.checkServerIdentity = (name, cert) => { identityMatched = !checkServerIdentity(name, cert); return undefined; };
  budget.reserve();
  return new Promise((resolve, reject) => {
    const signal = AbortSignal.any([budget.signal, AbortSignal.timeout(Math.max(1, Math.min(3000, budget.deadline - Date.now())))]);
    const req = (secure ? https : http).request({ ...options, signal }, res => {
      try {
        const raw = [`HTTP/1.1 ${res.statusCode}`];
        for (let i = 0; i < res.rawHeaders.length; i += 2) raw.push(`${res.rawHeaders[i]}: ${res.rawHeaders[i + 1]}`);
        const head: TLSHead = parseHead(raw.join('\r\n'));
        if (secure) {
          const socket = res.socket as TLSSocket;
          if (!socket.authorized) throw new Error('Unverified TLS');
          const protocol = socket.getProtocol();
          if (protocol === 'TLSv1.2' || protocol === 'TLSv1.3') head.protocol = protocol;
          const cipher = socket.getCipher().standardName ?? socket.getCipher().name;
          if (cipher && /^[A-Za-z0-9_-]{1,100}$/.test(cipher)) head.cipher = cipher;
          const validTo = Date.parse(socket.getPeerCertificate().valid_to ?? '');
          if (Number.isFinite(validTo)) head.certificateDaysRemaining = Math.floor((validTo - Date.now()) / 86400000);
          const cert = socket.getPeerCertificate();
          const printable = (value: unknown, max = 250) => typeof value === 'string' && value.length <= max && /^[\x20-\x7e]+$/.test(value) ? value : undefined;
          const san = (cert.subjectaltname ?? '').split(', ').filter(value => value.startsWith('DNS:'))
            .map(value => value.slice(4)).filter(value => printable(value, 253)).slice(0, 12);
          let keyType: string | undefined, keyBits: number | undefined, keyCurve: string | undefined, signatureAlgorithm: string | undefined;
          let chain: NonNullable<NonNullable<TLSHead['certificate']>['chain']> | undefined;
          try {
            const leaf = new X509Certificate(cert.raw);
            const key = leaf.publicKey;
            keyType = printable(key.asymmetricKeyType, 32);
            const details = key.asymmetricKeyDetails;
            if (details && 'modulusLength' in details && Number.isSafeInteger(details.modulusLength)) keyBits = details.modulusLength;
            if (details && 'namedCurve' in details) keyCurve = printable(details.namedCurve, 64);
            if (keyCurve) keyBits = ({ prime256v1: 256, secp256k1: 256, secp384r1: 384, secp521r1: 521 } as Record<string, number>)[keyCurve] ?? keyBits;
            if (keyType === 'ed25519') keyBits = 256;
            if (keyType === 'ed448') keyBits = 456;
            signatureAlgorithm = printable(leaf.signatureAlgorithm, 100);
            chain = [];
            let current = socket.getPeerCertificate(true);
            const seen = new Set<string>();
            for (let depth = 0; depth < 4 && current?.raw; depth++) {
              const x509 = new X509Certificate(current.raw);
              if (seen.has(x509.fingerprint256)) break;
              seen.add(x509.fingerprint256);
              chain.push({ subject: printable(current.subject?.CN), issuer: printable(current.issuer?.CN),
                valid_to: printable(current.valid_to, 64), fingerprint256: printable(x509.fingerprint256, 95) });
              if (!current.issuerCertificate || current.issuerCertificate === current) break;
              current = current.issuerCertificate;
            }
          } catch { /* Certificate verification already succeeded; metadata may be unavailable. */ }
          head.certificate = {
            ...(identityMatched === undefined ? {} : { ip_address_match: identityMatched }),
            valid_from: printable(cert.valid_from, 64), valid_to: printable(cert.valid_to, 64),
            issuer: printable(cert.issuer?.O ?? cert.issuer?.CN), subject: printable(cert.subject?.CN),
            san_names: san, fingerprint256: printable(cert.fingerprint256, 95),
            alpn: printable(socket.alpnProtocol, 32), public_key_type: keyType, public_key_bits: keyBits,
            public_key_curve: keyCurve, signature_algorithm: signatureAlgorithm, chain
          };
        }
        resolve(head);
      } catch (error) { reject(error); }
      finally { res.destroy(); req.destroy(); }
    });
    req.maxHeadersCount = 100;
    req.once('error', reject);
    req.end();
  });
}
export async function pinnedText(host: string, ip: string, path: string, budget: Budget): Promise<{ status: number; body: string; content_type?: string }> {
  const options = pinnedOptions(host, ip, true, 'file', path);
  if (isIP(host)) options.checkServerIdentity = () => undefined;
  budget.reserve();
  return new Promise((resolve, reject) => {
    const signal = AbortSignal.any([budget.signal, AbortSignal.timeout(Math.max(1, Math.min(1500, budget.deadline - Date.now())))]);
    const req = https.request({ ...options, signal }, res => {
      const chunks: Buffer[] = []; let size = 0;
      res.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > 32768) { req.destroy(new Error('body_too_large')); return; }
        chunks.push(chunk);
      });
      res.once('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8'),
        content_type: typeof res.headers['content-type'] === 'string' ? res.headers['content-type'].slice(0, 128) : undefined }));
      res.once('error', reject);
    });
    req.once('error', reject);
    req.end();
  });
}
export async function redirectChain(host: string, ip: string, first: TLSHead, budget: Budget,
  probe: typeof pinnedHead = pinnedHead): Promise<{ chain: string[]; finalStatus: number; complete: boolean }> {
  const chain: string[] = [];
  let current = first, secure = false, currentUrl = new URL(`http://${host}/`);
  for (let hop = 0; hop < 4; hop++) {
    const location = current.headers.get('location');
    const redirect: string = [301, 302, 303, 307, 308].includes(current.status) ? redirectKind(location, host, secure) : 'none';
    chain.push(`${current.status} ${redirect}`);
    if (redirect === 'none') return { chain, finalStatus: current.status, complete: true };
    if (!['same_host_http', 'same_host_https'].includes(redirect) || !location || hop === 3) return { chain, finalStatus: current.status, complete: false };
    try {
      const url = new URL(location, currentUrl);
      const path = url.pathname + url.search;
      secure = redirect === 'same_host_https';
      current = await probe(host, ip, secure, budget, 'default', path);
      currentUrl = url;
    } catch { return { chain, finalStatus: current.status, complete: false }; }
  }
  return { chain, finalStatus: current.status, complete: false };
}
export async function webChecks(host: string, addresses: string[], budget: Budget, corsPath = '/', onFacts?: (facts: WebFact[]) => void): Promise<Check[]> {
  const checks: Check[] = [
    { id: 'http.response', name: 'HTTPS response', group: 'http', status: 'unknown', detail: 'HTTPS evidence was unavailable; this is not proof of a target defect.' },
    { id: 'tls.handshake', name: 'TLS handshake', group: 'tls', status: 'unknown', detail: 'A trusted hostname-verified TLS connection was not established.' },
    { id: 'tls.ciphers', name: 'TLS protocol and cipher samples', group: 'tls', status: 'unknown', detail: 'Negotiated TLS protocol versions and ciphers were not observed; this is not a full support inventory.' },
    { id: 'http.headers', name: 'HTTPS security headers', group: 'http', status: 'unknown', detail: 'HTTPS headers were not observed.' },
    { id: 'http.cors', name: 'CORS on HTTPS path', group: 'http', status: 'unknown', detail: 'A fixed foreign Origin was not tested on the requested HTTPS path.', evidence: { path: corsPath } },
    { id: 'http.redirect', name: 'HTTP redirect', group: 'http', status: 'unknown', detail: 'A same-host HTTP-to-HTTPS redirect was not established.' }
  ];
  if (!addresses.length || addresses.some(ip => !isPublicAddress(ip))) return checks;
  const [primary, alternate] = selectAddressSamples(addresses);
  if (!primary) {
    checks[0] = { ...checks[0]!, detail: 'Only IPv6 addresses were observed; this Lambda has no IPv6 egress, so HTTPS was not probed.' };
    checks[1] = { ...checks[1]!, detail: 'Only IPv6 addresses were observed; this Lambda has no IPv6 egress, so TLS was not probed.' };
    return checks;
  }
  const [tls, clear, tls12, tls13, cors, preflight, other, other12, other13] = await Promise.allSettled([
    pinnedHead(host, primary, true, budget), pinnedHead(host, primary, false, budget),
    pinnedHead(host, primary, true, budget, 'tls12'), pinnedHead(host, primary, true, budget, 'tls13'),
    pinnedHead(host, primary, true, budget, 'cors', corsPath),
    pinnedHead(host, primary, true, budget, 'preflight', corsPath),
    alternate ? pinnedHead(host, alternate, true, budget) : Promise.resolve(undefined),
    alternate ? pinnedHead(host, alternate, true, budget, 'tls12') : Promise.resolve(undefined),
    alternate ? pinnedHead(host, alternate, true, budget, 'tls13') : Promise.resolve(undefined)]);
  const firstHead = tls.status === 'fulfilled' ? tls.value : undefined;
  const otherHead = other.status === 'fulfilled' ? other.value : undefined;
  onFacts?.([[primary, firstHead], [alternate, otherHead]].filter((pair): pair is [string, TLSHead] => Boolean(pair[0] && pair[1]))
    .map(([ip, head]) => ({ ip, status_code: head.status, tls_protocol: head.protocol, cipher: head.cipher, certificate: head.certificate })));
  if (firstHead || otherHead) {
    const head = firstHead ?? otherHead!;
    const headAddress = firstHead ? primary! : alternate!;
    const statuses = [head.status, ...(firstHead && otherHead ? [otherHead.status] : [])];
    checks[0] = { ...checks[0]!, status: httpsResponseStatus(statuses),
      detail: `HTTPS root returned status ${head.status}${firstHead && otherHead ? `; the second sampled address returned ${otherHead.status}` : !firstHead ? '; the primary sampled address could not be determined' : alternate ? '; the second sampled address could not be determined' : ''}. Redirects were not followed.`,
      evidence: { status_code: head.status, validated_address_count: addresses.length, sampled_address_count: statuses.length,
        sampled_families: [isIP(headAddress) === 4 ? 'IPv4' : 'IPv6', ...(firstHead && otherHead ? [isIP(alternate!) === 4 ? 'IPv4' : 'IPv6'] : [])] } };
    const verified = [firstHead ? primary! : undefined, otherHead ? alternate! : undefined].filter((x): x is string => Boolean(x));
    const expiry = [firstHead?.certificateDaysRemaining !== undefined ? `${primary} ${firstHead.certificateDaysRemaining}` : undefined,
      otherHead?.certificateDaysRemaining !== undefined ? `${alternate} ${otherHead.certificateDaysRemaining}` : undefined].filter((x): x is string => Boolean(x));
    const ipMismatch = isIP(host) !== 0 && head.certificate?.ip_address_match === false;
    checks[1] = { ...checks[1]!, status: ipMismatch || (head.certificateDaysRemaining !== undefined && head.certificateDaysRemaining < 30) ? 'warn' : 'pass',
      detail: `${isIP(host) ? ipMismatch ? 'Certificate chain trust and validity passed; the certificate does not list this IP address.' : 'Certificate trust, validity and IP address identity passed.' : 'Certificate trust, validity and hostname verification passed.'}${head.certificateDaysRemaining !== undefined ? ` Certificate expires in ${head.certificateDaysRemaining} days.` : ''}`,
      evidence: { ...(head.certificateDaysRemaining === undefined ? {} : { certificate_days_remaining: head.certificateDaysRemaining }),
        verified_addresses: verified, certificate_expiry_by_address: expiry } };
    checks[3] = headerCheck(head);
    const samples = [[primary, firstHead], [primary, tls12.status === 'fulfilled' ? tls12.value : undefined],
      [primary, tls13.status === 'fulfilled' ? tls13.value : undefined], [alternate, otherHead],
      [alternate, other12.status === 'fulfilled' ? other12.value : undefined],
      [alternate, other13.status === 'fulfilled' ? other13.value : undefined]] as const;
    const addressCiphers = [...new Set(samples.filter((item): item is readonly [string, TLSHead] => Boolean(item[0] && item[1]?.protocol && item[1]?.cipher))
      .map(([ip, sample]) => `${ip} ${sample.protocol}/${sample.cipher}`))];
    const ciphers = [...new Set(addressCiphers.map(value => value.slice(value.indexOf(' ') + 1)))];
    const protocolResults: Array<readonly [string, 'TLSv1.2' | 'TLSv1.3', PromiseSettledResult<TLSHead | undefined>]> =
      [[primary, 'TLSv1.2', tls12], [primary, 'TLSv1.3', tls13],
        ...(alternate ? [[alternate, 'TLSv1.2', other12], [alternate, 'TLSv1.3', other13]] as const : [])];
    const addressProtocols = protocolResults.map(([ip, version, result]) =>
      `${ip} ${version} ${result.status === 'fulfilled' && result.value?.protocol === version ? 'negotiated' : 'not_observed'}`);
    const negotiatedProtocols = [...new Set(samples.map(([, sample]) => sample?.protocol).filter((value): value is string => Boolean(value)))];
    const weak = ciphers.some(cipher => /(?:RC4|3DES|NULL|CBC|TLS_RSA_)/i.test(cipher));
    checks[2] = { ...checks[2]!, status: ciphers.length ? weak ? 'warn' : 'pass' : 'unknown',
      detail: ciphers.length ? weak ? 'A legacy cipher was negotiated in a bounded TLS handshake; this is not a full support inventory.' : 'Modern ciphers were negotiated in bounded TLS handshakes; this is not a full support inventory.' : checks[2]!.detail,
      evidence: { negotiated_ciphers: ciphers, address_ciphers: addressCiphers,
        negotiated_protocols: negotiatedProtocols, address_protocol_probes: addressProtocols } };
  }
  if (cors.status === 'fulfilled') checks[4] = corsCheck(cors.value, corsPath, preflight.status === 'fulfilled' ? preflight.value : undefined);
  if (clear.status === 'fulfilled') {
    const head = clear.value;
    const redirect = [301, 302, 303, 307, 308].includes(head.status) ? redirectKind(head.headers.get('location'), host, false) : 'none';
    const chain = await redirectChain(host, primary, head, budget);
    checks[5] = { ...checks[5]!, status: redirect === 'same_host_https' ? 'pass' : 'unknown',
      detail: `HTTP root returned ${head.status}; ${chain.chain.length} same-host redirect-chain response${chain.chain.length === 1 ? '' : 's'} observed.`,
      evidence: { status_code: head.status, redirect, redirect_chain: chain.chain, final_status_code: chain.finalStatus,
        chain_complete: chain.complete } };
  }
  return checks;
}
