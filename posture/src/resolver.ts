import dgram from 'node:dgram';
import net from 'node:net';
import { readFileSync } from 'node:fs';
import { RESOLVER } from './dns.ts';
import type { Fetcher } from './types.ts';

/** The first nameserver in resolv.conf, or null when none is configured. */
export function systemNameserver(conf = '/etc/resolv.conf'): string | null {
  try {
    for (const line of readFileSync(conf, 'utf8').split('\n')) {
      const match = /^\s*nameserver\s+(\S+)/.exec(line);
      if (match && net.isIP(match[1]!)) return match[1]!;
    }
  } catch { /* No resolv.conf: callers fall back to DNS over HTTPS. */ }
  return null;
}

function udp(server: string, port: number, query: Uint8Array, signal: AbortSignal): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket(net.isIP(server) === 6 ? 'udp6' : 'udp4');
    const done = (error?: Error, reply?: Buffer) => { signal.removeEventListener('abort', abort); socket.close(); error ? reject(error) : resolve(reply!); };
    const abort = () => done(new Error('dns_timeout'));
    signal.addEventListener('abort', abort, { once: true });
    socket.on('error', error => done(error));
    socket.on('message', reply => { if (reply.length >= 2 && reply[0] === query[0] && reply[1] === query[1]) done(undefined, reply); });
    socket.send(query, port, server);
  });
}

function tcp(server: string, port: number, query: Uint8Array, signal: AbortSignal): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: server, port });
    const chunks: Buffer[] = [];
    const done = (error?: Error, reply?: Buffer) => { signal.removeEventListener('abort', abort); socket.destroy(); error ? reject(error) : resolve(reply!); };
    const abort = () => done(new Error('dns_timeout'));
    signal.addEventListener('abort', abort, { once: true });
    socket.on('error', error => done(error));
    socket.on('connect', () => socket.end(Buffer.concat([Buffer.from([query.length >> 8, query.length & 255]), query])));
    socket.on('data', chunk => {
      chunks.push(chunk);
      const all = Buffer.concat(chunks);
      if (all.length > 65537) done(new Error('dns_too_large'));
      else if (all.length >= 2 && all.length >= 2 + all.readUInt16BE(0)) done(undefined, all.subarray(2, 2 + all.readUInt16BE(0)));
    });
  });
}

/**
 * Sends the engine's DNS wire queries to the system resolver instead of DNS over HTTPS, so an
 * instance can check names only its own network resolves. Responses are parsed by the same
 * decoder; any non-resolver URL is fetched normally.
 */
export function systemResolverFetcher(server: string, fallback: Fetcher = fetch, port = 53): Fetcher {
  return async (url, init) => {
    if (url !== RESOLVER) return fallback(url, init);
    const query = init.body as Uint8Array;
    const signal = init.signal ?? AbortSignal.timeout(3000);
    let reply = await udp(server, port, query, signal);
    if (reply.length > 2 && (reply[2]! & 0x02)) reply = await tcp(server, port, query, signal); // TC: retry over TCP.
    return new Response(reply, { status: 200, headers: { 'Content-Type': 'application/dns-message' } });
  };
}
