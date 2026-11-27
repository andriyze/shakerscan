import ipaddr from 'ipaddr.js';
import { abortable, type Budget } from './budget.ts';
import { PublicError } from './response.ts';

const DAY = 86_400_000;
export function quotaWindow(now: number) {
  return { day: Math.floor(now / DAY), reset: (Math.floor(now / DAY) + 1) * DAY };
}
// A single IPv6 subscriber normally controls a whole /64, so it is one caller.
export function callerPrefix(ip: string): string {
  const address = ipaddr.process(ip);
  if (address.kind() === 'ipv4') return address.toString();
  const bytes = address.toByteArray().slice(0, 8).concat(Array(8).fill(0));
  return ipaddr.fromByteArray(bytes).toString() + '/64';
}
export async function quotaKey(ip: string, secret: string): Promise<string> {
  if (!secret || secret.length < 32 || !ipaddr.isValid(ip)) throw new PublicError('service_unavailable');
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const digest = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode('check:v1:' + callerPrefix(ip)));
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
}

