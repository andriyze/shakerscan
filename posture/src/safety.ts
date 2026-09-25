import ipaddr from 'ipaddr.js';

// Conservative policy: every special-use range is denied, including globally reachable exceptions.
const V4 = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
  '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16',
  '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4'].map(ipaddr.parseCIDR);
const V6 = ['2001::/23', '2001:db8::/32', '2002::/16', '3fff::/20'].map(ipaddr.parseCIDR);

// The hosted public service permits only public destinations. A self-hosted instance leaves
// that choice to its operator: every connectable unicast address and internal hostname is
// permitted. The policy is set once per process, before any check runs.
export type TargetPolicy = 'public' | 'any';
let targetPolicy: TargetPolicy = 'public';
export function configureTargetPolicy(policy: TargetPolicy): void { targetPolicy = policy; }
export function permitsAnyTarget(): boolean { return targetPolicy === 'any'; }

/** Whether the engine may connect to this address under the configured target policy. */
export function isPublicAddress(value: string): boolean {
  try {
    const address = ipaddr.parse(value);
    // Unspecified, multicast and broadcast addresses are never connectable destinations.
    if (targetPolicy === 'any') return !['unspecified', 'multicast', 'broadcast'].includes(address.range());
    if (address.range() !== 'unicast') return false;
    if (address.kind() === 'ipv4') return !V4.some(r => address.match(r));
    // Only currently allocated global unicast; excludes mapped/NAT64/ULA/link-local/etc.
    return address.match(ipaddr.parseCIDR('2000::/3')) && !V6.some(r => address.match(r));
  } catch { return false; }
}
