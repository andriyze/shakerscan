// Property-based fuzzing of the system resolver's DNS-over-TCP framing against a local resolver
// that always truncates over UDP and then writes its TCP reply in fuzzed segments.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import net from 'node:net';
import fc from 'fast-check';
import { RESOLVER } from '../src/dns.ts';
import { systemResolverFetcher } from '../src/resolver.ts';
import { encodeQuery } from '../src/wire.ts';
import { runs } from './helpers.ts';

// The bytes the resolver sends over TCP for the next exchange, and where to split them.
let plan = { frame: Buffer.alloc(0), cuts: [] as number[] };

/** TCP and UDP listeners on one loopback port: UDP replies only with the TC bit set, and TCP
 * writes the planned bytes in separate segments and then closes. */
async function resolver(): Promise<{ port: number; close: () => void }> {
  for (let attempt = 0; ; attempt++) {
    const tcp = net.createServer({ noDelay: true, allowHalfOpen: true }, async socket => {
      socket.on('error', () => {});
      const { frame, cuts } = plan;
      let from = 0;
      for (const cut of [...new Set(cuts.map(c => c % (frame.length + 1)))].sort((a, b) => a - b).concat(frame.length)) {
        if (cut > from) socket.write(frame.subarray(from, cut));
        from = cut;
        await new Promise(resolve => setImmediate(resolve));
      }
      socket.end();
    });
    await new Promise<void>(resolve => tcp.listen(0, '127.0.0.1', resolve));
    const port = (tcp.address() as net.AddressInfo).port;
    const udp = dgram.createSocket('udp4');
    udp.on('message', (message, remote) => {
      const reply = Buffer.from(message.subarray(0, 12)); reply[2] = reply[2]! | 0x82; // QR and TC
      udp.send(reply, remote.port, remote.address);
    });
    try {
      await new Promise<void>((resolve, reject) => { udp.once('error', reject); udp.bind(port, '127.0.0.1', resolve); });
      return { port, close: () => { tcp.close(); udp.close(); } };
    } catch (error) { tcp.close(); udp.close(); if (attempt >= 5) throw error; }
  }
}

const payload = fc.oneof(
  fc.uint8Array({ maxLength: 600 }),
  // Near the 65535-byte frame limit, built from a short pattern to keep generation cheap.
  fc.tuple(fc.uint8Array({ minLength: 1, maxLength: 16 }), fc.oneof(fc.constantFrom(65535, 65534), fc.integer({ min: 65400, max: 65535 })))
    .map(([pattern, length]) => Uint8Array.from({ length }, (_, i) => pattern[i % pattern.length]!)));
const framed = (bytes: Uint8Array) => Buffer.concat([Buffer.from([bytes.length >> 8, bytes.length & 255]), bytes]);

test('fuzz: DNS-over-TCP replies are reassembled from any segmentation and trailing data', async () => {
  const server = await resolver();
  try {
    const fetcher = systemResolverFetcher('127.0.0.1', fetch, server.port);
    const body = encodeQuery('example.com', 'A', 4242);
    await fc.assert(fc.asyncProperty(payload, fc.array(fc.nat(), { maxLength: 6 }), fc.uint8Array({ maxLength: 16 }), async (bytes, cuts, trailing) => {
      plan = { frame: Buffer.concat([framed(bytes), trailing]), cuts };
      const response = await fetcher(RESOLVER, { method: 'POST', body, signal: AbortSignal.timeout(2000) });
      assert.deepEqual(new Uint8Array(await response.arrayBuffer()), bytes);
    }), { numRuns: runs(200),
      // Regression: a 65535-byte reply whose last byte arrived with a following byte was refused.
      examples: [[new Uint8Array(65535), [], new Uint8Array([0])]] });
  } finally { server.close(); }
});

test('fuzz: a TCP reply cut short by the peer is refused at once, not at the deadline', async () => {
  const server = await resolver();
  try {
    const fetcher = systemResolverFetcher('127.0.0.1', fetch, server.port);
    const body = encodeQuery('example.com', 'A', 4242);
    await fc.assert(fc.asyncProperty(payload, fc.array(fc.nat(), { maxLength: 6 }), fc.nat(), async (bytes, cuts, at) => {
      const frame = framed(bytes);
      plan = { frame: frame.subarray(0, at % frame.length), cuts };
      const signal = AbortSignal.timeout(1500);
      await assert.rejects(fetcher(RESOLVER, { method: 'POST', body, signal }));
      assert.equal(signal.aborted, false);
    }), { numRuns: runs(100) });
  } finally { server.close(); }
});
