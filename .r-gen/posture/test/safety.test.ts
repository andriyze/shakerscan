import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isPublicAddress } from '../src/safety.ts';
for (const ip of ['0.0.0.0', '10.2.3.4', '100.64.0.1', '127.0.0.1', '169.254.169.254', '172.16.0.1', '192.0.0.9', '192.0.2.1', '192.168.1.1', '198.18.0.1', '198.51.100.1', '203.0.113.1', '224.1.1.1', '255.255.255.255',
  '::', '::1', '::ffff:8.8.8.8', '64:ff9b::808:808', 'fc00::1', 'fe80::1', 'ff02::1', '2001:db8::1', '2001::1', '2002:0808:0808::1', '3fff::1', '100::1', '5f00::1', 'garbage']) {
  test(`nonpublic ${ip}`, () => assert.equal(isPublicAddress(ip), false));
}
for (const ip of ['1.1.1.1', '8.8.8.8', '93.184.216.34', '2606:4700:4700::1111', '2001:4860:4860::8888']) {
  test(`public ${ip}`, () => assert.equal(isPublicAddress(ip), true));
}
