import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeTarget } from '../src/target.ts';
import { parseRequest } from '../src/request.ts';

for (const [input, expected] of [['Example.COM.', 'example.com'], [' bücher.de ', 'xn--bcher-kva.de'], ['faß.de', 'xn--fa-hia.de'], ['пример.рф', 'xn--e1afmkfd.xn--p1ai'], ['EXAMPLE。COM', 'example.com']]) {
  test(`normalization: ${input}`, () => assert.equal(normalizeTarget(input), expected));
}
for (const input of ['localhost', 'foo.local', 'foo.home.arpa', 'metadata.google.internal', '*.example.com', 'a..com', 'example.com..', 'a.test',
  '127.0.0.1', '127.1', '2130706433', '0x7f000001', '0177.0.0.1', '0x7f.0.0.1', '[::1]', '::ffff:127.0.0.1',
  'https://example.com', 'example.com:443', 'user@example.com', 'example.com/path', 'example.com?q', 'example.com#f',
  'example.com\\private', 'example%2ecom', 'ex ample.com', 'a\u0000.com', '-foo.com', 'foo-.com', 'xn--.com', 'a'.repeat(64) + '.com', '', '1.2.3.999']) {
  test(`reject target ${JSON.stringify(input)}`, () => assert.throws(() => normalizeTarget(input)));
}
test('JSON escapes accepted; only the single string target field is allowed', () => {
  assert.equal(parseRequest(' { "tar\\u0067et" : "example.com" } \n'), 'example.com');
  for (const bad of ['null', '[]', '{}', '{"target":false}', '{"target":{}}', '{"target":"a.com","target":"b.com"}', '{"target":"a.com","x":1}', '{"target":"a.com"}x', '{"Target":"a.com"}', '{"target":"a\n.com"}', '{"target":"a.com",}']) assert.throws(() => parseRequest(bad));
});
