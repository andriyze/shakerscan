import { test } from 'node:test'
import assert from 'node:assert/strict'

const { getApiUrl } = await import('../src/lib/apiConfig.ts')

function browserAt(pageUrl, configured) {
  const location = new URL(pageUrl)
  globalThis.window = {
    location: { hostname: location.hostname, protocol: location.protocol, origin: location.origin },
    __SHAKERSCAN_API_URL__: configured,
  }
  try {
    return getApiUrl()
  } finally {
    delete globalThis.window
  }
}

// The engine is bound to one private address; the UI is opened at another address that
// reaches the same host. The page kept fetching the configured address, which the browser
// cannot route to from outside the network, or refuses as a private-network request from a
// public page. Every read and write failed with no CORS header and a 403.
test('the API follows the address the page was opened at', () => {
  assert.equal(
    browserAt('http://18.215.239.210:3000/targets', 'http://172.31.33.227:8080'),
    'http://18.215.239.210:8080',
  )
})

test('the configured address is kept when the page is opened at it', () => {
  assert.equal(
    browserAt('http://172.31.33.227:3000/targets', 'http://172.31.33.227:8080'),
    'http://172.31.33.227:8080',
  )
})

test('the port and scheme of the configured API are preserved', () => {
  assert.equal(
    browserAt('https://10.0.0.5:3000/', 'https://172.31.33.227:9443'),
    'https://10.0.0.5:9443',
  )
})

test('a forwarded port on loopback is not an address literal and is left alone', () => {
  assert.equal(
    browserAt('http://localhost:3000/', 'http://172.31.33.227:8080'),
    'http://172.31.33.227:8080',
  )
})

// A name may legitimately be a gateway in front of a different API host, and following names
// is also the shape a rebound DNS name relies on. Names stay with the operator's allowlist.
test('a hostname page never redirects the API', () => {
  assert.equal(
    browserAt('http://shaker.box:3000/', 'http://172.31.33.227:8080'),
    'http://172.31.33.227:8080',
  )
})

test('a hostname API is never rewritten to the page address', () => {
  assert.equal(
    browserAt('http://18.215.239.210:3000/', 'https://api.example.test'),
    'https://api.example.test',
  )
})

test('an unparseable configured URL is left exactly as it is', () => {
  assert.equal(browserAt('http://18.215.239.210:3000/', 'not a url'), 'not a url')
})

test('with nothing configured the existing same-host fallback still applies', () => {
  globalThis.window = {
    location: { hostname: '18.215.239.210', protocol: 'http:', origin: 'http://18.215.239.210:3000' },
    __SHAKERSCAN_API_URL__: '',
  }
  try {
    assert.equal(getApiUrl(), 'http://18.215.239.210:8080')
  } finally {
    delete globalThis.window
  }
})
