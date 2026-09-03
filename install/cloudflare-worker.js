// install.shakerscan.com: serve the stable release's own bootstrap script.
//
// `main` used to be the live source of the installer entry point, so any merge touching
// install/bootstrap.sh was an unreviewed production deploy. The worker now reads only the
// one-line channel pointer from `main` and serves the bootstrap script from that release's
// immutable tag. Releases older than the bootstrap dispatcher fall back to `main`.
const CHANNEL_RAW_BASE = 'https://raw.githubusercontent.com/andriyze/shakerscan/main'
const RELEASE_RAW_ROOT = 'https://raw.githubusercontent.com/andriyze/shakerscan'
const VERSION_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$/
const FETCH_HEADERS = { 'User-Agent': 'shakerscan-install-worker' }

function failure(message) {
  return new Response(`${message}\n`, {
    status: 502,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  })
}

async function resolveStableVersion() {
  const response = await fetch(`${CHANNEL_RAW_BASE}/install/STABLE_VERSION`, { headers: FETCH_HEADERS })
  if (!response.ok) {
    return null
  }
  const version = (await response.text()).trim()
  return VERSION_PATTERN.test(version) ? version : null
}

export default {
  async fetch() {
    const version = await resolveStableVersion()
    if (!version) {
      return failure('Unable to resolve the stable ShakerScan release channel.')
    }
    let upstream = await fetch(`${RELEASE_RAW_ROOT}/v${version}/install/bootstrap.sh`, {
      headers: FETCH_HEADERS,
    })
    if (upstream.status === 404) {
      // The dispatcher script postdates some published releases; those keep the channel copy.
      upstream = await fetch(`${CHANNEL_RAW_BASE}/install/bootstrap.sh`, { headers: FETCH_HEADERS })
    }
    if (!upstream.ok) {
      return failure('Unable to load ShakerScan installer.')
    }
    return new Response(upstream.body, {
      status: 200,
      headers: {
        'Content-Type': 'text/x-shellscript; charset=utf-8',
        'Cache-Control': 'public, max-age=300',
        'X-Content-Type-Options': 'nosniff',
        'X-ShakerScan-Stable-Version': version,
      },
    })
  },
}
