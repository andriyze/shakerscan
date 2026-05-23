const INSTALL_SCRIPT_URL =
  'https://raw.githubusercontent.com/andriyze/shakerscan/main/install/index.sh'

export default {
  async fetch() {
    const upstream = await fetch(INSTALL_SCRIPT_URL, {
      headers: {
        'User-Agent': 'shakerscan-install-worker',
      },
    })

    if (!upstream.ok) {
      return new Response('Unable to load ShakerScan installer.\n', {
        status: 502,
        headers: {
          'Content-Type': 'text/plain; charset=utf-8',
          'Cache-Control': 'no-store',
          'X-Content-Type-Options': 'nosniff',
        },
      })
    }

    return new Response(upstream.body, {
      status: 200,
      headers: {
        'Content-Type': 'text/x-shellscript; charset=utf-8',
        'Cache-Control': 'public, max-age=300',
        'X-Content-Type-Options': 'nosniff',
      },
    })
  },
}
