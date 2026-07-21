/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  reactStrictMode: true,
  turbopack: {
    root: __dirname,
  },
  async redirects() {
    // AI Gate, Model Intake, and the Exceptions queue moved out of /settings/*
    // to top-level routes. Keep old links working — including backend-emitted
    // deep-links; query strings (e.g. ?remediate=controls) are preserved.
    return [
      { source: '/settings/ai-gate', destination: '/ai-gate', permanent: false },
      { source: '/settings/model-intake', destination: '/model-intake', permanent: false },
      { source: '/settings/exceptions', destination: '/exceptions', permanent: false },
      // The AI Investigator (Deep Hunt) moved from /settings/research-agent to
      // the top-level /deep-hunt. Keep old links + backend-emitted deep-links
      // (incl. ?episode_id / ?run query strings) working.
      { source: '/settings/research-agent', destination: '/deep-hunt', permanent: false },
      { source: '/settings/research-agent/:path*', destination: '/deep-hunt/:path*', permanent: false },
    ]
  },
}

module.exports = nextConfig
