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
    ]
  },
}

module.exports = nextConfig
