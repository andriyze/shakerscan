/** @type {import('next').NextConfig} */
const contentSecurityPolicy = [
  "default-src 'self'",
  "base-uri 'self'",
  "frame-ancestors 'none'",
  "object-src 'none'",
  "form-action 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob: http: https:",
  "font-src 'self' data:",
  "connect-src 'self' http: https: ws: wss:",
  "worker-src 'self' blob:",
].join('; ')

const securityHeaders = [
  { key: 'Content-Security-Policy', value: contentSecurityPolicy },
  { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
  { key: 'Cross-Origin-Resource-Policy', value: 'same-origin' },
  { key: 'Origin-Agent-Cluster', value: '?1' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), payment=(), usb=()' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'DENY' },
]

const nextConfig = {
  output: 'standalone',
  reactStrictMode: true,
  poweredByHeader: false,
  turbopack: {
    root: __dirname,
  },
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }]
  },
  async redirects() {
    // AI Gate and Model Intake moved out of /settings/* to top-level routes.
    // Keep old links working; query strings are preserved.
    return [
      { source: '/settings/ai-gate', destination: '/ai-gate', permanent: false },
      { source: '/settings/model-intake', destination: '/model-intake', permanent: false },
      // The AI Investigator (Deep Hunt) moved from /settings/research-agent to
      // the top-level /deep-hunt. Keep old links + backend-emitted deep-links
      // (incl. ?episode_id / ?run query strings) working.
      { source: '/settings/research-agent', destination: '/deep-hunt', permanent: false },
      { source: '/settings/research-agent/:path*', destination: '/deep-hunt/:path*', permanent: false },
    ]
  },
}

module.exports = nextConfig
