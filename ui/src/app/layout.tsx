import type { Metadata } from 'next'
import './globals.css'
import EditionTitle from '@/components/EditionTitle'
import Sidebar from '@/components/Sidebar'
import WorkspaceBoundary from '@/components/WorkspaceBoundary'
import { ToastProvider } from '@/components/ui/Toast'
import { PRODUCT_NAME, TITLE_TEMPLATE } from '@/lib/pageTitle'

// Deployment mode is runtime configuration, not a public-image build-time setting.
export const dynamic = 'force-dynamic'

export const metadata: Metadata = {
  // Each route segment names its page through segmentTitle (its layout.tsx, or the page itself
  // when it is a server component), so a tab reads "Findings · ShakerScan"; the dashboard names
  // itself too. The default only shows where nothing names a page, such as a URL that matches no
  // route. EditionTitle adds the edition a managed deployment names.
  title: {
    template: TITLE_TEMPLATE,
    default: PRODUCT_NAME,
  },
  description: 'Open Source Dynamic Application Security Testing Scanner',
  icons: {
    // The .ico (16 and 32 px) for browsers without SVG icons; browsers that take SVG use the
    // last entry. Both, and the apple-touch icon, are rendered from favicon.svg by
    // scripts/render-icons.mjs.
    icon: [
      { url: '/favicon.ico', sizes: '16x16 32x32' },
      { url: '/favicon.svg', type: 'image/svg+xml' },
    ],
    apple: [{ url: '/apple-touch-icon.png', sizes: '180x180' }],
  },
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="dark">
      <head>
        <script src="/api/runtime-config" />
      </head>
      <body className="min-h-screen bg-gray-950 text-gray-100">
        <EditionTitle />
        <ToastProvider>
          <WorkspaceBoundary managed={process.env.SHAKERSCAN_MANAGED_UI === 'true'}>
            {/* First tab stop: keyboard and screen-reader users reach the page without passing the sidebar. */}
            <a
              href="#main-content"
              className="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-[100] focus:rounded-lg focus:bg-blue-600 focus:px-4 focus:py-2 focus:text-sm focus:font-medium focus:text-white focus:outline-hidden focus:ring-2 focus:ring-white"
            >
              Skip to content
            </a>
            <div className="flex min-h-screen flex-col md:flex-row">
              <Sidebar />
              <main id="main-content" tabIndex={-1} className="min-w-0 flex-1 overflow-auto p-4 focus:outline-hidden md:p-6">
                {children}
              </main>
            </div>
          </WorkspaceBoundary>
        </ToastProvider>
      </body>
    </html>
  )
}
