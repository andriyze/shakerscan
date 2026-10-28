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
    icon: '/favicon.svg',
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
            <div className="flex min-h-screen flex-col md:flex-row">
              <Sidebar />
              <main className="min-w-0 flex-1 overflow-auto p-4 md:p-6">
                {children}
              </main>
            </div>
          </WorkspaceBoundary>
        </ToastProvider>
      </body>
    </html>
  )
}
