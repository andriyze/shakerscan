import type { Metadata } from 'next'
// Self-hosted faces: the CSP allows fonts from 'self' only.
import '@fontsource-variable/archivo/wdth.css'
import '@fontsource/ibm-plex-mono/400.css'
import '@fontsource/ibm-plex-mono/500.css'
import './globals.css'
import Sidebar from '@/components/Sidebar'
import WorkspaceBoundary from '@/components/WorkspaceBoundary'
import { ToastProvider } from '@/components/ui/Toast'

// Deployment mode is runtime configuration, not a public-image build-time setting.
export const dynamic = 'force-dynamic'

export const metadata: Metadata = {
  title: 'ShakerScan',
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
        <ToastProvider>
          <WorkspaceBoundary managed={process.env.SHAKERSCAN_MANAGED_UI === 'true'}>
            <div className="flex min-h-screen flex-col md:flex-row">
              <Sidebar />
              <main className="min-w-0 flex-1 overflow-auto px-4 py-5 md:px-8 md:py-7">
                <div className="mx-auto w-full max-w-[1600px]">{children}</div>
              </main>
            </div>
          </WorkspaceBoundary>
        </ToastProvider>
      </body>
    </html>
  )
}
