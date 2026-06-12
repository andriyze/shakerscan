import type { Metadata } from 'next'
import './globals.css'
import Sidebar from '@/components/Sidebar'
import { ToastProvider } from '@/components/ui/Toast'

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
      <body className="min-h-screen bg-gray-950 text-gray-100">
        <ToastProvider>
          <div className="flex min-h-screen flex-col md:flex-row">
            <Sidebar />
            <main className="min-w-0 flex-1 overflow-auto p-4 md:p-6">
              {children}
            </main>
          </div>
        </ToastProvider>
      </body>
    </html>
  )
}
