import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import { segmentTitle } from '@/lib/pageTitle'

export const metadata: Metadata = segmentTitle('New scan')

export default function ScanNewLayout({ children }: { children: ReactNode }) {
  return children
}
