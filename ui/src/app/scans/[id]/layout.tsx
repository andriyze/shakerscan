import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import { segmentTitle } from '@/lib/pageTitle'

export const metadata: Metadata = segmentTitle('Scan')

export default function ScansDetailLayout({ children }: { children: ReactNode }) {
  return children
}
