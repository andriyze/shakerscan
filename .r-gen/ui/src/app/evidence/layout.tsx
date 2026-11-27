import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import { segmentTitle } from '@/lib/pageTitle'

export const metadata: Metadata = segmentTitle('Evidence')

export default function EvidenceLayout({ children }: { children: ReactNode }) {
  return children
}
