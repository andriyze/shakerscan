import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import { segmentTitle } from '@/lib/pageTitle'

export const metadata: Metadata = segmentTitle('Coverage')

export default function AsmLayout({ children }: { children: ReactNode }) {
  return children
}
