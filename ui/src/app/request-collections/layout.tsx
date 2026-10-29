import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import { segmentTitle } from '@/lib/pageTitle'

export const metadata: Metadata = segmentTitle('Request collections')

export default function RequestCollectionsLayout({ children }: { children: ReactNode }) {
  return children
}
