import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import { segmentTitle } from '@/lib/pageTitle'

export const metadata: Metadata = segmentTitle('Finding')

export default function FindingsDetailLayout({ children }: { children: ReactNode }) {
  return children
}
