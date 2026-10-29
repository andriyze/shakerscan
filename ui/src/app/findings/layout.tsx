import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import { segmentTitle } from '@/lib/pageTitle'

export const metadata: Metadata = segmentTitle('Findings')

export default function FindingsLayout({ children }: { children: ReactNode }) {
  return children
}
