import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import { segmentTitle } from '@/lib/pageTitle'

export const metadata: Metadata = segmentTitle('Scans')

export default function ScansLayout({ children }: { children: ReactNode }) {
  return children
}
