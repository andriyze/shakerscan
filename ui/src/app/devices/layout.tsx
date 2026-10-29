import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import { segmentTitle } from '@/lib/pageTitle'

export const metadata: Metadata = segmentTitle('Connected devices')

export default function DevicesLayout({ children }: { children: ReactNode }) {
  return children
}
