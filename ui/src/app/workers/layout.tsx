import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import { segmentTitle } from '@/lib/pageTitle'

export const metadata: Metadata = segmentTitle('Worker pools')

export default function WorkersLayout({ children }: { children: ReactNode }) {
  return children
}
