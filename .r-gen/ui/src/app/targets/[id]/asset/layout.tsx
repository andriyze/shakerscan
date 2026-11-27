import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import { segmentTitle } from '@/lib/pageTitle'

export const metadata: Metadata = segmentTitle('Asset')

export default function TargetsAssetLayout({ children }: { children: ReactNode }) {
  return children
}
