import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import { segmentTitle } from '@/lib/pageTitle'

export const metadata: Metadata = segmentTitle('Command arsenal')

export default function SettingsArsenalLayout({ children }: { children: ReactNode }) {
  return children
}
