import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import { segmentTitle } from '@/lib/pageTitle'

export const metadata: Metadata = segmentTitle('Policy profiles')

export default function SettingsPolicyProfilesLayout({ children }: { children: ReactNode }) {
  return children
}
