import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import { segmentTitle } from '@/lib/pageTitle'

// The page's real name is declared by the deployment and known only in the browser; the page
// puts it in the tab once it has it. Until then the tab carries HOSTED_PAGE_TITLE
// (lib/uiExtensions.mjs), spelled out here because route metadata is read statically.
export const metadata: Metadata = segmentTitle('Page')

export default function HostedPageLayout({ children }: { children: ReactNode }) {
  return children
}
