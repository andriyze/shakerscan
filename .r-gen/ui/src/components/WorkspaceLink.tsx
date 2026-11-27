'use client'

import Link from 'next/link'
import type { ComponentProps } from 'react'
import { navigationAllowed } from '@/lib/workspaceCapabilities'
import { usePageAllowed } from '@/lib/useSessionCapabilities'

export default function WorkspaceLink(props: ComponentProps<typeof Link>) {
  const pageAllowed = usePageAllowed()
  const href = typeof props.href === 'string' ? props.href : props.href.pathname || ''
  if (href.startsWith('/') && !navigationAllowed(href)) return null
  // A page this person cannot open (session capabilities) keeps its words, without the link.
  if (href.startsWith('/') && !pageAllowed(href)) {
    return <span className={props.className} data-capability-denied-link={href}>{props.children as React.ReactNode}</span>
  }
  return <Link {...props} />
}
