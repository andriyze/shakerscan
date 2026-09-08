'use client'

import Link from 'next/link'
import type { ComponentProps } from 'react'
import { navigationAllowed } from '@/lib/workspaceCapabilities'

export default function WorkspaceLink(props: ComponentProps<typeof Link>) {
  const href = typeof props.href === 'string' ? props.href : props.href.pathname || ''
  if (href.startsWith('/') && !navigationAllowed(href)) return null
  return <Link {...props} />
}
