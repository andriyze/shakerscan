'use client'

import { Suspense, useEffect, useState } from 'react'
import { useParams, useSearchParams } from 'next/navigation'
import { EmptyState, PageHeader } from '@/components/ui'
import { HostedFrame } from '@/components/extensions/HostedFrame'
import { renamedTitle } from '@/lib/pageTitle'
import { HOSTED_PAGE_TITLE, hostedPageSrc, sameOriginPath } from '@/lib/uiExtensions.mjs'
import { workspaceExtensions } from '@/lib/workspaceCapabilities'

// The tab reads "<declared title> · ShakerScan" while the page is open, including after Next.js
// writes the route's own title again.
function useTabTitle(name: string | undefined) {
  useEffect(() => {
    if (!name) return
    const apply = () => {
      const next = renamedTitle(document.title, HOSTED_PAGE_TITLE, name)
      if (next !== document.title) document.title = next
    }
    apply()
    const observer = new MutationObserver(apply)
    observer.observe(document.head, { childList: true, subtree: true, characterData: true })
    return () => {
      observer.disconnect()
      document.title = renamedTitle(document.title, name, HOSTED_PAGE_TITLE)
    }
  }, [name])
}

// A page a managed deployment declares (ui-extensions/v1, docs/ui-extensions.md): this UI's
// shell and heading around the deployment's own same-origin page. The query string of this
// address is passed on, so a link can open the framed page at one item.
function HostedPage() {
  const { id } = useParams<{ id: string }>()
  const search = useSearchParams().toString()
  // Client-only, like every read of the managed policy: the server render has none.
  const [mounted, setMounted] = useState(false)
  useEffect(() => setMounted(true), [])
  const page = mounted ? workspaceExtensions().pages.find((candidate) => candidate.id === id) : undefined
  useTabTitle(page?.title)

  if (!mounted) return null
  const own = page ? sameOriginPath(page.src, window.location.origin) : null
  const src = own ? hostedPageSrc(own, search) : null
  if (!page || !src) {
    return <EmptyState message="This page is not part of this workspace." action={{ label: 'Back to the dashboard', href: '/' }} />
  }
  return (
    <div>
      <PageHeader title={page.title} />
      <HostedFrame key={src} src={src} title={page.title} variant="page" />
    </div>
  )
}

export default function HostedPageRoute() {
  return (
    <Suspense fallback={null}>
      <HostedPage />
    </Suspense>
  )
}
