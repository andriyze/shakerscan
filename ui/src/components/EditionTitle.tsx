'use client'

import { useEffect } from 'react'
import { editionTitle, productEdition } from '@/lib/pageTitle'
import { workspaceEdition } from '@/lib/workspaceCapabilities'

// Route metadata titles every page "Page · ShakerScan" on the server, which never sees the
// managed workspace policy. When that policy names an Enterprise edition, keep the tab title
// "Page · ShakerScan Enterprise", including after Next.js swaps the title on navigation.
export default function EditionTitle() {
  useEffect(() => {
    const edition = productEdition(workspaceEdition())
    if (!edition) return
    const apply = () => {
      const next = editionTitle(document.title, edition)
      if (next !== document.title) document.title = next
    }
    apply()
    const observer = new MutationObserver(apply)
    observer.observe(document.head, { childList: true, subtree: true, characterData: true })
    return () => observer.disconnect()
  }, [])
  return null
}
