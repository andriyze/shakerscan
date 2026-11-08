'use client'

import { useSyncExternalStore } from 'react'
import { API_URL } from '@/lib/apiConfig'
import {
  ALL_ALLOWED, actionAllowed, fetchSessionCapabilities, pageAllowed,
  type SessionAction, type SessionCapabilities,
} from '@/lib/sessionCapabilities.mjs'

// One request per page load, shared by every component; until it answers (and on any failure)
// everything is allowed, as before the contract. Presentation only.
let current: SessionCapabilities = ALL_ALLOWED
let requested = false
const listeners = new Set<() => void>()

function subscribe(listener: () => void): () => void {
  listeners.add(listener)
  if (!requested && typeof window !== 'undefined') {
    requested = true
    void fetchSessionCapabilities(`${API_URL}/session/capabilities`).then(answer => {
      current = answer
      listeners.forEach(notify => notify())
    })
  }
  return () => { listeners.delete(listener) }
}

const snapshot = () => current
const serverSnapshot = () => ALL_ALLOWED

export function useSessionCapabilities(): SessionCapabilities {
  return useSyncExternalStore(subscribe, snapshot, serverSnapshot)
}

export function useCan(action: SessionAction): boolean {
  return actionAllowed(useSessionCapabilities(), action)
}

export function usePageAllowed(): (href: string) => boolean {
  const capabilities = useSessionCapabilities()
  return (href: string) => pageAllowed(capabilities, href)
}
