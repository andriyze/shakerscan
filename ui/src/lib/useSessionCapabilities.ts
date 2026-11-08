'use client'

import { useSyncExternalStore } from 'react'
import { API_URL } from '@/lib/apiConfig'
import {
  ALL_ALLOWED, actionAllowed, fetchSessionCapabilities, pageAllowed, type SessionAction, type SessionCapabilities,
} from '@/lib/sessionCapabilities.mjs'
import { sessionCapabilities, subscribeSessionCapabilities } from '@/lib/workspaceCapabilities'

// React views of the session answer kept in workspaceCapabilities.ts: one request per page load,
// shared by every component; until it answers (and on any failure) everything is allowed.
const serverSnapshot = () => ALL_ALLOWED
const load = () => fetchSessionCapabilities(`${API_URL}/session/capabilities`)
const subscribe = (listener: () => void) => subscribeSessionCapabilities(listener, load)

export function useSessionCapabilities(): SessionCapabilities {
  return useSyncExternalStore(subscribe, sessionCapabilities, serverSnapshot)
}

export function useCan(action: SessionAction): boolean {
  return actionAllowed(useSessionCapabilities(), action)
}

export function usePageAllowed(): (href: string) => boolean {
  const capabilities = useSessionCapabilities()
  return (href: string) => pageAllowed(capabilities, href)
}
