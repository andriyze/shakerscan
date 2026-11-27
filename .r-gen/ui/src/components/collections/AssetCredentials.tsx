'use client'

import { useState } from 'react'
import { KeyRound, Search, X } from 'lucide-react'
import Link from '@/components/WorkspaceLink'
import { Card } from '@/components/ui'
import type { CredentialProfile } from '@/lib/credentialApi'
import { credentialDescription } from '@/lib/pickerOptions'

/** The credentials a target can use: its own and those shared with it, searchable. */
export function AssetCredentials({ assetId, credentials }: { assetId: string; credentials: CredentialProfile[] }) {
  const [query, setQuery] = useState('')
  const words = query.toLowerCase().split(/\s+/).filter(Boolean)
  const visible = credentials.filter(profile => {
    const text = [profile.name, profile.principal_slot, profile.auth_kind, profile.principal_label, profile.home_target_name].filter(Boolean).join(' ').toLowerCase()
    return words.every(word => text.includes(word))
  })
  return <Card className="p-0">
    <div className="flex flex-wrap items-center gap-3 border-b border-gray-800 p-4">
      <h3 className="flex items-center gap-2 font-medium text-white"><KeyRound className="h-4 w-4 text-blue-300" aria-hidden="true" />Credentials
        <span className="rounded-full bg-gray-800 px-2 py-0.5 text-xs text-gray-400">{credentials.length}</span></h3>
      {credentials.length > 5 && <div className="relative ml-auto min-w-48 flex-1 sm:max-w-xs">
        <Search className="pointer-events-none absolute left-3 top-2 h-4 w-4 text-gray-500" aria-hidden="true" />
        <input aria-label="Search credentials" value={query} onChange={event => setQuery(event.target.value)} placeholder="Search credentials…"
          className="h-8 w-full rounded-lg border border-gray-700 bg-gray-800 pl-9 pr-7 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-hidden" />
        {query && <button type="button" aria-label="Clear credential search" onClick={() => setQuery('')} className="absolute right-2 top-2 text-gray-500 hover:text-gray-200"><X className="h-4 w-4" /></button>}
      </div>}
      <Link href={`/credentials?${new URLSearchParams({ target_kind: 'network', target_id: assetId })}`} className={`text-sm text-blue-300 hover:text-blue-200 ${credentials.length > 5 ? '' : 'ml-auto'}`}>Manage</Link>
    </div>
    {!credentials.length ? <p className="p-4 text-sm text-gray-500">No credential profiles. Store a profile once, then select it for applicable services.</p>
      : !visible.length ? <p className="p-4 text-sm text-gray-500">No credentials match.</p>
      : <ul className="divide-y divide-gray-800/70" aria-label="Credentials">
        {visible.map(profile => <li key={profile.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5">
          <span className="min-w-0 flex-1">
            <span className="block truncate text-sm text-gray-100">{profile.name}</span>
            <span className="block truncate text-xs text-gray-500">{credentialDescription(profile)}</span>
            <code className="block select-all truncate font-mono text-[11px] text-gray-600" title="Opaque reference used by Scan and Hunt requests">{profile.id}</code>
          </span>
          <span className="rounded-md bg-blue-500/10 px-2 py-0.5 text-xs text-blue-300">{profile.principal_slot}</span>
          {profile.shared && <span className="rounded-md bg-violet-500/10 px-2 py-0.5 text-xs text-violet-300">shared from {profile.home_target_name || 'another target'}</span>}
          {!profile.is_active && <span className="rounded-md bg-gray-800 px-2 py-0.5 text-xs text-gray-400">inactive</span>}
        </li>)}
      </ul>}
  </Card>
}
