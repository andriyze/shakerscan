// Searchable-picker options for targets and credentials, labelled the same way on every page.
import type { ComboboxOption } from '@/components/ui'
import type { CredentialProfile } from './credentialApi'
import type { TargetAsset } from './targetAssetApi'

function locatorOf(url: string): string {
  return String(url || '').replace(/^host:\/\//, '')
}

export function targetKindLabel(asset: Pick<TargetAsset, 'connected_device' | 'url' | 'device_class'>): string {
  if (asset.connected_device) return asset.device_class && asset.device_class !== 'generic' ? `device · ${asset.device_class}` : 'device'
  return asset.url.startsWith('host://') ? 'host' : 'web app'
}

export function targetOptions(assets: TargetAsset[]): ComboboxOption[] {
  return assets.map(asset => ({
    value: asset.id,
    label: asset.name || asset.locator || locatorOf(asset.url),
    description: [targetKindLabel(asset), asset.environment].filter(Boolean).join(' · '),
    meta: asset.locator || locatorOf(asset.url),
    keywords: `${asset.url} ${asset.root_domain || ''}`,
    group: asset.connected_device ? 'Connected devices' : asset.url.startsWith('host://') ? 'Hosts & domains' : 'Web apps & APIs',
  }))
}

export function credentialDescription(profile: CredentialProfile): string {
  const parts = [profile.auth_kind.replaceAll('_', ' '), `v${profile.current_version}`]
  if (profile.principal_label) parts.push(profile.principal_label)
  if (profile.status === 'expired') parts.push('expired')
  else if (profile.expires_at) parts.push(`expires ${new Date(profile.expires_at).toLocaleDateString()}`)
  return parts.join(' · ')
}

export function credentialOptions(profiles: CredentialProfile[]): ComboboxOption[] {
  return profiles.map(profile => ({
    value: profile.id,
    label: profile.name,
    description: credentialDescription(profile),
    meta: profile.shared ? `from ${profile.home_target_name || 'another target'}` : profile.principal_slot,
    keywords: `${profile.principal_slot} ${profile.auth_kind} ${profile.home_target_locator || ''}`,
    group: profile.shared ? 'Shared with this target' : 'This target',
    disabled: profile.status === 'expired' || !profile.is_active,
  }))
}
