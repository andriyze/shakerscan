export const SCHEMA: 'shakerscan.ui-extensions/v1'
export const LIMITS: Readonly<{
  sections: number; pages: number; nav: number; slotPanels: number; accountLinks: number; text: number; path: number
  query: number
}>
export const SLOTS: Readonly<Record<SlotName, readonly string[]>>
export const DEFAULT_ICON: 'puzzle'
export const ICON_NAMES: readonly ExtensionIcon[]
export const FALLBACK_SECTION: string
export const HOSTED_PAGE_TITLE: string
export const NO_EXTENSIONS: UiExtensions

export type SlotName = 'finding.detail'
export type ExtensionIcon =
  | 'bell' | 'bug' | 'calendar' | 'calendar-clock' | 'chart' | 'clipboard-check' | 'clock'
  | 'file-text' | 'flag' | 'gauge' | 'globe' | 'inbox' | 'key' | 'layers' | 'link' | 'list-checks'
  | 'puzzle' | 'refresh' | 'shield-check' | 'tag' | 'ticket' | 'users' | 'wrench'

export type ExtensionSection = { id: string; label: string; after?: string }
/** A deployment page shown in a same-origin frame: a hosted page, or a panel in a slot. */
export type ExtensionFrame = { id: string; title: string; src: string }
export type ExtensionNavEntry = {
  label: string
  icon: ExtensionIcon
  /** `/ext/<page>` for a hosted page, or the declared same-origin path. */
  href: string
  page?: string
  section?: string
  after?: string
}
export type ExtensionAccount = {
  name: string
  detail: string | null
  links: { label: string; href: string }[]
  sign_out: string | null
}
export type UiExtensions = {
  sections: readonly ExtensionSection[]
  pages: readonly ExtensionFrame[]
  nav: readonly ExtensionNavEntry[]
  slots: Readonly<Partial<Record<SlotName, ExtensionFrame[]>>>
  account: ExtensionAccount | null
}

export function safeText(value: unknown): string | null
export function safePath(value: unknown, placeholders?: readonly string[]): string | null
export function sameOriginPath(path: unknown, origin: string): string | null
export function parseUiExtensions(block: unknown): UiExtensions
export function hostedPageSrc(src: string, search?: string): string
export function slotPanelSrc(src: string, values?: Record<string, string | undefined>): string | null

/** A declared sidebar entry as placed: `hosted` entries are routes of this UI (`/ext/<id>`). */
export type PlacedExtensionItem = {
  href: string; label: string; icon: ExtensionIcon; extension: true; hosted: boolean; anchor?: string
}
export function placeNavigation<Group extends { heading: string | null; items: { href: string }[] }>(
  groups: readonly Group[], extensions: UiExtensions | null | undefined,
): (Omit<Group, 'items'> & { items: (Group['items'][number] | PlacedExtensionItem)[]; extension?: boolean })[]
