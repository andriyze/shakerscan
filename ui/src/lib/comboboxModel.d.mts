export interface ComboboxOptionLike {
  value: string
  label: string
  description?: string
  meta?: string
  keywords?: string
  group?: string
  disabled?: boolean
}

export function normalize(value: unknown): string
export function matches(option: ComboboxOptionLike, query: string): boolean
export function filterOptions<T extends ComboboxOptionLike>(options: T[], query: string): T[]
export function moveActive(options: ComboboxOptionLike[], current: number, step: 1 | -1): number
export function groupOptions<T extends ComboboxOptionLike>(options: T[]): Array<{ name: string; options: T[] }>
