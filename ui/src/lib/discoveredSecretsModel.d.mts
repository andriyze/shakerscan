export function shellQuote(value: unknown): string
export function secretsCommand(
  action: 'reveal' | 'grant' | 'promote',
  targetId: string,
  ref: string,
  choices?: { to?: string; name?: string; authKind?: string; headerName?: string },
): string
export interface SecretGroup<T> { key: string; kind: string; label: string; foundOn: string; rows: T[] }
export function groupSecrets<T extends { kind: string; label: string; found_on: string }>(rows: readonly T[]): SecretGroup<T>[]
export const SECRETS_PAGE_SIZE: number
