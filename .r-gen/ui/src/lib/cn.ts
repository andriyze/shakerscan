// Tiny class-name joiner: drops falsy entries so conditional classes read
// cleanly (`cn('base', active && 'ring-2', error && 'border-red-500')`).
export function cn(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
