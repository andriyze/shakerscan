import type { RequestCollectionBinding, RequestCollectionInventoryItem } from './requestCollectionApi'

export interface CollectionApi { id: string; url: string; label: string; kind: 'host' | 'origin' }

export function filterRequests(items: RequestCollectionInventoryItem[], filter?: { query?: string; method?: string }): RequestCollectionInventoryItem[]
export function methodCounts(items: RequestCollectionInventoryItem[]): Array<{ method: string; count: number }>
export function originOf(url: string): string
export function boundApis<T extends CollectionApi>(bindings: RequestCollectionBinding[], apis: T[]): Array<T & { binding: RequestCollectionBinding | null; bound: boolean }>
