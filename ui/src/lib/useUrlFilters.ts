'use client'

import { useSearchParams, usePathname } from 'next/navigation'
import { useCallback, useMemo, useEffect } from 'react'

export type FilterValue = string | number | undefined

export interface FilterState {
  [key: string]: FilterValue
}

export interface UseUrlFiltersOptions<T extends FilterState> {
  defaults?: Partial<T>
}

// Filter changes are shallow client-side updates: native history.pushState /
// replaceState (which useSearchParams syncs with) instead of router.push.
// router.push re-renders through the App Router cache, and on a statically
// prerendered page that was hard-loaded WITH query params it reconciles the
// push against the prerendered entry and silently reverts it — breaking every
// filter interaction after opening a deep link.
function shallowNavigate(url: string, mode: 'push' | 'replace') {
  if (mode === 'push') window.history.pushState(null, '', url)
  else window.history.replaceState(null, '', url)
}

export function useUrlFilters<T extends FilterState = FilterState>(options: UseUrlFiltersOptions<T> = {}) {
  const searchParams = useSearchParams()
  const pathname = usePathname()
  const { defaults = {} as Partial<T> } = options
  // Memoize defaults to prevent infinite re-renders
  // Empty deps is intentional - we capture initial defaults only
  const defaultsRecord = useMemo(() => defaults as FilterState, [])

  // Parse filters from URL with defaults
  const filters = useMemo(() => {
    const result: FilterState = { ...defaultsRecord }
    searchParams.forEach((value, key) => {
      if (key === 'page') {
        // Page is 1-based; treat 0 and invalid values as page 1 for backwards compatibility
        const parsed = parseInt(value, 10)
        result[key] = parsed >= 1 ? parsed : 1
      } else {
        result[key] = value
      }
    })
    return result as T
  }, [searchParams, defaultsRecord])

  // Normalize invalid page values in URL (e.g., ?page=0 -> remove page param)
  useEffect(() => {
    const urlPage = searchParams.get('page')
    if (urlPage !== null) {
      const parsed = parseInt(urlPage, 10)
      // If page is invalid (0, negative, NaN) or equals the default, remove it from URL
      if (isNaN(parsed) || parsed < 1 || parsed === defaultsRecord['page']) {
        const params = new URLSearchParams(searchParams.toString())
        params.delete('page')
        const queryString = params.toString()
        shallowNavigate(queryString ? `${pathname}?${queryString}` : pathname, 'replace')
      }
    }
  }, [searchParams, pathname, defaultsRecord])

  // Update a single filter
  const setFilter = useCallback((key: string, value: string | number | undefined) => {
    const params = new URLSearchParams(searchParams.toString())

    if (value === undefined || value === '' || value === defaultsRecord[key]) {
      params.delete(key)
    } else {
      params.set(key, String(value))
    }

    // Reset page when changing other filters
    if (key !== 'page') {
      params.delete('page')
    }

    const queryString = params.toString()
    shallowNavigate(queryString ? `${pathname}?${queryString}` : pathname, 'push')
  }, [searchParams, pathname, defaultsRecord])

  // Update multiple filters at once
  const setFilters = useCallback((updates: FilterState) => {
    const params = new URLSearchParams(searchParams.toString())

    Object.entries(updates).forEach(([key, value]) => {
      if (value === undefined || value === '' || value === defaultsRecord[key]) {
        params.delete(key)
      } else {
        params.set(key, String(value))
      }
    })

    // Reset page when filters change (unless page is being updated)
    if (!('page' in updates)) {
      params.delete('page')
    }

    const queryString = params.toString()
    shallowNavigate(queryString ? `${pathname}?${queryString}` : pathname, 'push')
  }, [searchParams, pathname, defaultsRecord])

  // Build a URL with given filters, preserving current context
  const buildUrl = useCallback((path: string, overrides: FilterState = {}) => {
    const params = new URLSearchParams()

    // Include current filters as "return" params if we're linking to a detail page
    const isDetailPage = path.includes('[id]') || /\/[a-f0-9-]{36}$/.test(path)
    if (isDetailPage) {
      searchParams.forEach((value, key) => {
        params.set(`return_${key}`, value)
      })
    }

    // Add overrides
    Object.entries(overrides).forEach(([key, value]) => {
      if (value !== undefined && value !== '') {
        params.set(key, String(value))
      }
    })

    const queryString = params.toString()
    return queryString ? `${path}?${queryString}` : path
  }, [searchParams])

  // Build return URL from detail page back to list
  const buildReturnUrl = useCallback((basePath: string) => {
    const params = new URLSearchParams()

    // Extract return params and restore them
    searchParams.forEach((value, key) => {
      if (key.startsWith('return_')) {
        params.set(key.replace('return_', ''), value)
      }
    })

    const queryString = params.toString()
    return queryString ? `${basePath}?${queryString}` : basePath
  }, [searchParams])

  // Get all return params as an object
  const returnParams = useMemo(() => {
    const result: FilterState = {}
    searchParams.forEach((value, key) => {
      if (key.startsWith('return_')) {
        result[key.replace('return_', '')] = value
      }
    })
    return result
  }, [searchParams])

  return {
    filters,
    setFilter,
    setFilters,
    buildUrl,
    buildReturnUrl,
    returnParams,
    searchParams
  }
}
