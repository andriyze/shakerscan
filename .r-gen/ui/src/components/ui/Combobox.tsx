'use client'

import { useCallback, useEffect, useId, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { Check, ChevronDown, Search, X } from 'lucide-react'
import { cn } from '@/lib/cn'
import { canChooseActive, clampActive, filterOptions, groupOptions, initialActive, moveActive } from '@/lib/comboboxModel.mjs'
import { fieldClasses } from './Input'

export interface ComboboxOption {
  value: string
  label: string
  /** Second line: kind, slot, version — whatever tells similar options apart. */
  description?: string
  /** Right-aligned detail such as a host or locator. */
  meta?: string
  /** Extra searchable words that are not displayed. */
  keywords?: string
  group?: string
  disabled?: boolean
  badge?: ReactNode
}

/**
 * A searchable select. The trigger is a button that takes the Field's id, so its label stays
 * associated; the chosen value is exposed as data-value. The list is positioned against the
 * viewport so modals and cards never clip it.
 */
export function Combobox({
  id, value, onChange, options, placeholder = 'Choose…', searchPlaceholder = 'Search…',
  noneLabel, emptyMessage = 'No matches', disabled, className, 'aria-describedby': describedBy,
  'aria-invalid': invalid, 'aria-label': ariaLabel, onQueryChange, loading = false, footerNote, optionsQuery,
}: {
  id?: string
  value: string
  onChange: (value: string) => void
  options: ComboboxOption[]
  placeholder?: string
  searchPlaceholder?: string
  /** Adds an explicit empty choice at the top, e.g. "All targets" or "No primary identity". */
  noneLabel?: string
  emptyMessage?: string
  disabled?: boolean
  className?: string
  'aria-describedby'?: string
  'aria-invalid'?: boolean
  'aria-label'?: string
  /**
   * Server-side search: the typed text goes to the caller, which supplies the matching `options`
   * (bounded) instead of the list being filtered in the browser.
   */
  onQueryChange?: (query: string) => void
  /** A server search is in flight. */
  loading?: boolean
  /** Shown under the list, e.g. "Showing the first 25 matches; type to narrow". */
  footerNote?: string | null
  /**
   * Server search: the query the current `options` answer (useTargetSearch's answeredQuery).
   * Enter chooses only when it equals the text in the box, so a stale result is never picked.
   */
  optionsQuery?: string | null
}) {
  const generated = useId()
  const listId = `${id || generated}-list`
  const trigger = useRef<HTMLButtonElement>(null)
  const panel = useRef<HTMLDivElement>(null)
  const search = useRef<HTMLInputElement>(null)
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(-1)
  const [position, setPosition] = useState<{ top: number; left: number; width: number; maxHeight: number }>({ top: 0, left: 0, width: 320, maxHeight: 320 })

  const all = useMemo<ComboboxOption[]>(() => noneLabel !== undefined ? [{ value: '', label: noneLabel }, ...options] : options, [noneLabel, options])
  const remote = Boolean(onQueryChange)
  const visible = useMemo(() => remote ? all : filterOptions(all, query), [all, query, remote])
  const onQueryChangeRef = useRef(onQueryChange)
  onQueryChangeRef.current = onQueryChange
  useEffect(() => { onQueryChangeRef.current?.(query) }, [query])
  const selected = all.find(option => option.value === value)

  const close = useCallback((focusTrigger = false) => {
    setOpen(false)
    setQuery('')
    if (focusTrigger) trigger.current?.focus()
  }, [])

  const place = useCallback(() => {
    const rect = trigger.current?.getBoundingClientRect()
    if (!rect || rect.bottom < 0 || rect.top > window.innerHeight) return false
    const margin = 8
    const width = Math.min(Math.max(rect.width, 288), window.innerWidth - 2 * margin)
    const left = Math.max(margin, Math.min(rect.left, window.innerWidth - width - margin))
    const below = window.innerHeight - rect.bottom - margin - 4
    const above = rect.top - margin - 4
    const height = Math.min(panel.current?.scrollHeight || 360, 400)
    const downward = height <= below || below >= above
    const maxHeight = Math.max(160, Math.min(400, downward ? below : above))
    setPosition({ top: downward ? rect.bottom + 4 : Math.max(margin, rect.top - 4 - Math.min(height, maxHeight)), left, width, maxHeight })
    return true
  }, [])

  function openList(seed = '') {
    if (disabled) return
    setQuery(seed)
    setOpen(true)
  }

  useLayoutEffect(() => { if (open) place() }, [open, place, visible.length])
  // The list's identity: a new result list (another query's answer, a page that arrived) resets
  // the highlight, so it never points at a different option or past the end.
  const visibleKey = visible.map(option => `${option.value}\u0000${option.disabled ? 1 : 0}`).join('\u0001')
  useEffect(() => {
    if (!open) return
    setActive(initialActive(visible, value))
    // Recompute only when the list opens or what it shows changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, visibleKey])
  useEffect(() => {
    if (open) requestAnimationFrame(() => search.current?.focus())
  }, [open])
  const activeIndex = clampActive(visible, active)
  const chooseReady = canChooseActive({ remote, loading, query, optionsQuery })
  useEffect(() => {
    if (!open) return
    const onPointer = (event: PointerEvent) => {
      const target = event.target as Node
      if (!panel.current?.contains(target) && !trigger.current?.contains(target)) close()
    }
    const onScroll = (event: Event) => {
      if (panel.current?.contains(event.target as Node)) return
      if (!place()) close()
    }
    document.addEventListener('pointerdown', onPointer)
    window.addEventListener('scroll', onScroll, true)
    window.addEventListener('resize', onScroll)
    return () => {
      document.removeEventListener('pointerdown', onPointer)
      window.removeEventListener('scroll', onScroll, true)
      window.removeEventListener('resize', onScroll)
    }
  }, [open, close, place])
  useEffect(() => {
    if (!open || activeIndex < 0) return
    panel.current?.querySelector(`[data-index="${activeIndex}"]`)?.scrollIntoView({ block: 'nearest' })
  }, [open, activeIndex])

  function choose(option: ComboboxOption | undefined) {
    if (!option || option.disabled) return
    onChange(option.value)
    close(true)
  }

  function onKeyDown(event: React.KeyboardEvent) {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault()
      setActive(current => moveActive(visible, clampActive(visible, current), event.key === 'ArrowDown' ? 1 : -1))
    } else if (event.key === 'Enter') {
      event.preventDefault()
      // Server search: only a list that answers the text in the box, and only a valid index.
      if (chooseReady && activeIndex >= 0) choose(visible[activeIndex])
    } else if (event.key === 'Escape') {
      event.preventDefault()
      close(true)
    } else if (event.key === 'Tab') {
      close()
    }
  }

  let index = -1
  return <div className={cn('relative w-full', className)}>
    <button ref={trigger} id={id} type="button" disabled={disabled} data-value={value}
      aria-haspopup="listbox" aria-expanded={open} aria-controls={open ? listId : undefined}
      aria-describedby={describedBy} aria-invalid={invalid || undefined} aria-label={ariaLabel}
      onClick={() => open ? close() : openList()}
      onKeyDown={event => {
        if (event.key === 'ArrowDown' || event.key === 'Enter' || event.key === ' ') { event.preventDefault(); openList() }
        else if (event.key.length === 1 && !event.metaKey && !event.ctrlKey && !event.altKey) openList(event.key)
      }}
      className={cn(fieldClasses(invalid), 'flex w-full min-w-0 items-center gap-2 pr-9 text-left')}>
      <span className="min-w-0 flex-1">
        <span className={cn('block truncate', selected ? 'text-white' : 'text-gray-500')}>{selected ? selected.label : placeholder}</span>
        {selected?.description && <span className="block truncate text-[11px] leading-4 text-gray-500">{selected.description}</span>}
      </span>
      {selected?.badge}
      <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" aria-hidden="true" />
    </button>
    {open && <div ref={panel} style={{ position: 'fixed', top: position.top, left: position.left, width: position.width, maxHeight: position.maxHeight }}
      className="z-[60] flex flex-col overflow-hidden rounded-xl border border-gray-700 bg-gray-900 shadow-2xl shadow-black/50">
      <div className="relative border-b border-gray-800 p-2">
        <Search className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" aria-hidden="true" />
        <input ref={search} role="combobox" aria-expanded="true" aria-controls={listId} aria-autocomplete="list"
          aria-label={`${searchPlaceholder.replace(/…$/, '')}`} aria-activedescendant={activeIndex >= 0 ? `${listId}-${activeIndex}` : undefined}
          value={query} onChange={event => setQuery(event.target.value)} onKeyDown={onKeyDown} placeholder={searchPlaceholder}
          className="w-full rounded-lg border border-gray-700 bg-gray-800 py-1.5 pl-8 pr-8 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-hidden" />
        {query && <button type="button" aria-label="Clear search" onClick={() => { setQuery(''); search.current?.focus() }}
          className="absolute right-4 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-200"><X className="h-3.5 w-3.5" /></button>}
      </div>
      <div id={listId} role="listbox" aria-label={ariaLabel || placeholder} className="min-h-0 flex-1 overflow-y-auto overscroll-contain p-1.5">
        {!visible.length && <p className="px-3 py-6 text-center text-sm text-gray-500">{loading ? 'Searching…' : emptyMessage}</p>}
        {groupOptions(visible).map(group => <div key={group.name || 'all'} role="group" aria-label={group.name || undefined}>
          {group.name && <p className="px-2.5 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-wider text-gray-500">{group.name}</p>}
          {group.options.map(option => {
            index += 1
            const at = visible.indexOf(option)
            const isSelected = option.value === value
            return <div key={`${option.value}-${index}`} id={`${listId}-${at}`} data-index={at} role="option" aria-selected={isSelected}
              aria-disabled={option.disabled || undefined}
              onPointerMove={() => { if (!option.disabled && active !== at) setActive(at) }}
              onClick={() => choose(option)}
              className={cn('flex cursor-pointer items-start gap-2 rounded-lg px-2.5 py-2 text-sm',
                option.disabled ? 'cursor-not-allowed opacity-40' : at === activeIndex ? 'bg-blue-500/15' : 'hover:bg-gray-800')}>
              <Check className={cn('mt-0.5 h-4 w-4 shrink-0', isSelected ? 'text-blue-300' : 'invisible')} aria-hidden="true" />
              <span className="min-w-0 flex-1">
                <span className="flex items-center gap-2">
                  <span className={cn('truncate', option.value ? 'text-gray-100' : 'text-gray-400')}>{option.label}</span>
                  {option.badge}
                </span>
                {option.description && <span className="mt-0.5 block truncate text-xs text-gray-500">{option.description}</span>}
              </span>
              {option.meta && <span className="mt-0.5 max-w-[45%] shrink-0 truncate font-mono text-[11px] text-gray-500">{option.meta}</span>}
            </div>
          })}
        </div>)}
      </div>
      {remote
        ? <p className="border-t border-gray-800 px-3 py-1.5 text-[11px] text-gray-500" aria-live="polite">
            {loading ? 'Searching…' : footerNote || `${visible.length} match${visible.length === 1 ? '' : 'es'}`} · ↑↓ to move, Enter to choose
          </p>
        : all.length > 8 && <p className="border-t border-gray-800 px-3 py-1.5 text-[11px] text-gray-500">{visible.length} of {all.length} · ↑↓ to move, Enter to choose</p>}
    </div>}
  </div>
}
