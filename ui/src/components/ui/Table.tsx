import { cn } from '@/lib/cn'

/**
 * The one data-table look: a bordered container, a quiet sentence-case header row and hairline
 * row dividers. Use the components for new tables; existing hand-written tables can adopt
 * `tableStyles` class by class without restructuring their markup.
 */
export const tableStyles = {
  container: 'overflow-hidden rounded-lg border border-gray-800 bg-gray-900',
  // Positioned so absolutely placed descendants (sr-only labels) are clipped by the scroller
  // instead of widening the whole document on narrow screens.
  scroll: 'relative overflow-x-auto',
  table: 'w-full text-left text-sm',
  head: 'border-b border-gray-800 bg-gray-900',
  headerCell: 'whitespace-nowrap px-4 py-2.5 text-xs font-medium text-gray-400',
  row: 'group/row border-t border-gray-800 first:border-t-0 transition-colors hover:bg-gray-800/40',
  cell: 'px-4 py-3 align-middle text-gray-300',
} as const

/**
 * For a row's one quick-action button: with a mouse it appears on row hover or keyboard focus,
 * so a long list does not carry a column of identical buttons; on touch it is always shown.
 * The row must carry `group/row` (tableStyles.row and TableRow do).
 */
export const ROW_ACTION_REVEAL =
  'pointer-fine:opacity-0 pointer-fine:transition-opacity pointer-fine:group-hover/row:opacity-100 ' +
  'pointer-fine:group-focus-within/row:opacity-100 pointer-fine:focus-visible:opacity-100'

export function TableContainer({ className = '', children, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn(tableStyles.container, className)} {...props}>
      <div className={tableStyles.scroll}>{children}</div>
    </div>
  )
}

export function Table({ className = '', ...props }: React.TableHTMLAttributes<HTMLTableElement>) {
  return <table className={cn(tableStyles.table, className)} {...props} />
}

export function TableHead({ className = '', ...props }: React.HTMLAttributes<HTMLTableSectionElement>) {
  return <thead className={cn(tableStyles.head, className)} {...props} />
}

export function TableHeaderCell({ className = '', ...props }: React.ThHTMLAttributes<HTMLTableCellElement>) {
  return <th scope="col" className={cn(tableStyles.headerCell, className)} {...props} />
}

export function TableRow({ className = '', ...props }: React.HTMLAttributes<HTMLTableRowElement>) {
  return <tr className={cn(tableStyles.row, className)} {...props} />
}

export function TableCell({ className = '', ...props }: React.TdHTMLAttributes<HTMLTableCellElement>) {
  return <td className={cn(tableStyles.cell, className)} {...props} />
}
