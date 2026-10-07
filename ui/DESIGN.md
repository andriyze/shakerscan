# ShakerScan UI design rules

One product, one visual language. Every page is built from the primitives in
`src/components/ui/`; if a page needs something they do not offer, extend the primitive instead of
styling a local copy.

## Tokens

`src/app/globals.css` retunes Tailwind's scales, so use the ordinary class names:

- **Gray is ink and graphite.** `gray-950` page, `gray-900` surfaces, `gray-800` hairlines and
  hover fills, `gray-400` secondary text, `gray-500` tertiary text. The scale leans very slightly
  toward the accent. No navy, no gradients, no glows.
- **Blue is ShakerScan cobalt, the only accent.** Primary buttons, links, focus rings, activity
  (running) and the active-filter rule.
- **Color means something.** Red/orange/amber/sky are severities (low is sky, never the accent);
  emerald is proven or healthy. Do not use color to decorate icons, tiles or headings.
- **Radius:** `rounded-lg` (6px) for controls and cards, `rounded-md` inside them. `rounded-xl`
  and `rounded-2xl` resolve to 8px; prefer `rounded-lg`.

## Type: width is the system

One superfamily, self-hosted (the CSP allows fonts from `'self'` only):

- **Body — Archivo, slightly condensed (96%).** Tables and prose stay dense.
- **Readout — Archivo, semi-expanded (`readout` utility).** Page titles, `Stat` values, verdict
  numbers and the wordmark, like the display of a test instrument. This is the product's one
  expressive move: do not apply it to body copy, labels, buttons or table cells.
- **Evidence — IBM Plex Mono (`font-mono`).** Literal values only: URLs, hosts, ports, IDs,
  payloads, signatures. Never labels or headings.
- `tabular-nums` on every number column.

## Page anatomy

1. `PageHeader` — `text-xl` semibold title, one-sentence description, actions on the right.
   No title icons, no eyebrow kickers, no "live" dots.
2. Optional `StatGroup` of `Stat`s — the page's headline numbers in one hairline-divided strip.
   A `Stat` with `onClick` is a quick filter (`active` draws the blue underline).
3. `Toolbar` — `SearchInput` plus `Select` filters, sitting directly on the page (no card).
4. The list: one `TableContainer` (or one `Card`) holding every row. Do not wrap each record in
   its own card; do not nest cards inside cards.

## Lists and rows

- Rows are single-line where possible, ~44px tall, separated by hairlines.
- Header cells are sentence case `text-xs font-medium text-gray-400` (`tableStyles.headerCell`).
- A row shows **at most one quick-action button**, `secondary` or `ghost`, with
  `ROW_ACTION_REVEAL` so mouse users see it on hover/focus (touch always sees it). Everything else
  goes in an `ActionMenu` (…). Destructive actions live only in that menu or a detail page.
- Empty values render as a muted `—` with a `title`/`aria-label` naming what is absent, instead
  of repeating a sentence on every row.
- Names are `text-gray-100` links that turn blue on hover; do not color whole columns blue.
- Repeated explanations (e.g. "secret values hidden") are stated once, in the page description.

## Buttons and badges

- `Button` `primary` once per view (the page's main action). Row and toolbar actions are
  `secondary` or `ghost`, size `sm`.
- `SeverityBadge`, `ProofStateBadge` and finding badges stay filled — they are the signal.
- Lifecycle state (scan/hunt status, active/expired) uses `StatusDot`: a dot and a plain label.
- Tags and kinds (environment, format, slot) are plain `text-gray-400` text or a neutral
  `Badge className="bg-gray-800 text-gray-300"`, never a colored pill.

## Copy

Short, sentence case, no marketing tone. Page descriptions are one sentence. Card titles are
nouns ("Recent activity"), not slogans.
