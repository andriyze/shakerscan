import type { Metadata } from 'next'

// Browser tab titles read "Page · ShakerScan": the page first, so tabs stay distinguishable when
// the browser truncates them. A managed deployment whose edition label names Enterprise reads
// "Page · ShakerScan Enterprise". Presentation only.
export const PRODUCT_NAME = 'ShakerScan'
export const TITLE_SEPARATOR = ' · '
export const TITLE_TEMPLATE = `%s${TITLE_SEPARATOR}${PRODUCT_NAME}`

// The metadata a route segment (its layout.tsx, or a server page) names its page with. It passes
// the template on: in Next.js a plain string title hands its child segments no template, so a
// nested route such as /findings/[id] would read a bare "Finding" instead of
// "Finding · ShakerScan".
export function segmentTitle(name: string): Metadata {
  return { title: { default: name, template: TITLE_TEMPLATE } }
}

// The dashboard's metadata. The root page shares its segment with the root layout, and Next.js
// applies a layout's template only to child segments, so this title is spelled out in full.
export function rootPageTitle(name: string): Metadata {
  return { title: { absolute: `${name}${TITLE_SEPARATOR}${PRODUCT_NAME}` } }
}

// The product line an edition label names, when it changes how the product is called.
export function productEdition(editionLabel: string | undefined): 'Enterprise' | undefined {
  return editionLabel && /\benterprise\b/i.test(editionLabel) ? 'Enterprise' : undefined
}

// The title with the edition added to its product name. Idempotent, and any title that does not
// end with the product name (a page that names itself differently) is left alone.
export function editionTitle(title: string, edition: string | undefined): string {
  if (!edition) return title
  const product = `${PRODUCT_NAME} ${edition}`
  if (title === PRODUCT_NAME) return product
  const suffix = `${TITLE_SEPARATOR}${PRODUCT_NAME}`
  return title.endsWith(suffix) ? `${title.slice(0, -PRODUCT_NAME.length)}${product}` : title
}
