import { readFile } from 'node:fs/promises'
import path from 'node:path'
import type { ReactNode } from 'react'
import { BookOpen, ExternalLink } from 'lucide-react'
import ReactMarkdown, { type Components } from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { Card, PageHeader } from '@/components/ui'
import { SHAKERSCAN_DOCUMENTATION_BLOB_URL } from '@/lib/repository'

export const dynamic = 'force-dynamic'

async function loadReadme(): Promise<string | null> {
  const configuredPath = process.env.SHAKERSCAN_README_PATH?.trim()
  const candidates = [
    configuredPath,
    '/docs/README.md',
    path.resolve(process.cwd(), '../README.md'),
    path.resolve(process.cwd(), 'README.md'),
  ].filter((candidate): candidate is string => Boolean(candidate))

  for (const candidate of [...new Set(candidates)]) {
    try {
      return await readFile(candidate, 'utf8')
    } catch {
      // Source development and packaged installs use different paths. Try the
      // next fixed candidate without exposing host filesystem details.
    }
  }
  return null
}

function nodeText(node: ReactNode): string {
  if (typeof node === 'string' || typeof node === 'number') return String(node)
  if (Array.isArray(node)) return node.map(nodeText).join(' ')
  if (node && typeof node === 'object' && 'props' in node) {
    return nodeText((node as { props?: { children?: ReactNode } }).props?.children)
  }
  return ''
}

function headingId(children: ReactNode): string {
  return nodeText(children)
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
}

function documentationHref(href?: string): string {
  if (!href) return '#'
  if (href.startsWith('#') || /^(https?:|mailto:)/i.test(href)) return href
  const normalized = href.replace(/^\.\//, '')
  return `${SHAKERSCAN_DOCUMENTATION_BLOB_URL}/${normalized}`
}

const markdownComponents: Components = {
  h1: ({ children }) => (
    <h2 id={headingId(children)} className="mb-5 mt-2 scroll-mt-6 text-3xl font-bold tracking-tight text-white">
      {children}
    </h2>
  ),
  h2: ({ children }) => (
    <h3 id={headingId(children)} className="mb-3 mt-10 scroll-mt-6 border-b border-gray-800 pb-2 text-2xl font-semibold text-white">
      {children}
    </h3>
  ),
  h3: ({ children }) => (
    <h4 id={headingId(children)} className="mb-2 mt-7 scroll-mt-6 text-xl font-semibold text-gray-100">
      {children}
    </h4>
  ),
  h4: ({ children }) => <h5 className="mb-2 mt-6 text-base font-semibold text-gray-100">{children}</h5>,
  p: ({ children }) => <p className="my-4 leading-7 text-gray-300">{children}</p>,
  a: ({ href, children }) => {
    const resolved = documentationHref(href)
    const external = /^(https?:|mailto:)/i.test(resolved)
    return (
      <a
        href={resolved}
        target={external ? '_blank' : undefined}
        rel={external ? 'noopener noreferrer' : undefined}
        className="font-medium text-blue-400 underline decoration-blue-500/40 underline-offset-4 transition-colors hover:text-blue-300"
      >
        {children}
      </a>
    )
  },
  ul: ({ children }) => <ul className="my-4 list-disc space-y-2 pl-6 text-gray-300 marker:text-gray-600">{children}</ul>,
  ol: ({ children }) => <ol className="my-4 list-decimal space-y-2 pl-6 text-gray-300 marker:text-gray-500">{children}</ol>,
  li: ({ children }) => <li className="pl-1 leading-7">{children}</li>,
  blockquote: ({ children }) => (
    <blockquote className="my-5 border-l-4 border-amber-500/60 bg-amber-500/5 px-4 py-1 text-gray-300">
      {children}
    </blockquote>
  ),
  code: ({ className, children, ...props }) => {
    const block = Boolean(className)
    return (
      <code
        className={block ? `text-sm text-gray-200 ${className}` : 'rounded bg-gray-800 px-1.5 py-0.5 text-[0.9em] text-blue-200'}
        {...props}
      >
        {children}
      </code>
    )
  },
  pre: ({ children }) => (
    <pre className="my-5 overflow-x-auto rounded-lg border border-gray-800 bg-gray-950 p-4 leading-6 text-gray-200">
      {children}
    </pre>
  ),
  table: ({ children }) => (
    <div className="my-6 overflow-x-auto rounded-lg border border-gray-800">
      <table className="w-full border-collapse text-left text-sm">{children}</table>
    </div>
  ),
  thead: ({ children }) => <thead className="bg-gray-800/80 text-gray-200">{children}</thead>,
  tbody: ({ children }) => <tbody className="divide-y divide-gray-800">{children}</tbody>,
  th: ({ children }) => <th className="border-r border-gray-700 px-3 py-2 font-semibold last:border-r-0">{children}</th>,
  td: ({ children }) => <td className="border-r border-gray-800 px-3 py-2 align-top text-gray-300 last:border-r-0">{children}</td>,
  hr: () => <hr className="my-8 border-gray-800" />,
  strong: ({ children }) => <strong className="font-semibold text-gray-100">{children}</strong>,
}

export default async function DocsPage() {
  const readme = await loadReadme()

  return (
    <div className="mx-auto max-w-5xl">
      <PageHeader
        title="Documentation"
        icon={<BookOpen className="h-5 w-5" />}
        description="Installation, first steps, workflow selection, safety boundaries, and operator reference."
        actions={
          <a
            href={`${SHAKERSCAN_DOCUMENTATION_BLOB_URL}/README.md`}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 rounded-md border border-gray-700 px-3 py-2 text-sm text-gray-300 transition-colors hover:border-gray-600 hover:bg-gray-800 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
          >
            View on GitHub <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
          </a>
        }
      />

      <Card className="overflow-hidden">
        <div className="flex items-center justify-between border-b border-gray-800 bg-gray-900/80 px-5 py-3">
          <span className="font-mono text-xs text-gray-400">README.md</span>
          <span className="text-xs text-gray-600">Installed documentation</span>
        </div>
        {readme ? (
          <article className="px-5 py-6 sm:px-8 lg:px-10">
            <ReactMarkdown remarkPlugins={[remarkGfm]} components={markdownComponents}>
              {readme}
            </ReactMarkdown>
          </article>
        ) : (
          <div className="px-6 py-16 text-center">
            <BookOpen className="mx-auto h-8 w-8 text-gray-600" aria-hidden="true" />
            <h2 className="mt-3 text-base font-semibold text-gray-200">README unavailable</h2>
            <p className="mt-1 text-sm text-gray-500">
              Restart ShakerScan after updating the runtime files, or open the repository documentation on GitHub.
            </p>
          </div>
        )}
      </Card>
    </div>
  )
}
