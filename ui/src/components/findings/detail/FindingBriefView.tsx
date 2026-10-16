'use client'

import Link from '@/components/WorkspaceLink'
import type { BriefCommand, BriefFact, FindingBrief, RelatedFinding } from '@/lib/findingBrief'
import { secretLink } from '@/lib/findingBrief'
import { CopyButton } from './CopyButton'
import { Section } from './Section'

const CONFIDENCE: Record<string, { label: string; tone: string }> = {
  confirmed: { label: 'Confirmed', tone: 'bg-emerald-500/15 text-emerald-300' },
  likely: { label: 'Likely', tone: 'bg-amber-500/15 text-amber-300' },
  tentative: { label: 'Tentative', tone: 'bg-gray-700 text-gray-300' },
}

function FactList({ items }: { items: BriefFact[] }) {
  return (
    <dl className="grid gap-x-6 gap-y-2 sm:grid-cols-2">
      {items.map(item => (
        <div key={`${item.label}:${item.value}`} className="min-w-0">
          <dt className="text-xs text-gray-500">{item.label}</dt>
          <dd className={`mt-0.5 text-sm text-gray-100 wrap-anywhere ${item.mono ? 'font-mono text-xs leading-5' : ''}`}>{item.value}</dd>
        </div>
      ))}
    </dl>
  )
}

function Heading({ children }: { children: React.ReactNode }) {
  return <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-gray-400">{children}</h3>
}

export function CommandBlock({ title, item, testId }: { title: string; item: BriefCommand; testId?: string }) {
  return (
    <div data-testid={testId}>
      <Heading>{title}</Heading>
      <div className="flex items-start gap-2">
        <pre className="min-w-0 flex-1 overflow-x-auto whitespace-pre-wrap break-all rounded-md bg-gray-950 px-3 py-2 font-mono text-xs leading-5 text-gray-200">{item.command}</pre>
        <CopyButton text={item.command} label={`Copy ${title.toLowerCase()} command`} />
      </div>
      {item.expect && <p className="mt-1 text-xs text-gray-400">Expect: <span className="text-gray-200">{item.expect}</span></p>}
      {item.note && <p className="mt-1 text-xs text-gray-500">{item.note}</p>}
    </div>
  )
}

// Leads the finding page: what is wrong in concrete terms, the proof, how sure, how to reproduce.
export function FindingBriefView({ brief, targetId, related }: { brief: FindingBrief; targetId?: string; related: RelatedFinding[] }) {
  const confidence = brief.confidence ? CONFIDENCE[brief.confidence.level] || CONFIDENCE.tentative : null
  return (
    <Section id="brief" title={brief.label || 'Finding'} actions={confidence ? (
      <span className={`rounded px-2 py-0.5 text-xs font-medium ${confidence.tone}`} title="How sure the scanner is">{confidence.label}</span>
    ) : undefined}>
      <div className="space-y-5" data-testid="finding-brief">
        {brief.summary && <p className="text-[15px] leading-6 text-gray-100 wrap-break-word" data-testid="finding-brief-summary">{brief.summary}</p>}

        {brief.where.length > 0 && <div><Heading>Where</Heading><FactList items={brief.where} /></div>}

        {(brief.observed.length > 0 || brief.expected.length > 0) && (
          <div className="grid gap-4 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
            {brief.observed.length > 0 && <div><Heading>Observed</Heading><FactList items={brief.observed} /></div>}
            {brief.expected.length > 0 && (
              <div>
                <Heading>Expected</Heading>
                <ul className="space-y-1 text-sm text-gray-200">
                  {brief.expected.map(line => <li key={line} className="font-mono text-xs leading-5 wrap-anywhere">{line}</li>)}
                </ul>
              </div>
            )}
          </div>
        )}

        {brief.secrets.length > 0 && (
          <div>
            <Heading>Secrets in the response <span className="font-normal normal-case text-gray-500">· values never stored or shown</span></Heading>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="text-xs text-gray-500"><tr><th className="pr-4 font-medium">Field</th><th className="pr-4 font-medium">Kind</th><th className="pr-4 font-medium">Length</th><th className="font-medium">Stored as</th></tr></thead>
                <tbody>
                  {brief.secrets.map((secret, index) => {
                    const href = secretLink(targetId, secret.ref)
                    return (
                      <tr key={`${secret.field}-${index}`} className="border-t border-gray-800">
                        <td className="py-1 pr-4 font-mono text-xs text-amber-200 break-all">{secret.field || '—'}</td>
                        <td className="py-1 pr-4 text-gray-300">{secret.category || '—'}</td>
                        <td className="py-1 pr-4 text-gray-300">{secret.length ?? '—'}</td>
                        <td className="py-1 font-mono text-xs break-all">{secret.ref ? (href ? <Link href={href} className="text-blue-300 hover:text-blue-200">{secret.ref}</Link> : secret.ref) : '—'}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {brief.excerpt && (
          <div>
            <Heading>{brief.excerpt.label}</Heading>
            <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-md border border-gray-800 bg-gray-950 p-3 font-mono text-xs leading-5 text-gray-200">{brief.excerpt.text}</pre>
          </div>
        )}

        {brief.pairs.length > 0 && (
          <div>
            <Heading>Control versus payload responses</Heading>
            <table className="text-sm">
              <thead><tr className="text-left text-xs text-gray-500"><th className="pr-6 font-medium">Run</th><th className="pr-6 font-medium">Control</th><th className="font-medium">With payload</th></tr></thead>
              <tbody className="font-mono text-gray-200">
                {brief.pairs.map((pair, index) => (
                  <tr key={index}><td className="pr-6 text-gray-500">{index + 1}</td><td className="pr-6">{pair.control || '—'}</td><td className={pair.payload !== pair.control ? 'text-amber-200' : ''}>{pair.payload || '—'}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {brief.cves.map(cve => (
          <div key={cve.id} className="rounded-md border border-gray-800 bg-gray-950/60 p-3 text-sm" data-testid="finding-brief-cve">
            <div className="flex flex-wrap items-center gap-2">
              {cve.nvd ? <a href={cve.nvd} target="_blank" rel="noopener noreferrer" className="font-mono text-blue-300 hover:text-blue-200">{cve.id}</a> : <span className="font-mono">{cve.id}</span>}
              {cve.kev && <span className="rounded bg-red-500/15 px-2 py-0.5 text-xs font-medium text-red-300">Known exploited{cve.kev.dateAdded ? ` · since ${cve.kev.dateAdded}` : ''}{cve.kev.ransomware ? ' · ransomware' : ''}</span>}
              {cve.epss !== null && <span className="text-xs text-gray-400">EPSS {(cve.epss * 100).toFixed(1)}%</span>}
            </div>
            {cve.title && <p className="mt-1 text-gray-300">{cve.title}</p>}
            {cve.affected.length > 0 && <p className="mt-1 text-xs text-gray-400">Affected: <span className="text-gray-200">{cve.affected.join('; ')}</span></p>}
            {cve.fixedIn.length > 0 && <p className="mt-1 text-xs text-gray-400">Fixed in: <span className="text-gray-200">{cve.fixedIn.join('; ')}</span></p>}
          </div>
        ))}

        {brief.context.length > 0 && (
          <div>
            <Heading>Why it matters here</Heading>
            <ul className="space-y-1.5 text-sm text-gray-300">
              {brief.context.map(line => <li key={line} className="flex gap-2"><span aria-hidden="true" className="text-amber-400">•</span><span className="min-w-0 wrap-break-word">{line}</span></li>)}
            </ul>
          </div>
        )}

        {brief.confidence?.reason && (
          <p className="text-xs text-gray-400"><span className="font-medium text-gray-300">Confidence: {confidence?.label}.</span> {brief.confidence.reason}</p>
        )}

        {brief.reproduce && <CommandBlock title="Reproduce" item={brief.reproduce} testId="finding-brief-reproduce" />}

        {brief.severity?.reason && (
          <div data-testid="finding-brief-severity">
            <Heading>Why {brief.severity.severity}</Heading>
            <p className="text-sm leading-6 text-gray-300 wrap-break-word">{brief.severity.reason}</p>
            {brief.severity.currentRule && (
              <p className="mt-1 text-xs text-amber-300">Recorded as {brief.severity.severity} when found; the current rule rates this {brief.severity.currentRule.severity}. {brief.severity.policy}</p>
            )}
            {brief.severity.producerSeverity && !brief.severity.currentRule && (
              <p className="mt-1 text-xs text-gray-500">The check reported {brief.severity.producerSeverity}; calibrated to {brief.severity.severity} by rule.</p>
            )}
            {brief.severity.proofNote && <p className="mt-1 text-xs text-gray-500">{brief.severity.proofNote}</p>}
          </div>
        )}

        {related.length > 0 && (
          <div>
            <Heading>Related findings</Heading>
            <ul className="space-y-1 text-sm">
              {related.map(item => (
                <li key={item.id} className="flex min-w-0 flex-wrap items-baseline gap-x-2">
                  <span className="text-xs text-gray-500">{item.relation} ·</span>
                  <Link href={`/findings/${item.id}`} className="min-w-0 text-blue-300 hover:text-blue-200 wrap-break-word">{item.title}</Link>
                  <span className="text-xs uppercase text-gray-500">{item.severity}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </Section>
  )
}
