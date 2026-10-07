'use client'

import { hasObservation, type FindingObservation } from '@/lib/findingObservation'
import { CopyButton } from './CopyButton'
import { Section } from './Section'

export interface AiProbeEvidence {
  prompt: string
  responseExcerpt: string
  probeId: string
  family: string
  technique: string
  judge: string
  tactics: string[]
}

function Label({ children }: { children: React.ReactNode }) {
  return <p className="mb-1.5 text-xs font-medium text-gray-500">{children}</p>
}

// Leads the finding page: the observation the evidence records, before any workflow controls.
export function WhatWeFound({
  observation,
  description,
  payloads,
  signals,
  anomaly,
  aiProbe,
}: {
  observation: FindingObservation
  description: string | null
  payloads: string[]
  signals: string[]
  anomaly: string | null
  aiProbe: AiProbeEvidence | null
}) {
  const allSignals = Array.from(new Set([...observation.signals, ...signals]))
  // The probe block and the payload list already show these; a fact would repeat them.
  const facts = observation.facts.filter((fact) => (
    !(aiProbe && fact.label === 'Technique') && !(payloads.length > 0 && fact.label === 'Payload')
  ))
  const empty = !description && !aiProbe && !hasObservation(observation) && payloads.length === 0 && allSignals.length === 0 && !anomaly

  return (
    <Section id="evidence" title="What we found">
      <div className="space-y-5">
        {description && <p className="whitespace-pre-wrap text-sm leading-6 text-gray-200">{description}</p>}

        {aiProbe && (
          <div className="space-y-3">
            {(aiProbe.family || aiProbe.technique || aiProbe.judge || aiProbe.probeId) && (
              <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
                {aiProbe.family && <div><dt className="text-xs text-gray-500">Family</dt><dd className="text-gray-200">{aiProbe.family.replaceAll('_', ' ')}</dd></div>}
                {aiProbe.technique && <div><dt className="text-xs text-gray-500">Technique</dt><dd className="text-gray-200">{aiProbe.technique.replaceAll('_', ' ')}</dd></div>}
                {aiProbe.judge && <div><dt className="text-xs text-gray-500">Judge</dt><dd className="text-gray-200">{aiProbe.judge.replaceAll('_', ' ')}</dd></div>}
                {aiProbe.probeId && <div className="min-w-0"><dt className="text-xs text-gray-500">Probe ID</dt><dd className="font-mono text-xs text-blue-300 break-all">{aiProbe.probeId}</dd></div>}
              </dl>
            )}
            {aiProbe.tactics.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {aiProbe.tactics.map((tactic) => (
                  <span key={tactic} className="rounded-sm bg-gray-800 px-2 py-0.5 text-xs text-gray-300">{tactic.replaceAll('_', ' ')}</span>
                ))}
              </div>
            )}
            {aiProbe.prompt && (
              <div className="max-w-3xl rounded-lg border border-red-900/50 bg-red-950/30 p-3">
                <p className="text-xs font-medium uppercase tracking-wide text-red-300">Probe</p>
                <p className="mt-2 whitespace-pre-wrap text-sm text-gray-100 wrap-break-word">{aiProbe.prompt}</p>
              </div>
            )}
            {aiProbe.responseExcerpt && (
              <div className="ml-auto max-w-3xl rounded-lg border border-blue-900/50 bg-blue-950/30 p-3">
                <p className="text-xs font-medium uppercase tracking-wide text-blue-300">Target response</p>
                <p className="mt-2 whitespace-pre-wrap text-sm text-gray-100 wrap-break-word">{aiProbe.responseExcerpt}</p>
              </div>
            )}
          </div>
        )}

        {facts.length > 0 && (
          <dl className="grid grid-cols-2 gap-x-6 gap-y-3 lg:grid-cols-3">
            {facts.map((fact) => (
              <div key={fact.label} className="min-w-0">
                <dt className="text-xs text-gray-500">{fact.label}</dt>
                <dd className={`mt-0.5 text-sm text-gray-100 wrap-break-word ${fact.mono ? 'font-mono' : ''}`}>{fact.value}</dd>
              </div>
            ))}
          </dl>
        )}

        {observation.excerpt && (
          <div>
            <Label>Response excerpt <span className="font-normal text-gray-600">· redacted by the server</span></Label>
            <pre className="max-h-64 overflow-auto rounded-md border border-gray-800 bg-gray-950 p-3 font-mono text-xs leading-5 text-gray-200 whitespace-pre-wrap break-all">{observation.excerpt}</pre>
          </div>
        )}

        {observation.responseHeaders.length > 0 && (
          <div>
            <Label>Response headers recorded <span className="font-normal text-gray-600">· the scan&apos;s baseline request to this origin</span></Label>
            <dl className="max-h-64 overflow-auto rounded-md border border-gray-800 bg-gray-950 p-3 font-mono text-xs leading-5">
              {observation.responseHeaders.map((header) => (
                <div key={header.name} className="flex gap-2">
                  <dt className="shrink-0 text-gray-400">{header.name}:</dt>
                  <dd className="min-w-0 break-all text-gray-200">{header.value}</dd>
                </div>
              ))}
            </dl>
          </div>
        )}

        {observation.signatures.length > 0 && (
          <div>
            <Label>Matched {observation.signatures.length === 1 ? 'signature' : 'signatures'}</Label>
            <ul className="space-y-1">
              {observation.signatures.map((signature) => (
                <li key={signature}><code className="font-mono text-xs text-amber-200 break-all">{signature}</code></li>
              ))}
            </ul>
          </div>
        )}

        {observation.responsePairs.length > 0 && (
          <div>
            <Label>Control and payload responses</Label>
            <table className="text-sm">
              <thead>
                <tr className="text-left text-xs text-gray-500">
                  <th scope="col" className="pr-6 font-medium">Run</th>
                  <th scope="col" className="pr-6 font-medium">Control</th>
                  <th scope="col" className="font-medium">With payload</th>
                </tr>
              </thead>
              <tbody className="font-mono text-gray-200">
                {observation.responsePairs.map((pair, index) => (
                  <tr key={index}>
                    <td className="pr-6 text-gray-500">{index + 1}</td>
                    <td className="pr-6">{pair.control || '—'}</td>
                    <td className={pair.payload !== pair.control ? 'text-amber-200' : ''}>{pair.payload || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {(allSignals.length > 0 || anomaly) && (
          <div>
            <Label>Signals</Label>
            <ul className="space-y-1 text-sm text-gray-300">
              {anomaly && <li className="flex gap-2"><span aria-hidden="true" className="text-amber-400">•</span><span className="wrap-break-word">{anomaly}</span></li>}
              {allSignals.map((signal) => (
                <li key={signal} className="flex gap-2"><span aria-hidden="true" className="text-amber-400">•</span><span className="min-w-0 wrap-break-word">{signal}</span></li>
              ))}
            </ul>
          </div>
        )}

        {payloads.length > 0 && (
          <div>
            <Label>Working {payloads.length === 1 ? 'payload' : 'payloads'}</Label>
            <ul className="space-y-1.5">
              {payloads.map((payload, index) => (
                <li key={index} className="flex items-start justify-between gap-2 rounded-sm bg-gray-950 px-2 py-1.5">
                  <code className="min-w-0 flex-1 font-mono text-xs text-yellow-300 break-all">{payload}</code>
                  <CopyButton text={payload} label="Copy payload" />
                </li>
              ))}
            </ul>
          </div>
        )}

        {empty && (
          <p className="text-sm text-gray-500">
            The scanner stored no structured evidence for this finding. The raw record is under Technical details.
          </p>
        )}
      </div>
    </Section>
  )
}
