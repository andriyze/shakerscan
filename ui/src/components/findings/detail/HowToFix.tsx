'use client'

import { useState } from 'react'
import type { FindingRemediation } from '@/lib/api'
import { CopyButton } from './CopyButton'
import { Section } from './Section'

// Fix guidance: why it matters, the steps, a configuration example, and how to check the fix.
// Guidance matched by title is labelled general: the knowledge base guessed the kind of issue.
export function HowToFix({ remediation, toolSteps }: { remediation?: FindingRemediation | null; toolSteps: string[] }) {
  const examples = remediation?.code_examples || []
  const [exampleIndex, setExampleIndex] = useState(0)
  const steps = remediation?.steps?.length ? remediation.steps : toolSteps
  if (steps.length === 0) return null
  const example = examples[Math.min(exampleIndex, examples.length - 1)]
  return (
    <Section
      id="remediation"
      title="How to fix"
      actions={remediation ? (
        <span className="flex items-center gap-2 text-xs text-gray-500">
          {remediation.matched_by === 'title' && (
            <span title="Matched by the finding's title, not by what the scanner classified">General guidance</span>
          )}
          {remediation.effort && <span className="rounded-sm bg-gray-800 px-1.5 py-0.5 text-gray-300">Effort: {remediation.effort}</span>}
        </span>
      ) : undefined}
    >
      {remediation?.impact && <p className="mb-3 text-sm text-gray-300">{remediation.impact}</p>}
      <ol className="space-y-2">
        {steps.map((step, i) => (
          <li key={i} className="flex items-start gap-3 text-sm">
            <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-sm border border-gray-600 text-xs text-gray-400">{i + 1}</span>
            <span className="text-gray-200">{step}</span>
          </li>
        ))}
      </ol>
      {example && (
        <div className="mt-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div role="group" aria-label="Configuration example" className="flex flex-wrap gap-1">
              {examples.map((item, i) => (
                <button
                  key={item.label}
                  type="button"
                  aria-pressed={item === example}
                  onClick={() => setExampleIndex(i)}
                  className={`rounded-sm px-2 py-0.5 text-xs font-medium ${item === example ? 'bg-blue-600 text-white' : 'bg-gray-800 text-gray-400 hover:text-gray-200'}`}
                >
                  {item.label}
                </button>
              ))}
            </div>
            <CopyButton text={example.code} label={`Copy ${example.label} example`} />
          </div>
          <pre className="mt-2 overflow-x-auto rounded-md bg-gray-950 p-3 font-mono text-xs leading-5 text-gray-200">{example.code}</pre>
        </div>
      )}
      {remediation?.verification && (
        <div className="mt-4">
          <p className="text-xs font-medium text-gray-400">Check the fix</p>
          <div className="mt-1 flex items-start gap-2">
            <code className="min-w-0 flex-1 overflow-x-auto whitespace-pre rounded-md bg-gray-950 px-3 py-2 font-mono text-xs text-gray-200">{remediation.verification}</code>
            <CopyButton text={remediation.verification} label="Copy check command" />
          </div>
        </div>
      )}
      {(remediation?.references?.length || 0) > 0 && (
        <ul className="mt-4 flex flex-wrap gap-x-4 gap-y-1 text-xs">
          {remediation!.references.map((link) => (
            <li key={link}>
              <a href={link} target="_blank" rel="noopener noreferrer" className="text-blue-300 hover:text-blue-200 break-all">{link.replace(/^https?:\/\//, '')}</a>
            </li>
          ))}
        </ul>
      )}
    </Section>
  )
}
