import AISettingsPanel from '@/components/AISettingsPanel'
import ScanExecutionSettingsPanel from '@/components/ScanExecutionSettingsPanel'
import Link from 'next/link'
import { Boxes, ChevronRight, Cpu, ShieldCheck, Sparkles, Wand2 } from 'lucide-react'

type SettingsSection = 'automation' | 'ai' | 'advanced'

const SECTIONS: Array<{
  id: SettingsSection
  label: string
  description: string
}> = [
  {
    id: 'automation',
    label: 'Automation',
    description: 'Scanning and coverage defaults',
  },
  {
    id: 'ai',
    label: 'AI & verification',
    description: 'Provider and retest behavior',
  },
  {
    id: 'advanced',
    label: 'Advanced',
    description: 'Policy and developer tools',
  },
]

function SettingsNav({ active }: { active: SettingsSection }) {
  return (
    <nav aria-label="Settings sections" className="grid gap-2 sm:grid-cols-3">
      {SECTIONS.map((section) => {
        const selected = active === section.id
        return (
          <Link
            key={section.id}
            href={`/settings?section=${section.id}`}
            aria-current={selected ? 'page' : undefined}
            className={`rounded-lg border px-4 py-3 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
              selected
                ? 'border-blue-500/60 bg-blue-500/10'
                : 'border-gray-800 bg-gray-900 hover:border-gray-700 hover:bg-gray-800/80'
            }`}
          >
            <span className={`block text-sm font-medium ${selected ? 'text-blue-200' : 'text-gray-200'}`}>
              {section.label}
            </span>
            <span className="mt-0.5 block text-xs text-gray-500">{section.description}</span>
          </Link>
        )
      })}
    </nav>
  )
}

function DestinationCard({
  href,
  title,
  description,
  icon,
  tone,
  badge,
}: {
  href: string
  title: string
  description: string
  icon: React.ReactNode
  tone: string
  badge?: string
}) {
  return (
    <Link
      href={href}
      className="group flex min-h-32 flex-col justify-between rounded-lg border border-gray-800 bg-gray-900 p-4 transition-colors hover:border-gray-700 hover:bg-gray-800/80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
    >
      <div>
        <div className="flex items-start justify-between gap-3">
          <span className={`flex h-9 w-9 items-center justify-center rounded-lg ${tone}`}>{icon}</span>
          {badge ? (
            <span className="rounded-full border border-gray-700 px-2 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-gray-500">
              {badge}
            </span>
          ) : null}
        </div>
        <h3 className="mt-3 text-sm font-medium text-white">{title}</h3>
        <p className="mt-1 text-xs leading-5 text-gray-500">{description}</p>
      </div>
      <span className="mt-3 inline-flex items-center gap-1 text-xs font-medium text-gray-400 group-hover:text-white">
        Open <ChevronRight className="h-3.5 w-3.5" />
      </span>
    </Link>
  )
}

export default async function SettingsPage({
  searchParams,
}: {
  searchParams: Promise<{ section?: string }>
}) {
  const params = await searchParams
  const requestedSection = params.section
  const activeSection: SettingsSection = SECTIONS.some((section) => section.id === requestedSection)
    ? requestedSection as SettingsSection
    : 'automation'

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Settings</h1>
        <p className="mt-1 max-w-3xl text-sm text-gray-400">
          Configure organization-wide defaults. Settings on an individual scan or target take priority.
        </p>
      </div>

      <SettingsNav active={activeSection} />

      {activeSection === 'automation' ? (
        <section aria-label="Scanning and coverage defaults" className="space-y-4">
          <div className="flex items-start gap-3 rounded-lg border border-gray-800 bg-gray-900/60 px-4 py-3">
            <Cpu className="mt-0.5 h-5 w-5 shrink-0 text-blue-400" />
            <div>
              <p className="text-sm font-medium text-gray-100">Changes save immediately</p>
              <p className="mt-1 text-xs leading-5 text-gray-500">
                These controls save as soon as you change them. They affect new work only unless the control says otherwise.
              </p>
            </div>
          </div>
          <ScanExecutionSettingsPanel />
        </section>
      ) : null}

      {activeSection === 'ai' ? (
        <section aria-label="AI provider and verification" className="space-y-4">
          <div className="flex items-start gap-3 rounded-lg border border-gray-800 bg-gray-900/60 px-4 py-3">
            <Sparkles className="mt-0.5 h-5 w-5 shrink-0 text-purple-400" />
            <div>
              <p className="text-sm font-medium text-gray-100">Review, then save</p>
              <p className="mt-1 text-xs leading-5 text-gray-500">
                Provider changes are applied only after you select Save. Start with Basic; advanced controls are optional.
              </p>
            </div>
          </div>
          <AISettingsPanel />
        </section>
      ) : null}

      {activeSection === 'advanced' ? (
        <section aria-labelledby="advanced-settings-heading" className="space-y-4">
          <div>
            <h2 id="advanced-settings-heading" className="text-base font-semibold text-white">Advanced configuration</h2>
            <p className="mt-1 text-sm text-gray-500">
              Deployment policy and implementation-facing tools. Most users do not need to change these.
            </p>
          </div>
          <div className="grid gap-3 md:grid-cols-3">
            <DestinationCard
              href="/settings/policy-profiles"
              title="Policy profiles"
              description="Control deployment decisions, exceptions, and Model Intake requirements."
              icon={<ShieldCheck className="h-5 w-5" />}
              tone="bg-indigo-600/15 text-indigo-300"
            />
            <DestinationCard
              href="/settings/arsenal"
              title="Command Arsenal"
              description="Inspect registered command contracts, plans, receipts, and integrated tool status."
              icon={<Boxes className="h-5 w-5" />}
              tone="bg-teal-600/15 text-teal-300"
              badge="Developer"
            />
            <DestinationCard
              href="/settings/ai-ops-router"
              title="AI Operations Router"
              description="Preview how natural-language requests map to explicit, safety-gated API operations."
              icon={<Wand2 className="h-5 w-5" />}
              tone="bg-purple-600/15 text-purple-300"
              badge="Developer"
            />
          </div>
        </section>
      ) : null}
    </div>
  )
}
