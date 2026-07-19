import AISettingsPanel from '@/components/AISettingsPanel'
import ScanExecutionSettingsPanel from '@/components/ScanExecutionSettingsPanel'
import { Cpu, Sparkles } from 'lucide-react'
import { PageHeader, Tabs } from '@/components/ui'

type SettingsSection = 'automation' | 'ai'

const SECTIONS: Array<{ id: SettingsSection; label: string }> = [
  { id: 'automation', label: 'Automation' },
  { id: 'ai', label: 'AI & verification' },
]

function IntroBanner({ icon, title, text }: { icon: React.ReactNode; title: string; text: string }) {
  return (
    <div className="flex items-start gap-3 rounded-lg border border-gray-800 bg-gray-900/60 px-4 py-3">
      <span className="mt-0.5 shrink-0">{icon}</span>
      <div>
        <p className="text-sm font-medium text-gray-100">{title}</p>
        <p className="mt-1 text-xs leading-5 text-gray-500">{text}</p>
      </div>
    </div>
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
    ? (requestedSection as SettingsSection)
    : 'automation'

  return (
    <div className="space-y-6">
      <PageHeader
        title="Settings"
        description="Organization-wide defaults. Settings on an individual scan or target take priority."
      />

      <Tabs
        ariaLabel="Settings sections"
        active={activeSection}
        items={SECTIONS.map((section) => ({
          key: section.id,
          label: section.label,
          href: `/settings?section=${section.id}`,
        }))}
      />

      {activeSection === 'automation' ? (
        <section aria-label="Scanning and coverage defaults" className="space-y-4">
          <IntroBanner
            icon={<Cpu className="h-5 w-5 text-blue-400" />}
            title="Changes save immediately"
            text="These controls save as soon as you change them. They affect new work only unless the control says otherwise."
          />
          <ScanExecutionSettingsPanel />
        </section>
      ) : (
        <section aria-label="AI provider and verification" className="space-y-4">
          <IntroBanner
            icon={<Sparkles className="h-5 w-5 text-purple-400" />}
            title="Review, then save"
            text="Provider changes are applied only after you select Save. Start with Basic; advanced controls are optional."
          />
          <AISettingsPanel />
        </section>
      )}
    </div>
  )
}
