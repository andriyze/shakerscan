import AISettingsPanel from '@/components/AISettingsPanel'

export default function SettingsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Settings</h1>
        <p className="text-gray-400 mt-1">
          Runtime configuration for scan-time AI triage, retest verification, and smart-scan output policy. Hover the
          <span className="mx-1 inline-flex h-4 w-4 items-center justify-center rounded-full border border-gray-600 text-[10px] font-semibold text-gray-300">?</span>
          icons for quick explanations.
        </p>
      </div>

      <AISettingsPanel />
    </div>
  )
}
