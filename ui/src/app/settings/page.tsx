import AISettingsPanel from '@/components/AISettingsPanel'

export default function SettingsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Settings</h1>
        <p className="text-gray-400 mt-1">Runtime configuration for AI-assisted scan and retest behavior.</p>
      </div>

      <AISettingsPanel />
    </div>
  )
}
