'use client'

import { useEffect, useState } from 'react'
import {
  getAISettings,
  testAISettings,
  updateAISettings,
  type AISettings,
  type AISettingsUpdate,
} from '@/lib/api'
import { Button, Fieldset, Tabs, ToggleVisual, fieldClasses, useToast } from '@/components/ui'

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

const SEVERITY_OPTIONS: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
// Point the panel's local field class at the shared field styling so every
// input/select here matches the rest of the app and gets a real focus ring.
const INPUT_CLASS = `mt-1 w-full ${fieldClasses()}`
const HONEY_HOSTED_URL = 'https://honey.shakerscan.com'
const HONEY_LOCAL_PUBLIC_URL = 'http://localhost:18080'
const HONEY_LOCAL_SCANNER_URL = 'http://host.docker.internal:18080'

type DemoHoneyMode = 'hosted' | 'local' | 'custom'

function normalizeUrlValue(value?: string): string {
  const raw = String(value || '').trim().replace(/\/+$/, '')
  try {
    const url = new URL(raw)
    url.protocol = url.protocol.toLowerCase()
    url.hostname = url.hostname.toLowerCase()
    return url.toString().replace(/\/+$/, '')
  } catch {
    return raw
  }
}

function deriveDockerReachableUrl(value: string): string {
  const trimmed = normalizeUrlValue(value)
  try {
    const url = new URL(trimmed)
    if (url.hostname === 'localhost' || url.hostname === '127.0.0.1') {
      url.hostname = 'host.docker.internal'
      return normalizeUrlValue(url.toString())
    }
  } catch {
    return trimmed
  }
  return trimmed
}

function detectDemoHoneyMode(publicURL: string, scannerURL: string): DemoHoneyMode {
  const publicValue = normalizeUrlValue(publicURL)
  const scannerValue = normalizeUrlValue(scannerURL)
  if (publicValue === HONEY_HOSTED_URL && scannerValue === HONEY_HOSTED_URL) return 'hosted'
  if (publicValue === HONEY_LOCAL_PUBLIC_URL && scannerValue === HONEY_LOCAL_SCANNER_URL) return 'local'
  return 'custom'
}

export default function AISettingsPanel() {
  const toast = useToast()
  const [aiSettings, setAISettings] = useState<AISettings | null>(null)
  const [aiSettingsError, setAISettingsError] = useState<string | null>(null)
  const [aiSettingsMessage, setAISettingsMessage] = useState<string | null>(null)
  const [aiSaving, setAISaving] = useState(false)
  const [loading, setLoading] = useState(true)
  const [scanAPIKeyInput, setScanAPIKeyInput] = useState('')
  const [clearScanAPIKey, setClearScanAPIKey] = useState(false)
  const [persistAIToEnv, setPersistAIToEnv] = useState(false)
  const [aiURLInput, setAIURLInput] = useState('')
  const [aiModelInput, setAIModelInput] = useState('')
  const [aiModelFallbackInput, setAIModelFallbackInput] = useState('')
  const [aiMaskHostInput, setAIMaskHostInput] = useState('')
  const [aiScanClassificationEnabledInput, setAIScanClassificationEnabledInput] = useState(false)
  const [aiClassifyMinSeverityInput, setAIClassifyMinSeverityInput] = useState<Severity>('high')
  const [aiVerifyEnabledInput, setAIVerifyEnabledInput] = useState(false)
  const [aiVerifyMinSeverityInput, setAIVerifyMinSeverityInput] = useState<Severity>('high')
  const [autoRetestEnabledInput, setAutoRetestEnabledInput] = useState(true)
  const [autoRetestMinSeverityInput, setAutoRetestMinSeverityInput] = useState<Severity>('medium')
  const [autoRetestMaxPerScanInput, setAutoRetestMaxPerScanInput] = useState('25')
  const [verificationMinSeverityInput, setVerificationMinSeverityInput] = useState<Severity>('medium')
  const [aiEscalationMinSeverityInput, setAIEscalationMinSeverityInput] = useState<Severity>('high')
  const [proofRequiredForSmartInput, setProofRequiredForSmartInput] = useState(false)
  const [autoFpOnRetestInput, setAutoFpOnRetestInput] = useState(false)
  const [autoFpMinConfidenceInput, setAutoFpMinConfidenceInput] = useState('0.9')
  const [demoModeEnabledInput, setDemoModeEnabledInput] = useState(false)
  const [demoHoneyModeInput, setDemoHoneyModeInput] = useState<DemoHoneyMode>('custom')
  const [demoHoneyPublicURLInput, setDemoHoneyPublicURLInput] = useState('')
  const [demoHoneyScannerURLInput, setDemoHoneyScannerURLInput] = useState('')
  const [showDemoNetworking, setShowDemoNetworking] = useState(false)
  const [settingsMode, setSettingsMode] = useState<'basic' | 'advanced'>('basic')
  const [testingScope, setTestingScope] = useState<'scan' | 'verify' | null>(null)
  const [scanProbeMessage, setScanProbeMessage] = useState<string | null>(null)
  const [verifyProbeMessage, setVerifyProbeMessage] = useState<string | null>(null)

  const applyAISettingsToForm = (settings: AISettings) => {
    const verificationSeverity = settings.verification_min_severity || settings.auto_retest_min_severity || 'medium'
    const aiEscalationSeverity = settings.ai_escalation_min_severity || settings.ai_verify_min_severity || 'high'
    setAIURLInput(settings.ai_url || '')
    setAIModelInput(settings.ai_model || '')
    setAIModelFallbackInput(settings.ai_model_fallback || '')
    setAIMaskHostInput(settings.ai_mask_host || '')
    setAIScanClassificationEnabledInput(Boolean(settings.ai_scan_classification_enabled))
    setAIClassifyMinSeverityInput(settings.ai_classify_min_severity || settings.ai_verify_min_severity || 'high')
    setAIVerifyEnabledInput(Boolean(settings.ai_verify_enabled))
    setAIVerifyMinSeverityInput(aiEscalationSeverity)
    setAutoRetestEnabledInput(Boolean(settings.auto_retest_on_scan_complete))
    setAutoRetestMinSeverityInput(verificationSeverity)
    setAutoRetestMaxPerScanInput(String(settings.auto_retest_max_per_scan ?? 25))
    setVerificationMinSeverityInput(verificationSeverity)
    setAIEscalationMinSeverityInput(aiEscalationSeverity)
    setProofRequiredForSmartInput(Boolean(settings.proof_required_for_smart))
    setAutoFpOnRetestInput(Boolean(settings.auto_fp_on_retest))
    setAutoFpMinConfidenceInput(String(settings.auto_fp_min_confidence ?? 0.9))
    setDemoModeEnabledInput(Boolean(settings.demo_mode_enabled))
    const publicURL = settings.demo_honey_public_url || ''
    const scannerURL = settings.demo_honey_scanner_url || ''
    setDemoHoneyPublicURLInput(publicURL)
    setDemoHoneyScannerURLInput(scannerURL)
    setDemoHoneyModeInput(detectDemoHoneyMode(publicURL, scannerURL))
    setScanAPIKeyInput('')
    setClearScanAPIKey(false)
    setScanProbeMessage(null)
    setVerifyProbeMessage(null)
  }

  const fetchAISettings = async () => {
    try {
      const settings = await getAISettings()
      setAISettings(settings)
      setAISettingsError(null)
      applyAISettingsToForm(settings)
    } catch {
      setAISettingsError('AI settings unavailable')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchAISettings()
  }, [])

  const handleSaveAISettings = async () => {
    if (aiSaving) return
    setAISettingsError(null)
    setAISettingsMessage(null)
    if (SEVERITY_RANK[aiEscalationMinSeverityInput] < SEVERITY_RANK[verificationMinSeverityInput]) {
      const message = 'AI escalation cannot include severities excluded by the verification baseline.'
      setAISettingsError(message)
      toast.error(message)
      return
    }
    setAISaving(true)

    try {
      const payload: AISettingsUpdate = {
        ai_url: aiURLInput,
        ai_model: aiModelInput,
        ai_model_fallback: aiModelFallbackInput,
        ai_mask_host: aiMaskHostInput,
        ai_scan_classification_enabled: aiScanClassificationEnabledInput,
        ai_classify_min_severity: aiClassifyMinSeverityInput,
        ai_verify_enabled: aiVerifyEnabledInput,
        auto_retest_on_scan_complete: autoRetestEnabledInput,
        auto_retest_max_per_scan: Math.max(0, Number.parseInt(autoRetestMaxPerScanInput || '0', 10) || 0),
        verification_min_severity: verificationMinSeverityInput,
        ai_escalation_min_severity: aiEscalationMinSeverityInput,
        proof_required_for_smart: proofRequiredForSmartInput,
        auto_fp_on_retest: autoFpOnRetestInput,
        auto_fp_min_confidence: Math.min(1, Math.max(0, Number.parseFloat(autoFpMinConfidenceInput || '0.9') || 0.9)),
        demo_mode_enabled: demoModeEnabledInput,
        demo_honey_public_url: demoModeEnabledInput ? demoHoneyPublicURLInput : '',
        demo_honey_scanner_url: demoModeEnabledInput ? demoHoneyScannerURLInput : '',
        persist_to_env: persistAIToEnv,
      }

      if (clearScanAPIKey) {
        payload.ai_api_key = ''
      } else if (scanAPIKeyInput.trim()) {
        payload.ai_api_key = scanAPIKeyInput.trim()
      }

      const result = await updateAISettings(payload)
      setAISettings(result.settings)
      applyAISettingsToForm(result.settings)
      const successMessage = result.persisted_to_env
        ? result.persist_message || 'AI settings updated and persisted to .env'
        : 'AI runtime settings updated'
      setAISettingsMessage(successMessage)
      toast.success(successMessage)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to update AI settings'
      setAISettingsError(message)
      toast.error(message)
    } finally {
      setAISaving(false)
    }
  }

  const handleTestAISettings = async (scope: 'scan' | 'verify') => {
    if (aiSaving || testingScope) return
    setAISettingsError(null)
    if (scope === 'scan') {
      setScanProbeMessage(null)
    } else {
      setVerifyProbeMessage(null)
    }
    setTestingScope(scope)

    try {
      const result = await testAISettings({
        scope,
        ai_url: aiURLInput || undefined,
        ai_api_key: scanAPIKeyInput.trim() || undefined,
        ai_model: aiModelInput || undefined,
        ai_fallback_model: aiModelFallbackInput || undefined,
      })

      const usedModel = String(result.probe?.provider_meta?.model_used || '').trim()
      const latency = result.probe?.latency_ms
      const detail = usedModel ? `model ${usedModel}` : 'provider responded'
      const latencyLabel = typeof latency === 'number' ? ` in ${latency}ms` : ''
      const message =
        result.status === 'ok'
          ? `Probe succeeded (${detail}${latencyLabel}).`
          : `Probe failed: ${result.probe?.error || 'unknown error'}`

      if (scope === 'scan') {
        setScanProbeMessage(message)
      } else {
        setVerifyProbeMessage(message)
      }
      if (result.status === 'ok') {
        toast.success(message)
      } else {
        toast.error(message)
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to test AI settings'
      if (scope === 'scan') {
        setScanProbeMessage(`Probe failed: ${message}`)
      } else {
        setVerifyProbeMessage(`Probe failed: ${message}`)
      }
      setAISettingsError(message)
      toast.error(`Probe failed: ${message}`)
    } finally {
      setTestingScope(null)
    }
  }

  const setUnifiedVerificationSeverity = (severity: Severity) => {
    setAIVerifyMinSeverityInput(severity)
    setVerificationMinSeverityInput(severity)
    setAIEscalationMinSeverityInput(severity)
    setAutoRetestMinSeverityInput(severity)
  }

  const updateVerificationSeverity = (severity: Severity) => {
    setVerificationMinSeverityInput(severity)
    setAutoRetestMinSeverityInput(severity)
  }

  const updateAIEscalationSeverity = (severity: Severity) => {
    setAIEscalationMinSeverityInput(severity)
    setAIVerifyMinSeverityInput(severity)
  }

  const selectDemoHoneyMode = (mode: DemoHoneyMode) => {
    setDemoHoneyModeInput(mode)
    if (mode === 'hosted') {
      setDemoHoneyPublicURLInput(HONEY_HOSTED_URL)
      setDemoHoneyScannerURLInput(HONEY_HOSTED_URL)
      setShowDemoNetworking(false)
    } else if (mode === 'local') {
      setDemoHoneyPublicURLInput(HONEY_LOCAL_PUBLIC_URL)
      setDemoHoneyScannerURLInput(HONEY_LOCAL_SCANNER_URL)
    } else {
      setShowDemoNetworking(true)
    }
  }

  const updateDemoPublicURL = (value: string) => {
    setDemoHoneyPublicURLInput(value)
    if (demoHoneyModeInput === 'local') {
      setDemoHoneyScannerURLInput(deriveDockerReachableUrl(value))
    } else {
      setDemoHoneyModeInput('custom')
      setShowDemoNetworking(true)
    }
  }

  const thresholdContradiction = SEVERITY_RANK[aiEscalationMinSeverityInput]
    < SEVERITY_RANK[verificationMinSeverityInput]

  if (loading && !aiSettings) {
    return (
      <div className="bg-gray-900 rounded-lg border border-gray-800 p-4 text-sm text-gray-400">
        Loading AI settings...
      </div>
    )
  }

  return (
    <div className="bg-gray-900 rounded-lg border border-gray-800 p-4 space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-medium text-gray-200">AI provider & verification</h2>
          <p className="text-xs text-gray-500 mt-1">
            Configure scan-time triage, authoritative retest verification, and verified-only Scan reporting.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="secondary" size="sm" onClick={fetchAISettings} disabled={loading || aiSaving}>
            Refresh
          </Button>
          <Button size="sm" onClick={handleSaveAISettings} loading={aiSaving} disabled={loading || thresholdContradiction}>
            {aiSaving ? 'Saving…' : 'Save'}
          </Button>
        </div>
      </div>

      {aiSettings && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-2 text-xs">
          <div className="bg-gray-800/70 border border-gray-700 rounded px-2 py-1.5 text-gray-300">
            Shared key: {aiSettings.ai_api_key_configured ? 'configured' : 'not set'}
          </div>
          <div className="bg-gray-800/70 border border-gray-700 rounded px-2 py-1.5 text-gray-300">
            AI retest: {aiSettings.ai_verify_enabled ? 'enabled' : 'disabled'}
          </div>
          <div className="bg-gray-800/70 border border-gray-700 rounded px-2 py-1.5 text-gray-300">
            Scan classification:{' '}
            {aiSettings.ai_scan_classification_enabled ? `on (${aiSettings.ai_classify_min_severity}+)` : 'off'}
          </div>
          <div className="bg-gray-800/70 border border-gray-700 rounded px-2 py-1.5 text-gray-300">
            Smart proof filter: {aiSettings.proof_required_for_smart ? 'on' : 'off'}
          </div>
        </div>
      )}

      <Tabs
        ariaLabel="AI settings detail level"
        active={settingsMode}
        onChange={(key) => setSettingsMode(key as 'basic' | 'advanced')}
        items={[
          { key: 'basic', label: 'Basic' },
          { key: 'advanced', label: 'Advanced' },
        ]}
      />

      {(settingsMode === 'advanced' || demoModeEnabledInput) && (
        <Fieldset
          title="Calibration Lab"
          description="Optional Honey regression runner for maintainers. Leave disabled for normal ShakerScan deployments."
        >
          <ToggleRow
            label="Enable Honey calibration controls"
            description="Adds the hidden Honey runner to AI Gate and allows ShakerScan to queue calibration-only targets."
            hint="Calibration targets stay hidden from the normal AI target list unless Show demo targets is enabled."
            checked={demoModeEnabledInput}
            onChange={setDemoModeEnabledInput}
          />

          {demoModeEnabledInput && (
            <div className="space-y-3 rounded border border-gray-800 bg-gray-900/50 p-3">
              <div>
                <p className="text-xs font-medium text-gray-300">Honey source</p>
                <p className="text-[11px] text-gray-500 mt-0.5">
                  Hosted uses the public Honey service. Local uses your dev Honey on port 18080 and rewrites scanner traffic for Docker.
                </p>
              </div>
              <Tabs
                ariaLabel="Honey source"
                active={demoHoneyModeInput}
                onChange={(key) => selectDemoHoneyMode(key as DemoHoneyMode)}
                items={[
                  { key: 'hosted', label: 'Hosted Honey' },
                  { key: 'local', label: 'Local Honey' },
                  { key: 'custom', label: 'Custom' },
                ]}
              />

              <Field
                label={demoHoneyModeInput === 'local' ? 'Local Honey URL' : 'Honey URL'}
                hint="Browser-facing URL used for labels and links."
              >
                <input
                  type="url"
                  value={demoHoneyPublicURLInput}
                  onChange={(e) => updateDemoPublicURL(e.target.value)}
                  className={INPUT_CLASS}
                  placeholder={demoHoneyModeInput === 'local' ? HONEY_LOCAL_PUBLIC_URL : HONEY_HOSTED_URL}
                />
              </Field>

              {demoHoneyModeInput === 'local' && (
                <p className="text-[11px] text-gray-500">
                  Docker scanner traffic will use <span className="font-mono text-gray-400">{demoHoneyScannerURLInput || HONEY_LOCAL_SCANNER_URL}</span>.
                </p>
              )}

              <button
                type="button"
                onClick={() => setShowDemoNetworking(!showDemoNetworking)}
                aria-expanded={showDemoNetworking}
                className="rounded text-xs text-gray-400 hover:text-gray-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
              >
                {showDemoNetworking ? 'Hide networking details' : 'Show networking details'}
              </button>

              {showDemoNetworking && (
                <Field
                  label="Scanner-reachable Honey URL"
                  hint="URL that API and worker containers can reach. Local Docker scans usually need host.docker.internal."
                >
                  <input
                    type="url"
                    value={demoHoneyScannerURLInput}
                    onChange={(e) => {
                      setDemoHoneyScannerURLInput(e.target.value)
                      setDemoHoneyModeInput(detectDemoHoneyMode(demoHoneyPublicURLInput, e.target.value))
                    }}
                    className={INPUT_CLASS}
                    placeholder={HONEY_LOCAL_SCANNER_URL}
                  />
                </Field>
              )}
            </div>
          )}
        </Fieldset>
      )}

      <div className="rounded border border-blue-500/30 bg-blue-500/10 px-3 py-2">
        <p className="text-xs font-medium text-blue-200">Pipeline flow</p>
        <p className="text-xs text-blue-100/90 mt-1">
          Scanner tools run first. Optional scan-time AI helps with triage. Retests run deterministic proofs first, then
          optional AI escalation for hard cases.
        </p>
      </div>

      {settingsMode === 'basic' ? (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <Fieldset
            title="Quick Setup"
            description="Recommended defaults for most teams: configure one key, enable retest AI, set severity threshold."
          >
            <Field
              label="AI API Key"
              hint="Primary key used for AI provider access. Advanced mode supports separate retest key/provider."
            >
              <input
                type="password"
                autoComplete="off"
                value={scanAPIKeyInput}
                onChange={(e) => setScanAPIKeyInput(e.target.value)}
                className={INPUT_CLASS}
                placeholder={aiSettings?.ai_api_key_configured ? 'Configured (enter to replace)' : 'sk-...'}
              />
            </Field>
            <ToggleRow
              label="Enable AI verification for retests"
              description="Uses AI only when deterministic retest cannot confidently conclude."
              hint="Deterministic proof checks still run first."
              checked={aiVerifyEnabledInput}
              onChange={setAIVerifyEnabledInput}
            />
            <Field
              label="Minimum Severity for AI Verification"
              hint="Findings below this severity are not escalated to AI retest."
            >
              <select
                value={aiVerifyMinSeverityInput}
                onChange={(e) => setUnifiedVerificationSeverity(e.target.value as Severity)}
                className={INPUT_CLASS}
              >
                {SEVERITY_OPTIONS.map((sev) => (
                  <option key={sev} value={sev}>
                    {sev}
                  </option>
                ))}
              </select>
            </Field>
            <p className="text-xs text-gray-500">
              Need provider/model overrides, proof-gated smart mode, scan-time AI classification, or auto-retest tuning?
              Switch to <span className="text-gray-300">Advanced</span>.
            </p>
            <div className="flex items-center gap-2 pt-1">
              <Button
                variant="secondary"
                size="sm"
                onClick={() => handleTestAISettings('verify')}
                loading={testingScope === 'verify'}
                disabled={loading || aiSaving || testingScope !== null}
              >
                {testingScope === 'verify' ? 'Testing retest AI…' : 'Test AI Verification'}
              </Button>
              {verifyProbeMessage && (
                <span className={`text-xs ${verifyProbeMessage.startsWith('Probe succeeded') ? 'text-green-400' : 'text-red-400'}`}>
                  {verifyProbeMessage}
                </span>
              )}
            </div>
          </Fieldset>
        </div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <Fieldset
          title="Shared Provider"
          description="Default provider used for scan-time classification and as fallback for retest verification."
        >
          <Field
            label="AI URL"
            hint="OpenAI-compatible endpoint used for scan-time AI, and as fallback for retest AI if verify URL is empty."
          >
            <input
              type="text"
              value={aiURLInput}
              onChange={(e) => setAIURLInput(e.target.value)}
              className={INPUT_CLASS}
              placeholder="https://api.openai.com/v1/chat/completions"
            />
          </Field>
          <Field label="AI Model" hint="Primary model for scan-time AI calls.">
            <input
              type="text"
              value={aiModelInput}
              onChange={(e) => setAIModelInput(e.target.value)}
              className={INPUT_CLASS}
              placeholder="gpt-4o-mini"
            />
          </Field>
          <Field
            label="Fallback Models (comma-separated)"
            hint="Tried in order when the primary model fails or returns incompatible output."
          >
            <input
              type="text"
              value={aiModelFallbackInput}
              onChange={(e) => setAIModelFallbackInput(e.target.value)}
              className={INPUT_CLASS}
              placeholder="deepseek/deepseek-chat,openai/gpt-4o-mini"
            />
          </Field>
          <Field
            label="Mask Host"
            hint="Host used to redact sensitive domains/URLs in prompts sent to AI providers."
          >
            <input
              type="text"
              value={aiMaskHostInput}
              onChange={(e) => setAIMaskHostInput(e.target.value)}
              className={INPUT_CLASS}
              placeholder="example.com"
            />
          </Field>
          <Field label="AI API Key" hint="Shared provider key used unless a dedicated retest key is configured.">
            <input
              type="password"
              autoComplete="off"
              value={scanAPIKeyInput}
              onChange={(e) => setScanAPIKeyInput(e.target.value)}
              className={INPUT_CLASS}
              placeholder={aiSettings?.ai_api_key_configured ? 'Configured (enter to replace)' : 'sk-...'}
            />
          </Field>
          <ToggleRow
            label="Clear shared provider API key"
            description="Removes the currently stored shared key when you click Save."
            hint="Only applies on save."
            checked={clearScanAPIKey}
            onChange={setClearScanAPIKey}
          />
          <div className="flex items-center gap-2 pt-1">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => handleTestAISettings('scan')}
              loading={testingScope === 'scan'}
              disabled={loading || aiSaving || testingScope !== null}
            >
              {testingScope === 'scan' ? 'Testing provider…' : 'Test Shared Provider'}
            </Button>
            {scanProbeMessage && (
              <span className={`text-xs ${scanProbeMessage.startsWith('Probe succeeded') ? 'text-green-400' : 'text-red-400'}`}>
                {scanProbeMessage}
              </span>
            )}
          </div>
        </Fieldset>

        <Fieldset
          title="Scan-Time Classification"
          description="Optional AI triage during report generation. This does not replace retest verification."
        >
          <ToggleRow
            label="Enable scan-time AI classification"
            description="Uses AI during scan result processing to help classify findings."
            hint="When off, scan findings rely only on scanner/tool logic."
            checked={aiScanClassificationEnabledInput}
            onChange={setAIScanClassificationEnabledInput}
          />
          <Field
            label="Scan Classification Min Severity"
            hint="Only findings at or above this severity are sent to scan-time AI classification."
          >
            <select
              value={aiClassifyMinSeverityInput}
              onChange={(e) => setAIClassifyMinSeverityInput(e.target.value as Severity)}
              disabled={!aiScanClassificationEnabledInput}
              className={`${INPUT_CLASS} disabled:opacity-50`}
            >
              {SEVERITY_OPTIONS.map((sev) => (
                <option key={sev} value={sev}>
                  {sev}
                </option>
              ))}
            </select>
          </Field>
          <p className="text-xs text-gray-500">
            Recommendation: keep this at <code>medium</code> or higher for lower noise.
          </p>
        </Fieldset>

        <Fieldset
          title="Retest Verification (Authoritative)"
          description="AI settings used for post-scan retest verification and exploit validation."
        >
          <ToggleRow
            label="Enable AI verification for retests"
            description="Allows AI escalation when deterministic retest cannot confidently conclude."
            hint="Deterministic checks still run first."
            checked={aiVerifyEnabledInput}
            onChange={setAIVerifyEnabledInput}
          />
          <p className="text-xs text-gray-500">
            Retest AI uses the shared provider settings from <span className="text-gray-300">Shared Provider</span>.
          </p>
          <div className="rounded border border-gray-800 bg-gray-950/50 px-3 py-2 text-xs text-gray-400">
            Effective AI threshold: <span className="font-medium text-gray-200">{aiEscalationMinSeverityInput}</span>.
            Change it once under Verification Policy below.
          </div>
          <div className="flex items-center gap-2 pt-1">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => handleTestAISettings('verify')}
              loading={testingScope === 'verify'}
              disabled={loading || aiSaving || testingScope !== null}
            >
              {testingScope === 'verify' ? 'Testing retest AI…' : 'Test Retest AI'}
            </Button>
            {verifyProbeMessage && (
              <span className={`text-xs ${verifyProbeMessage.startsWith('Probe succeeded') ? 'text-green-400' : 'text-red-400'}`}>
                {verifyProbeMessage}
              </span>
            )}
          </div>
        </Fieldset>

        <Fieldset
          title="Verification Policy"
          description="Controls proof-gating and escalation thresholds used by Scan and retest workflows."
        >
          <ToggleRow
            label="Proof required in Scan reports"
            description="When on, only findings with verification evidence are kept in the primary Scan output."
            hint="Can reduce visible findings and attack chains when proof collection fails."
            checked={proofRequiredForSmartInput}
            onChange={setProofRequiredForSmartInput}
          />
          <ToggleRow
            label="Auto-close high-confidence false positives"
            description="When on, a retest that concludes a high-confidence false positive flips the finding from active to false positive automatically (audited and reversible)."
            hint="Off by default: a wrong auto-FP hides a real vulnerability. Leave off to keep a human in the loop via the one-click 'mark false positive' control."
            checked={autoFpOnRetestInput}
            onChange={setAutoFpOnRetestInput}
          />
          {autoFpOnRetestInput && (
            <Field
              label="Auto-FP minimum confidence"
              hint="Retest confidence required before auto-closing (0–1). Higher than the 0.7 false-positive verdict bar because auto-closing is riskier than labeling."
            >
              <input
                type="number"
                min={0.7}
                max={1}
                step={0.05}
                value={autoFpMinConfidenceInput}
                onChange={(e) => setAutoFpMinConfidenceInput(e.target.value)}
                className={INPUT_CLASS}
              />
            </Field>
          )}
          <Field
            label="Verification Min Severity (scan-time + retest)"
            hint="Baseline minimum severity for verification workflows across scan-time checks and retests."
          >
            <select
              value={verificationMinSeverityInput}
              onChange={(e) => updateVerificationSeverity(e.target.value as Severity)}
              className={INPUT_CLASS}
            >
              {SEVERITY_OPTIONS.map((sev) => (
                <option key={sev} value={sev}>
                  {sev}
                </option>
              ))}
            </select>
          </Field>
          <Field
            label="AI Escalation Min Severity"
            hint="Minimum severity required before deterministic retest can escalate to AI."
          >
            <select
              value={aiEscalationMinSeverityInput}
              onChange={(e) => updateAIEscalationSeverity(e.target.value as Severity)}
              className={INPUT_CLASS}
            >
              {SEVERITY_OPTIONS.map((sev) => (
                <option key={sev} value={sev}>
                  {sev}
                </option>
              ))}
            </select>
          </Field>
          <div className="rounded border border-blue-500/20 bg-blue-500/10 p-3">
            <div className="text-xs font-medium text-blue-200">Effective policy preview</div>
            {thresholdContradiction && (
              <p role="alert" className="mt-1 text-xs text-red-300">
                AI escalation cannot include severities excluded by the verification baseline.
              </p>
            )}
            <div className="mt-2 grid gap-1">
              {SEVERITY_OPTIONS.map((severity) => {
                const verificationAllowed = SEVERITY_RANK[severity] >= SEVERITY_RANK[verificationMinSeverityInput]
                const aiAllowed = verificationAllowed && aiVerifyEnabledInput
                  && SEVERITY_RANK[severity] >= SEVERITY_RANK[aiEscalationMinSeverityInput]
                const autoQueued = verificationAllowed && autoRetestEnabledInput
                return (
                  <div key={severity} className="grid grid-cols-[5rem_1fr] gap-2 text-xs">
                    <span className="capitalize text-gray-300">{severity}</span>
                    <span className={verificationAllowed ? 'text-blue-100' : 'text-gray-500'}>
                      {verificationAllowed
                        ? `deterministic verification${autoQueued ? ' · auto-retest' : ''}${aiAllowed ? ' · AI escalation allowed' : ''}`
                        : 'excluded by verification baseline'}
                    </span>
                  </div>
                )
              })}
            </div>
            <p className="mt-2 text-[11px] text-blue-100/80">
              Precedence: verification baseline → optional automatic queue → deterministic proof → AI escalation threshold.
            </p>
          </div>
          <p className="text-xs text-yellow-400/90 bg-yellow-500/10 border border-yellow-500/20 rounded px-2 py-1.5">
            If proof-required is enabled, Scan reports can look quieter because unverified findings are filtered out of
            the primary report.
          </p>
        </Fieldset>

        <Fieldset
          title="Auto Retest Policy"
          description="Queues retests automatically after scan completion."
        >
          <ToggleRow
            label="Auto-queue retests after each scan"
            description="Creates retest jobs for eligible findings when a scan completes."
            hint="Useful for continuous validation with less manual work."
            checked={autoRetestEnabledInput}
            onChange={setAutoRetestEnabledInput}
          />
          <div className="rounded border border-gray-800 bg-gray-950/50 px-3 py-2 text-xs text-gray-400">
            Automatic queue threshold follows the canonical verification baseline:
            {' '}<span className="font-medium text-gray-200">{autoRetestMinSeverityInput}</span>.
          </div>
          <Field
            label="Auto Retest Max Findings Per Scan"
            hint="Hard cap on number of findings auto-queued for retest from one scan."
          >
            <input
              type="number"
              min={0}
              max={500}
              value={autoRetestMaxPerScanInput}
              onChange={(e) => setAutoRetestMaxPerScanInput(e.target.value)}
              className={INPUT_CLASS}
            />
          </Field>
        </Fieldset>
        </div>
      )}

      <div className="pt-2 border-t border-gray-800">
        <ToggleRow
          label="Keep settings after restart"
          description="When on, saved settings survive service and container restarts. When off, changes last only for the current runtime."
          hint="Leave off for temporary experiments."
          checked={persistAIToEnv}
          onChange={setPersistAIToEnv}
        />
      </div>

      {aiSettingsMessage && <p className="text-xs text-green-400">{aiSettingsMessage}</p>}
      {aiSettingsError && <p className="text-xs text-red-400">{aiSettingsError}</p>}
    </div>
  )
}

function Field({
  label,
  hint,
  children,
}: {
  label: string
  hint?: string
  children: React.ReactNode
}) {
  return (
    <label className="block">
      <span className="text-xs text-gray-400 inline-flex items-center gap-1">
        {label}
        {hint && <HelpHint text={hint} />}
      </span>
      {children}
    </label>
  )
}

function ToggleRow({
  label,
  description,
  hint,
  checked,
  onChange,
}: {
  label: string
  description: string
  hint?: string
  checked: boolean
  onChange: (checked: boolean) => void
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      onClick={() => onChange(!checked)}
      className="flex w-full items-start justify-between gap-3 rounded border border-gray-800 bg-gray-900/50 px-2.5 py-2 text-left transition-colors hover:border-gray-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 focus-visible:ring-offset-gray-950"
    >
      <span className="min-w-0 space-y-0.5">
        <span className="block text-xs text-gray-200">{label}</span>
        <span className="block text-[11px] text-gray-500">{description}</span>
        {hint && <span className="block text-[11px] text-gray-600">{hint}</span>}
      </span>
      <ToggleVisual checked={checked} />
    </button>
  )
}

function HelpHint({ text }: { text: string }) {
  return (
    <span
      className="inline-flex h-4 w-4 items-center justify-center rounded-full border border-gray-600 text-[10px] font-semibold text-gray-300 cursor-help"
      title={text}
      aria-label={text}
    >
      ?
    </span>
  )
}
