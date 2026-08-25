type CountMap = Record<string, number>

type CoverageDimension = {
  coverage?: number
  tested?: number
  discovered?: number
  by_method?: CountMap
  by_location?: CountMap
}

type TemplateCoverage = {
  hit_rate?: number
  matched?: number
  run?: number
  run_approximate?: boolean
  by_category?: CountMap
}

export type ScanCoverage = {
  endpoints?: CoverageDimension
  parameters?: CoverageDimension
  nuclei_templates?: TemplateCoverage
  auth_states_tested?: string[]
  discovery_sources?: string[]
}

type Props = {
  coverage: ScanCoverage
}

const METHOD_CLASSES: Record<string, string> = {
  GET: 'bg-green-900/50 text-green-300',
  POST: 'bg-blue-900/50 text-blue-300',
  PUT: 'bg-yellow-900/50 text-yellow-300',
  DELETE: 'bg-red-900/50 text-red-300',
  PATCH: 'bg-purple-900/50 text-purple-300',
}

const LOCATION_CLASSES: Record<string, string> = {
  query: 'bg-blue-900/50 text-blue-300',
  body: 'bg-purple-900/50 text-purple-300',
  path: 'bg-green-900/50 text-green-300',
  header: 'bg-yellow-900/50 text-yellow-300',
}

function percentage(value: number | undefined): number {
  const normalized = Number(value || 0)
  return Number.isFinite(normalized) ? Math.max(0, Math.min(normalized * 100, 100)) : 0
}

function Progress({ value, className }: { value?: number; className: string }) {
  return (
    <div className="mb-2 h-2 w-full rounded-full bg-gray-700">
      <div className={`${className} h-2 rounded-full transition-all`} style={{ width: `${percentage(value)}%` }} />
    </div>
  )
}

function Breakdown({
  title,
  values,
  classes,
}: {
  title: string
  values?: CountMap
  classes: Record<string, string>
}) {
  if (!values || !Object.keys(values).length) return null
  return (
    <div className="rounded-lg bg-gray-900 p-4">
      <h3 className="mb-3 text-sm font-semibold text-gray-400">{title}</h3>
      <div className="flex flex-wrap gap-2">
        {Object.entries(values).map(([label, count]) => (
          <span
            key={label}
            className={`rounded px-2 py-1 font-mono text-xs ${classes[label] || 'bg-gray-700 text-gray-300'}`}
          >
            {label}: {count}
          </span>
        ))}
      </div>
    </div>
  )
}

export default function ScanCoverageSection({ coverage }: Props) {
  if (!coverage.endpoints && !coverage.parameters && !coverage.nuclei_templates) return null
  const templates = coverage.nuclei_templates
  const approximate = Boolean(templates?.run_approximate)
  const categories = Object.entries(templates?.by_category || {}).sort(([, left], [, right]) => right - left)

  return (
    <section className="mb-8 rounded-lg bg-gray-800/50 p-6 backdrop-blur-lg" aria-labelledby="scan-coverage-heading">
      <h2 id="scan-coverage-heading" className="mb-4 text-2xl font-bold">Scan Coverage</h2>

      <div className="mb-6 grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
        {coverage.endpoints && (
          <div className="rounded-lg bg-gray-900 p-4">
            <div className="mb-2 flex items-center justify-between">
              <h3 className="text-sm font-semibold text-gray-400">Endpoint Coverage</h3>
              <span className="text-lg font-bold text-white">{Math.round(percentage(coverage.endpoints.coverage))}%</span>
            </div>
            <Progress value={coverage.endpoints.coverage} className="bg-blue-500" />
            <p className="text-xs text-gray-500">
              {coverage.endpoints.tested || 0} tested / {coverage.endpoints.discovered || 0} discovered
            </p>
          </div>
        )}

        {coverage.parameters && (
          <div className="rounded-lg bg-gray-900 p-4">
            <div className="mb-2 flex items-center justify-between">
              <h3 className="text-sm font-semibold text-gray-400">Parameter Testing</h3>
              <span className="text-lg font-bold text-white">
                {(coverage.parameters.discovered || 0) > 0
                  ? `${Math.round(percentage(coverage.parameters.coverage))}%`
                  : '—'}
              </span>
            </div>
            <Progress value={coverage.parameters.coverage} className="bg-green-500" />
            <p className="text-xs text-gray-500">
              {(coverage.parameters.discovered || 0) > 0
                ? `${coverage.parameters.tested || 0} probe attempts across ${coverage.parameters.discovered} discovered parameters`
                : `${coverage.parameters.tested || 0} active parameter probes · no parameters inventoried`}
            </p>
          </div>
        )}

        {templates && (
          <div className="rounded-lg bg-gray-900 p-4">
            <div className="mb-2 flex items-center justify-between">
              <h3 className="text-sm font-semibold text-gray-400">Template Hit Rate</h3>
              <span className="text-lg font-bold text-white">{Math.round(percentage(templates.hit_rate))}%</span>
            </div>
            <Progress
              value={templates.hit_rate}
              className={(templates.hit_rate || 0) > 0.1 ? 'bg-red-500' : (templates.hit_rate || 0) > 0.05 ? 'bg-yellow-500' : 'bg-green-500'}
            />
            <p className="flex items-center gap-2 text-xs text-gray-500">
              <span>{templates.matched || 0} matched / {approximate ? '~' : ''}{templates.run || 0} run</span>
              {approximate && (
                <span className="rounded bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-amber-300">
                  estimated
                </span>
              )}
            </p>
          </div>
        )}
      </div>

      <div className="mb-6 grid grid-cols-1 gap-4 md:grid-cols-2">
        <Breakdown title="Endpoints by Method" values={coverage.endpoints?.by_method} classes={METHOD_CLASSES} />
        <Breakdown title="Parameters by Location" values={coverage.parameters?.by_location} classes={LOCATION_CLASSES} />
      </div>

      {categories.length > 0 && (
        <div className="mb-6">
          <h3 className="mb-3 text-sm font-semibold text-gray-400">Templates by Category</h3>
          <div className="flex flex-wrap gap-2">
            {categories.slice(0, 12).map(([category, count]) => (
              <span key={category} className="rounded bg-gray-900 px-2 py-1 text-xs text-gray-300">{category}: {count}</span>
            ))}
            {categories.length > 12 && <span className="px-2 py-1 text-xs text-gray-500">+{categories.length - 12} more</span>}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        {coverage.auth_states_tested && coverage.auth_states_tested.length > 0 && (
          <div className="rounded-lg bg-gray-900 p-4">
            <h3 className="mb-2 text-sm font-semibold text-gray-400">Auth States Tested</h3>
            <div className="flex flex-wrap gap-2">
              {coverage.auth_states_tested.map((state) => (
                <span key={state} className="rounded bg-yellow-900/30 px-2 py-1 text-xs text-yellow-400">{state}</span>
              ))}
            </div>
          </div>
        )}
        {coverage.discovery_sources && coverage.discovery_sources.length > 0 && (
          <div className="rounded-lg bg-gray-900 p-4">
            <h3 className="mb-2 text-sm font-semibold text-gray-400">Discovery Sources</h3>
            <div className="flex flex-wrap gap-2">
              {coverage.discovery_sources.map((source) => (
                <span key={source} className="rounded bg-blue-900/30 px-2 py-1 text-xs text-blue-400">{source}</span>
              ))}
            </div>
          </div>
        )}
      </div>
    </section>
  )
}
