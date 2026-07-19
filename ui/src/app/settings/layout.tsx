// Shared container for the whole /settings/* cluster: one centered width so the
// sub-pages stop each picking a different max-w (they previously ranged over
// max-w-4xl/5xl/6xl/7xl and full-bleed). Adds no padding of its own — the root
// layout's <main> already supplies it — which also removes the double-padding
// the research-agent pages had from wrapping in their own px-4 py-6.
export default function SettingsLayout({ children }: { children: React.ReactNode }) {
  return <div className="mx-auto w-full max-w-6xl">{children}</div>
}
