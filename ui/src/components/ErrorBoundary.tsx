'use client'

import { Component, type ReactNode } from 'react'

interface Props {
  children: ReactNode
  /** Named in the default fallback, e.g. "the hypotheses panel". */
  label?: string
  fallback?: ReactNode
}

/**
 * Isolates a render failure to its own subtree. If one panel throws (typically an
 * unexpected API shape reaching a `.map()`), the rest of the page keeps working
 * instead of blanking to the app-level error boundary.
 */
export class ErrorBoundary extends Component<Props, { hasError: boolean }> {
  state = { hasError: false }

  static getDerivedStateFromError() {
    return { hasError: true }
  }

  render() {
    if (this.state.hasError) {
      if (this.props.fallback !== undefined) return this.props.fallback
      return (
        <div className="rounded-lg border border-amber-500/20 bg-amber-500/[0.06] px-4 py-3 text-sm text-amber-200">
          Couldn’t load {this.props.label || 'this section'}. The rest of the page is unaffected.
        </div>
      )
    }
    return this.props.children
  }
}
