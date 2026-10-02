'use client'

import { useEffect, useRef, useState } from 'react'
import { Search } from 'lucide-react'
import { Button, useToast } from '@/components/ui'
import { discoverSubdomains, getDiscoveryRun } from '@/lib/api'
import { discoveryOutcomeMessage } from '@/lib/targetDns'

export function TargetDomainDiscovery({ domain, onSettled }: {domain: string; onSettled: () => void}) {
  const toast = useToast()
  const [running, setRunning] = useState(false)
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const mounted = useRef(false)
  useEffect(() => {
    mounted.current = true
    return () => { mounted.current = false; if (timer.current) clearTimeout(timer.current) }
  }, [])

  async function discover() {
    if (running) return
    setRunning(true)
    const finish = () => { if (mounted.current) { setRunning(false); onSettled() } }
    const schedule = (poll: () => void) => {
      if (mounted.current) timer.current = setTimeout(poll, 3_000)
    }
    try {
      const started = await discoverSubdomains(domain)
      if (!mounted.current) return
      toast.success(`Subdomain discovery started for ${domain}`)
      if (!started.discovery_id) { schedule(finish); return }
      let polls = 0
      const poll = async () => {
        polls++
        try {
          const run = await getDiscoveryRun(started.discovery_id!)
          if (!mounted.current) return
          if (run.status === 'completed' || run.status === 'failed') {
            const outcome = discoveryOutcomeMessage(domain, run)
            toast[outcome.kind](outcome.message)
            finish()
            return
          }
        } catch { /* A transient status error does not imply the queued discovery failed. */ }
        if (polls >= 100) {
          if (mounted.current) toast.info(`Discovery for ${domain} is still pending; refresh later to see its results.`)
          finish()
        } else schedule(poll)
      }
      schedule(poll)
    } catch (error) {
      if (!mounted.current) return
      toast.error(error instanceof Error ? error.message : `Could not start discovery for ${domain}`)
      setRunning(false)
    }
  }

  return <Button size="sm" variant="secondary" loading={running} aria-label={`Discover subdomains of ${domain}`} onClick={() => void discover()}>
    <Search className="h-4 w-4" aria-hidden="true" />{running ? 'Discovering…' : 'Discover subdomains'}
  </Button>
}
