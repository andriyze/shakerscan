import {
  Bell, Bug, Calendar, CalendarClock, ChartBar, ClipboardCheck, Clock, FileText, Flag, Gauge, Globe,
  Inbox, KeyRound, Layers, Link as LinkIcon, ListChecks, Puzzle, RefreshCw, ShieldCheck, Tag, Ticket,
  Users, Wrench, type LucideIcon,
} from 'lucide-react'
import type { ExtensionIcon as ExtensionIconName } from '@/lib/uiExtensions.mjs'

// One drawing per name a deployment may ask for (ICON_NAMES in lib/uiExtensions.mjs). The type
// makes a name without a drawing a build error.
const ICONS: Record<ExtensionIconName, LucideIcon> = {
  bell: Bell,
  bug: Bug,
  calendar: Calendar,
  'calendar-clock': CalendarClock,
  chart: ChartBar,
  'clipboard-check': ClipboardCheck,
  clock: Clock,
  'file-text': FileText,
  flag: Flag,
  gauge: Gauge,
  globe: Globe,
  inbox: Inbox,
  key: KeyRound,
  layers: Layers,
  link: LinkIcon,
  'list-checks': ListChecks,
  puzzle: Puzzle,
  refresh: RefreshCw,
  'shield-check': ShieldCheck,
  tag: Tag,
  ticket: Ticket,
  users: Users,
  wrench: Wrench,
}

export function ExtensionIcon({ name, className = 'w-5 h-5' }: { name: ExtensionIconName; className?: string }) {
  const Icon = ICONS[name] ?? Puzzle
  return <Icon className={className} aria-hidden="true" />
}
