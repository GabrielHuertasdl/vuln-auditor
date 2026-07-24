import React from 'react'
import { cn, type ScanStatus } from '@/lib/utils'

const scanStatusConfig: Record<ScanStatus, { label: string; className: string; dot?: string }> = {
  pending: {
    label: 'Pending',
    className: 'bg-slate-500/10 text-slate-400 border-slate-500/30',
    dot: 'bg-slate-400',
  },
  running: {
    label: 'Running',
    className: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
    dot: 'bg-blue-400 animate-pulse',
  },
  analyzing: {
    label: 'Analyzing',
    className: 'bg-violet-500/10 text-violet-400 border-violet-500/30',
    dot: 'bg-violet-400 animate-pulse',
  },
  done: {
    label: 'Done',
    className: 'bg-green-500/10 text-green-500 border-green-500/30',
    dot: 'bg-green-500',
  },
  failed: {
    label: 'Failed',
    className: 'bg-red-500/10 text-red-500 border-red-500/30',
    dot: 'bg-red-500',
  },
  partial: {
    label: 'Partial',
    className: 'bg-amber-500/10 text-amber-500 border-amber-500/30',
    dot: 'bg-amber-500',
  },
}

interface ScanStatusBadgeProps {
  status: ScanStatus
  className?: string
}

export function ScanStatusBadge({ status, className }: ScanStatusBadgeProps) {
  const config = scanStatusConfig[status]
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium',
        config.className,
        className,
      )}
    >
      {config.dot && <span className={cn('h-1.5 w-1.5 rounded-full', config.dot)} />}
      {config.label}
    </span>
  )
}
