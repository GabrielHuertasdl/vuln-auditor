import React from 'react'
import { cn, type FindingStatus } from '@/lib/utils'

const statusConfig: Record<FindingStatus, { label: string; className: string }> = {
  open: { label: 'Open', className: 'bg-red-500/10 text-red-500 border-red-500/30' },
  acknowledged: {
    label: 'Acknowledged',
    className: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/30',
  },
  resolved: { label: 'Resolved', className: 'bg-green-500/10 text-green-500 border-green-500/30' },
  false_positive: {
    label: 'False Positive',
    className: 'bg-slate-500/10 text-slate-400 border-slate-500/30',
  },
  retest_needed: {
    label: 'Retest',
    className: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
  },
}

interface StatusBadgeProps {
  status: FindingStatus
  className?: string
}

export function StatusBadge({ status, className }: StatusBadgeProps) {
  const config = statusConfig[status]
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium',
        config.className,
        className,
      )}
    >
      {config.label}
    </span>
  )
}
