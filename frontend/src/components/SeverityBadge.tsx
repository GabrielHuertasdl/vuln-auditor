import React from 'react'
import { cn, type Severity, severityColors } from '@/lib/utils'

interface SeverityBadgeProps {
  severity: Severity
  className?: string
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide',
        severityColors[severity],
        className,
      )}
    >
      {severity}
    </span>
  )
}
