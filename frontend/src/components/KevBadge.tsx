import React from 'react'

interface Props {
  inKev: boolean
  epssScore?: number | null
  size?: 'sm' | 'default'
}

export function KevBadge({ inKev, epssScore, size = 'default' }: Props) {
  const small = size === 'sm'
  return (
    <div className={`flex items-center gap-1 ${small ? 'text-xs' : 'text-sm'}`}>
      {inKev && (
        <span className="inline-flex items-center gap-1 rounded border border-red-500/50 bg-red-500/10 px-1.5 py-0.5 text-xs font-bold text-red-400">
          <svg className="h-3 w-3 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
            <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
            <path d="M12 9v4M12 17h.01"/>
          </svg>
          KEV
        </span>
      )}
      {epssScore != null && (
        <span
          className={`inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-medium ${
            epssScore >= 0.5
              ? 'border-red-500/40 bg-red-500/10 text-red-400'
              : epssScore >= 0.1
              ? 'border-orange-500/40 bg-orange-500/10 text-orange-400'
              : 'border-border bg-muted text-muted-foreground'
          }`}
          title="EPSS: probability of exploitation in next 30 days"
        >
          EPSS {(epssScore * 100).toFixed(1)}%
        </span>
      )}
    </div>
  )
}
