import React from 'react'

interface Props {
  dast?: boolean
  sast?: boolean
  sca?: boolean
  iac?: boolean
  tools?: string[]
  compact?: boolean
}

export function AspmCoverage({ dast = false, sast = false, sca = false, iac = false, tools = [], compact = false }: Props) {
  const pillars = [
    { key: 'DAST', active: dast, desc: 'Dynamic App Security Testing' },
    { key: 'SAST', active: sast, desc: 'Static App Security Testing' },
    { key: 'SCA',  active: sca,  desc: 'Software Composition Analysis' },
    { key: 'IaC',  active: iac,  desc: 'Infrastructure as Code' },
  ]

  return (
    <div className={`flex ${compact ? 'gap-1.5' : 'gap-2'} flex-wrap`}>
      {pillars.map((p) => (
        <div
          key={p.key}
          title={p.desc}
          className={`flex items-center gap-1 rounded-full border px-2 py-0.5 ${compact ? 'text-xs' : 'text-xs font-medium'} ${
            p.active
              ? 'border-green-500/40 bg-green-500/10 text-green-400'
              : 'border-border bg-muted text-muted-foreground opacity-50'
          }`}
        >
          <span className={`h-1.5 w-1.5 rounded-full ${p.active ? 'bg-green-400' : 'bg-muted-foreground'}`} />
          {p.key}
        </div>
      ))}
    </div>
  )
}
