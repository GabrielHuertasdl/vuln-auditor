import React from 'react'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts'
import { type SeveritySummary } from '@/lib/api'
import { severityChartColors } from '@/lib/utils'

interface SeverityBarChartProps {
  data: Array<{ label: string; summary: SeveritySummary }>
  height?: number
}

interface CustomTooltipProps {
  active?: boolean
  payload?: Array<{ name: string; value: number; fill: string }>
  label?: string
}

function CustomTooltip({ active, payload, label }: CustomTooltipProps) {
  if (!active || !payload?.length) return null
  const total = payload.reduce((sum, p) => sum + p.value, 0)
  return (
    <div className="rounded-lg border border-border bg-card p-3 shadow-lg text-xs">
      <p className="font-semibold mb-2 text-foreground">{label}</p>
      <p className="text-muted-foreground mb-2">Total: {total}</p>
      {payload.map((entry) => (
        <div key={entry.name} className="flex items-center gap-2 mb-1">
          <span className="h-2 w-2 rounded-full" style={{ backgroundColor: entry.fill }} />
          <span className="text-muted-foreground capitalize">{entry.name}:</span>
          <span className="font-medium text-foreground">{entry.value}</span>
        </div>
      ))}
    </div>
  )
}

export function SeverityBarChart({ data, height = 240 }: SeverityBarChartProps) {
  const chartData = data.map((d) => ({
    name: d.label,
    critical: d.summary.critical,
    high: d.summary.high,
    medium: d.summary.medium,
    low: d.summary.low,
    informational: d.summary.informational,
  }))

  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={chartData} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
        <XAxis
          dataKey="name"
          tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 11 }}
          tickLine={false}
          axisLine={false}
        />
        <YAxis
          tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 11 }}
          tickLine={false}
          axisLine={false}
        />
        <Tooltip content={<CustomTooltip />} />
        <Legend wrapperStyle={{ fontSize: 12 }} />
        <Bar dataKey="critical" name="Critical" stackId="a" fill={severityChartColors.critical} radius={[0, 0, 0, 0]} />
        <Bar dataKey="high" name="High" stackId="a" fill={severityChartColors.high} />
        <Bar dataKey="medium" name="Medium" stackId="a" fill={severityChartColors.medium} />
        <Bar dataKey="low" name="Low" stackId="a" fill={severityChartColors.low} />
        <Bar dataKey="informational" name="Info" stackId="a" fill={severityChartColors.informational} radius={[4, 4, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  )
}
