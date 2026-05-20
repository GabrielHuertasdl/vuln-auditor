import React from 'react'
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts'
import { type PostureTrendPoint } from '@/lib/api'
import { formatDate } from '@/lib/utils'

interface PostureTrendChartProps {
  data: PostureTrendPoint[]
  showDomains?: boolean
  height?: number
}

interface CustomTooltipProps {
  active?: boolean
  payload?: Array<{ name: string; value: number; color: string }>
  label?: string
}

function CustomTooltip({ active, payload, label }: CustomTooltipProps) {
  if (!active || !payload?.length) return null
  return (
    <div className="rounded-lg border border-border bg-card p-3 shadow-lg text-xs">
      <p className="font-semibold mb-2 text-foreground">{label}</p>
      {payload.map((entry) => (
        <div key={entry.name} className="flex items-center gap-2 mb-1">
          <span className="h-2 w-2 rounded-full" style={{ backgroundColor: entry.color }} />
          <span className="text-muted-foreground capitalize">{entry.name}:</span>
          <span className="font-medium text-foreground">{entry.value.toFixed(1)}</span>
        </div>
      ))}
    </div>
  )
}

export function PostureTrendChart({
  data,
  showDomains = false,
  height = 240,
}: PostureTrendChartProps) {
  const chartData = data.map((d) => ({
    ...d,
    date: formatDate(d.date),
    overall: Math.round(d.overall_score),
    coverage: Math.round(d.coverage_score),
    confidence: Math.round(d.confidence_score),
    exposure: Math.round(d.exposure_score),
  }))

  return (
    <ResponsiveContainer width="100%" height={height}>
      <LineChart data={chartData} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
        <XAxis
          dataKey="date"
          tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 11 }}
          tickLine={false}
          axisLine={false}
          interval="preserveStartEnd"
        />
        <YAxis
          domain={[0, 100]}
          tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 11 }}
          tickLine={false}
          axisLine={false}
        />
        <Tooltip content={<CustomTooltip />} />
        {showDomains && <Legend wrapperStyle={{ fontSize: 12 }} />}
        <Line
          type="monotone"
          dataKey="overall"
          name="Overall"
          stroke="#3b82f6"
          strokeWidth={2}
          dot={false}
          activeDot={{ r: 4, strokeWidth: 0 }}
        />
        {showDomains && (
          <>
            <Line
              type="monotone"
              dataKey="coverage"
              name="Coverage"
              stroke="#8b5cf6"
              strokeWidth={1.5}
              dot={false}
              strokeDasharray="4 2"
            />
            <Line
              type="monotone"
              dataKey="confidence"
              name="Confidence"
              stroke="#22c55e"
              strokeWidth={1.5}
              dot={false}
              strokeDasharray="4 2"
            />
            <Line
              type="monotone"
              dataKey="exposure"
              name="Exposure"
              stroke="#f97316"
              strokeWidth={1.5}
              dot={false}
              strokeDasharray="4 2"
            />
          </>
        )}
      </LineChart>
    </ResponsiveContainer>
  )
}
