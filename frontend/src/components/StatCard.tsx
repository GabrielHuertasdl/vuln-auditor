import React from 'react'
import { cn } from '@/lib/utils'
import { Card } from './ui/Card'

interface StatCardProps {
  title: string
  value: string | number
  subtitle?: string
  icon?: React.ReactNode
  trend?: { value: number; label: string }
  colorClass?: string
  className?: string
}

export function StatCard({
  title,
  value,
  subtitle,
  icon,
  trend,
  colorClass,
  className,
}: StatCardProps) {
  return (
    <Card className={cn('relative overflow-hidden', className)}>
      <div className="p-6">
        <div className="flex items-start justify-between">
          <div className="space-y-1">
            <p className="text-sm font-medium text-muted-foreground">{title}</p>
            <p className={cn('text-3xl font-bold tracking-tight', colorClass)}>{value}</p>
            {subtitle && <p className="text-xs text-muted-foreground">{subtitle}</p>}
          </div>
          {icon && (
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-muted">
              {icon}
            </div>
          )}
        </div>
        {trend && (
          <div className="mt-4 flex items-center gap-1 text-xs">
            <span
              className={cn(
                'font-medium',
                trend.value >= 0 ? 'text-green-500' : 'text-red-500',
              )}
            >
              {trend.value >= 0 ? '+' : ''}
              {trend.value}%
            </span>
            <span className="text-muted-foreground">{trend.label}</span>
          </div>
        )}
      </div>
      {/* Decorative gradient */}
      {colorClass && (
        <div
          className="absolute inset-x-0 bottom-0 h-0.5 opacity-50"
          style={{ background: 'currentColor' }}
        />
      )}
    </Card>
  )
}
