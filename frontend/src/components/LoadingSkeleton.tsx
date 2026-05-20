import React from 'react'
import { Skeleton, SkeletonCard, SkeletonTable } from './ui/Skeleton'

export function DashboardSkeleton() {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
        {Array.from({ length: 5 }).map((_, i) => (
          <SkeletonCard key={i} />
        ))}
      </div>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="rounded-xl border border-border bg-card p-6">
          <Skeleton className="h-4 w-1/3 mb-4" />
          <Skeleton className="h-48 w-full" />
        </div>
        <div className="rounded-xl border border-border bg-card p-6">
          <Skeleton className="h-4 w-1/3 mb-4" />
          <Skeleton className="h-48 w-full" />
        </div>
      </div>
      <div className="rounded-xl border border-border bg-card p-6">
        <Skeleton className="h-4 w-1/4 mb-4" />
        <SkeletonTable rows={5} cols={6} />
      </div>
    </div>
  )
}

export function TableSkeleton({ rows = 8 }: { rows?: number }) {
  return (
    <div className="rounded-xl border border-border bg-card p-6">
      <SkeletonTable rows={rows} cols={5} />
    </div>
  )
}

export function DetailSkeleton() {
  return (
    <div className="space-y-6">
      <div className="rounded-xl border border-border bg-card p-6">
        <Skeleton className="h-6 w-1/3 mb-2" />
        <Skeleton className="h-4 w-1/2 mb-4" />
        <div className="flex gap-2">
          <Skeleton className="h-6 w-16 rounded-full" />
          <Skeleton className="h-6 w-16 rounded-full" />
        </div>
      </div>
      <div className="rounded-xl border border-border bg-card p-6">
        <Skeleton className="h-4 w-1/4 mb-4" />
        <Skeleton className="h-48 w-full" />
      </div>
      <div className="rounded-xl border border-border bg-card p-6">
        <Skeleton className="h-4 w-1/4 mb-4" />
        <SkeletonTable rows={5} cols={6} />
      </div>
    </div>
  )
}
