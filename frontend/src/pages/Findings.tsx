import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { findingsApi, targetsApi } from '@/lib/api'
import { useDebounce } from '@/hooks/useDebounce'
import { Card, CardContent } from '@/components/ui/Card'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Button } from '@/components/ui/Button'
import { Table, TableHeader, TableBody, TableHead, TableRow } from '@/components/ui/Table'
import { FindingRow } from '@/components/FindingRow'
import { EmptyState } from '@/components/EmptyState'
import { TableSkeleton } from '@/components/LoadingSkeleton'
import { t } from '@/lib/i18n'

const SEVERITY_OPTIONS = [
  { value: '', label: 'All Severities' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'informational', label: 'Informational' },
]

const STATUS_OPTIONS = [
  { value: '', label: 'All Statuses' },
  { value: 'open', label: 'Open' },
  { value: 'acknowledged', label: 'Acknowledged' },
  { value: 'resolved', label: 'Resolved' },
  { value: 'false_positive', label: 'False Positive' },
  { value: 'retest_needed', label: 'Retest Needed' },
]

const PAGE_SIZE = 50

export default function Findings() {
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('')
  const [status, setStatus] = useState('')
  const [targetId, setTargetId] = useState('')
  const [offset, setOffset] = useState(0)

  const debouncedSearch = useDebounce(search, 300)

  const { data: targets } = useQuery({
    queryKey: ['targets'],
    queryFn: () => targetsApi.list().then((r) => r.data),
  })

  const targetOptions = [
    { value: '', label: 'All Targets' },
    ...(targets ?? []).map((t) => ({ value: t.id, label: t.name })),
  ]

  const { data: findings, isLoading } = useQuery({
    queryKey: ['findings', { severity, status, targetId, offset }],
    queryFn: () =>
      findingsApi
        .list({
          severity: severity || undefined,
          status: status || undefined,
          target_id: targetId || undefined,
          limit: PAGE_SIZE,
          offset,
        })
        .then((r) => r.data),
  })

  const targetMap = Object.fromEntries((targets ?? []).map((t) => [t.id, t]))

  // Client-side search filter
  const filtered = findings?.filter((f) =>
    debouncedSearch
      ? f.title.toLowerCase().includes(debouncedSearch.toLowerCase())
      : true,
  ) ?? []

  const resetFilters = () => {
    setSearch('')
    setSeverity('')
    setStatus('')
    setTargetId('')
    setOffset(0)
  }

  const hasFilters = search || severity || status || targetId

  if (isLoading) return <TableSkeleton rows={10} />

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-xl font-semibold">{t('findings.title')}</h2>
        <p className="text-sm text-muted-foreground mt-0.5">
          {findings?.length ?? 0} finding{findings?.length !== 1 ? 's' : ''}
          {hasFilters ? ' (filtered)' : ''}
        </p>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div className="flex-1 min-w-[200px]">
          <Input
            placeholder={t('findings.search')}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div className="w-40">
          <Select
            options={SEVERITY_OPTIONS}
            value={severity}
            onChange={(e) => { setSeverity(e.target.value); setOffset(0) }}
          />
        </div>
        <div className="w-44">
          <Select
            options={STATUS_OPTIONS}
            value={status}
            onChange={(e) => { setStatus(e.target.value); setOffset(0) }}
          />
        </div>
        <div className="w-44">
          <Select
            options={targetOptions}
            value={targetId}
            onChange={(e) => { setTargetId(e.target.value); setOffset(0) }}
          />
        </div>
        {hasFilters && (
          <Button variant="ghost" onClick={resetFilters} size="sm" className="self-end mb-0.5">
            Clear filters
          </Button>
        )}
      </div>

      <Card>
        <CardContent className="p-0">
          {filtered.length === 0 ? (
            <EmptyState
              title={t('findings.empty')}
              description={hasFilters ? t('findings.empty_desc') : 'No findings have been discovered yet.'}
              action={hasFilters ? { label: 'Clear filters', onClick: resetFilters } : undefined}
              className="py-16"
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('findings.severity')}</TableHead>
                  <TableHead>Risk</TableHead>
                  <TableHead>{t('findings.title_col')}</TableHead>
                  <TableHead>{t('findings.target')}</TableHead>
                  <TableHead>{t('findings.host')}</TableHead>
                  <TableHead>{t('findings.status')}</TableHead>
                  <TableHead>{t('findings.first_seen')}</TableHead>
                  <TableHead>{t('findings.last_seen')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map((finding) => (
                  <FindingRow
                    key={finding.id}
                    finding={finding}
                    showTarget
                    targetName={targetMap[finding.target_id]?.name}
                  />
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Pagination */}
      {(findings?.length ?? 0) >= PAGE_SIZE && (
        <div className="flex items-center justify-between">
          <p className="text-sm text-muted-foreground">
            Showing {offset + 1}–{offset + (filtered.length)} results
          </p>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={offset === 0}
              onClick={() => setOffset((o) => Math.max(0, o - PAGE_SIZE))}
            >
              Previous
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={(findings?.length ?? 0) < PAGE_SIZE}
              onClick={() => setOffset((o) => o + PAGE_SIZE)}
            >
              Next
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
