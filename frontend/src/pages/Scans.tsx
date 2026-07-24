import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { scansApi, targetsApi } from '@/lib/api'
import { Card, CardContent } from '@/components/ui/Card'
import { Table, TableHeader, TableBody, TableHead, TableRow } from '@/components/ui/Table'
import { ScanRow } from '@/components/ScanRow'
import { EmptyState } from '@/components/EmptyState'
import { TableSkeleton } from '@/components/LoadingSkeleton'
import { t } from '@/lib/i18n'

export default function Scans() {
  const navigate = useNavigate()

  const { data: scans, isLoading } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.list().then((r) => r.data),
    refetchInterval: (query) => {
      const data = query.state.data
      if (!data) return 10_000
      const hasActive = data.some(
        (s) => s.status === 'running' || s.status === 'pending' || s.status === 'analyzing'
      )
      return hasActive ? 3_000 : 30_000
    },
  })

  const { data: targets } = useQuery({
    queryKey: ['targets'],
    queryFn: () => targetsApi.list().then((r) => r.data),
  })

  const targetMap = Object.fromEntries((targets ?? []).map((t) => [t.id, t]))

  if (isLoading) return <TableSkeleton />

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-xl font-semibold">{t('scans.title')}</h2>
        <p className="text-sm text-muted-foreground mt-0.5">
          {scans?.length ?? 0} scans total
        </p>
      </div>

      <Card>
        <CardContent className="p-0">
          {!scans || scans.length === 0 ? (
            <EmptyState
              title={t('scans.empty')}
              description={t('scans.empty_desc')}
              action={{ label: 'Go to Targets', onClick: () => navigate('/targets') }}
              className="py-16"
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('scans.id')}</TableHead>
                  <TableHead>{t('scans.target')}</TableHead>
                  <TableHead>{t('scans.status')}</TableHead>
                  <TableHead>{t('scans.tools')}</TableHead>
                  <TableHead>{t('scans.findings')}</TableHead>
                  <TableHead>New / Regr.</TableHead>
                  <TableHead>{t('scans.started')}</TableHead>
                  <TableHead>{t('scans.duration')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scans.map((scan) => (
                  <ScanRow
                    key={scan.id}
                    scan={scan}
                    targetName={targetMap[scan.target_id]?.name ?? scan.target_url}
                  />
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
