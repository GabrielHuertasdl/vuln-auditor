import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { scansApi, reportsApi, targetsApi } from '@/lib/api'
import { formatDate, formatDuration, shortId } from '@/lib/utils'
import { Card, CardContent } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '@/components/ui/Table'
import { ScanStatusBadge } from '@/components/ScanStatusBadge'
import { EmptyState } from '@/components/EmptyState'
import { TableSkeleton } from '@/components/LoadingSkeleton'
import { useToast } from '@/hooks/useToast'
import { t } from '@/lib/i18n'

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

export default function Reports() {
  const { toast } = useToast()

  const { data: scans, isLoading } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.list().then((r) => r.data),
  })

  const { data: targets } = useQuery({
    queryKey: ['targets'],
    queryFn: () => targetsApi.list().then((r) => r.data),
  })

  const targetMap = Object.fromEntries((targets ?? []).map((t) => [t.id, t]))

  const completedScans = (scans ?? []).filter((s) => s.status === 'done')

  const handleDownloadMd = async (scanId: string) => {
    try {
      const { data } = await reportsApi.markdown(scanId)
      const blob = new Blob([data], { type: 'text/markdown' })
      downloadBlob(blob, `report-${shortId(scanId)}.md`)
    } catch {
      toast('Failed to download report', 'error')
    }
  }

  const handleDownloadPdf = async (scanId: string) => {
    try {
      const { data } = await reportsApi.pdf(scanId)
      downloadBlob(data as Blob, `report-${shortId(scanId)}.pdf`)
    } catch {
      toast('Failed to download PDF', 'error')
    }
  }

  if (isLoading) return <TableSkeleton />

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-xl font-semibold">{t('reports.title')}</h2>
        <p className="text-sm text-muted-foreground mt-0.5">
          {completedScans.length} completed scan{completedScans.length !== 1 ? 's' : ''} available
        </p>
      </div>

      <Card>
        <CardContent className="p-0">
          {completedScans.length === 0 ? (
            <EmptyState
              title={t('reports.empty')}
              description={t('reports.empty_desc')}
              className="py-16"
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Scan ID</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Date</TableHead>
                  <TableHead>Duration</TableHead>
                  <TableHead>Findings</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Downloads</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {completedScans.map((scan) => (
                  <TableRow key={scan.id}>
                    <TableCell>
                      <span className="font-mono text-xs text-muted-foreground">
                        {shortId(scan.id)}
                      </span>
                    </TableCell>
                    <TableCell>
                      <div>
                        <p className="text-sm font-medium">
                          {targetMap[scan.target_id]?.name ?? '—'}
                        </p>
                        <p className="text-xs text-muted-foreground font-mono truncate max-w-[180px]">
                          {targetMap[scan.target_id]?.url ?? scan.target_url ?? '—'}
                        </p>
                      </div>
                    </TableCell>
                    <TableCell>
                      <span className="text-sm text-muted-foreground">
                        {formatDate(scan.completed_at)}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span className="text-sm text-muted-foreground">
                        {formatDuration(scan.duration_seconds)}
                      </span>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{scan.finding_count}</span>
                        {scan.severity_summary.critical > 0 && (
                          <span className="text-xs font-semibold text-red-500">
                            {scan.severity_summary.critical}C
                          </span>
                        )}
                        {scan.severity_summary.high > 0 && (
                          <span className="text-xs font-semibold text-orange-500">
                            {scan.severity_summary.high}H
                          </span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <ScanStatusBadge status={scan.status} />
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-1.5">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handleDownloadMd(scan.id)}
                        >
                          <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3" />
                          </svg>
                          MD
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handleDownloadPdf(scan.id)}
                        >
                          <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                            <polyline points="14,2 14,8 20,8" />
                          </svg>
                          PDF
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
