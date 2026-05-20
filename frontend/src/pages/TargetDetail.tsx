import React, { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { targetsApi, scansApi, postureApi } from '@/lib/api'
import { formatRelativeTime, formatDuration, postureScoreColor, shortId } from '@/lib/utils'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card'
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '@/components/ui/Table'
import { ScanStatusBadge } from '@/components/ScanStatusBadge'
import { SeverityBadge } from '@/components/SeverityBadge'
import { StatusBadge } from '@/components/StatusBadge'
import { PostureTrendChart } from '@/components/charts/PostureTrendChart'
import { DetailSkeleton } from '@/components/LoadingSkeleton'
import { EmptyState } from '@/components/EmptyState'
import { useToast } from '@/hooks/useToast'
import { t } from '@/lib/i18n'
import { type Severity, type FindingStatus } from '@/lib/utils'

const SEVERITY_OPTIONS = ['all', 'critical', 'high', 'medium', 'low', 'informational']

export default function TargetDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const { toast } = useToast()
  const [sevFilter, setSevFilter] = useState('all')
  const [isScanning, setIsScanning] = useState(false)

  const { data: target, isLoading } = useQuery({
    queryKey: ['targets', id],
    queryFn: () => targetsApi.get(id!).then((r) => r.data),
    enabled: !!id,
  })

  const { data: scans } = useQuery({
    queryKey: ['targets', id, 'scans'],
    queryFn: () => targetsApi.scans(id!).then((r) => r.data),
    enabled: !!id,
  })

  const { data: findings } = useQuery({
    queryKey: ['targets', id, 'findings'],
    queryFn: () => targetsApi.findings(id!).then((r) => r.data),
    enabled: !!id,
  })

  const { data: postureTrend } = useQuery({
    queryKey: ['posture', 'trend', id],
    queryFn: () => postureApi.trend({ target_id: id, limit: 20 }).then((r) => r.data),
    enabled: !!id,
  })

  const onScanNow = async () => {
    if (!target) return
    setIsScanning(true)
    try {
      await scansApi.start({
        target_url: target.url,
        tools: ['nmap', 'zap', 'nikto'],
        scan_mode: 'full',
      })
      toast(t('toast.scan_started'), 'success')
      void qc.invalidateQueries({ queryKey: ['scans'] })
      void qc.invalidateQueries({ queryKey: ['targets', id, 'scans'] })
    } catch {
      toast(t('toast.scan_failed'), 'error')
    } finally {
      setIsScanning(false)
    }
  }

  if (isLoading) return <DetailSkeleton />
  if (!target) return <EmptyState title="Target not found" description="This target may have been deleted." />

  const filteredFindings = findings?.filter(
    (f) => sevFilter === 'all' || f.severity === sevFilter,
  ) ?? []

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <button
              onClick={() => navigate('/targets')}
              className="text-sm text-muted-foreground hover:text-foreground"
            >
              Targets
            </button>
            <span className="text-muted-foreground">/</span>
            <span className="text-sm font-medium">{target.name}</span>
          </div>
          <h1 className="text-2xl font-bold">{target.name}</h1>
          <p className="text-sm text-muted-foreground font-mono mt-1">{target.url}</p>
          <div className="mt-2 flex flex-wrap gap-2">
            {target.tags.map((tag) => (
              <Badge key={tag} variant="secondary">{tag}</Badge>
            ))}
            {target.schedule && (
              <Badge variant="outline">{target.schedule}</Badge>
            )}
          </div>
        </div>
        <Button onClick={onScanNow} isLoading={isScanning} size="lg">
          <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="m5 3 14 9-14 9V3z" />
          </svg>
          {t('targets.scan_now')}
        </Button>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div className="rounded-xl border border-border bg-card p-4 text-center">
          <p className="text-2xl font-bold">{target.scan_count}</p>
          <p className="text-xs text-muted-foreground mt-1">Total Scans</p>
        </div>
        <div className="rounded-xl border border-border bg-card p-4 text-center">
          <p className="text-2xl font-bold text-red-500">{target.open_finding_count ?? 0}</p>
          <p className="text-xs text-muted-foreground mt-1">Open Findings</p>
        </div>
        <div className="rounded-xl border border-border bg-card p-4 text-center">
          <p className="text-sm font-semibold">{formatRelativeTime(target.last_scan_at)}</p>
          <p className="text-xs text-muted-foreground mt-1">Last Scan</p>
        </div>
        <div className="rounded-xl border border-border bg-card p-4 text-center">
          {postureTrend && postureTrend.length > 0 ? (
            <>
              <p className={`text-2xl font-bold ${postureScoreColor(postureTrend[postureTrend.length - 1].overall_score)}`}>
                {Math.round(postureTrend[postureTrend.length - 1].overall_score)}
              </p>
              <p className="text-xs text-muted-foreground mt-1">Posture Score</p>
            </>
          ) : (
            <p className="text-xs text-muted-foreground mt-4">No score yet</p>
          )}
        </div>
      </div>

      {/* Posture Trend */}
      {postureTrend && postureTrend.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Security Posture Trend</CardTitle>
          </CardHeader>
          <CardContent>
            <PostureTrendChart data={postureTrend} height={200} showDomains />
          </CardContent>
        </Card>
      )}

      {/* Scan History */}
      <Card>
        <CardHeader>
          <CardTitle>Scan History</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {!scans || scans.length === 0 ? (
            <EmptyState
              title={t('scans.empty')}
              description="No scans have been run for this target yet."
              className="py-10"
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Scan ID</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Findings</TableHead>
                  <TableHead>Duration</TableHead>
                  <TableHead>Started</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scans.map((scan) => (
                  <TableRow
                    key={scan.id}
                    className="cursor-pointer"
                    onClick={() => navigate(`/scans/${scan.id}`)}
                  >
                    <TableCell>
                      <span className="font-mono text-xs text-muted-foreground">{shortId(scan.id)}</span>
                    </TableCell>
                    <TableCell><ScanStatusBadge status={scan.status} /></TableCell>
                    <TableCell>
                      <span className="font-medium">{scan.finding_count}</span>
                      {scan.new_finding_count > 0 && (
                        <span className="ml-2 text-xs text-green-500">+{scan.new_finding_count} new</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <span className="text-xs text-muted-foreground">{formatDuration(scan.duration_seconds)}</span>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs text-muted-foreground">{formatRelativeTime(scan.started_at)}</span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Findings */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Open Findings</CardTitle>
            <div className="flex gap-1">
              {SEVERITY_OPTIONS.map((s) => (
                <button
                  key={s}
                  onClick={() => setSevFilter(s)}
                  className={`rounded px-2.5 py-1 text-xs font-medium capitalize transition-colors ${
                    sevFilter === s
                      ? 'bg-primary text-primary-foreground'
                      : 'bg-muted text-muted-foreground hover:text-foreground'
                  }`}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {filteredFindings.length === 0 ? (
            <EmptyState
              title={t('findings.empty')}
              description={t('findings.empty_desc')}
              className="py-10"
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('findings.severity')}</TableHead>
                  <TableHead>{t('findings.title_col')}</TableHead>
                  <TableHead>OWASP</TableHead>
                  <TableHead>{t('findings.status')}</TableHead>
                  <TableHead>{t('findings.first_seen')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredFindings.map((finding) => (
                  <TableRow key={finding.id}>
                    <TableCell>
                      <SeverityBadge severity={finding.severity as Severity} />
                    </TableCell>
                    <TableCell>
                      <p className="font-medium text-sm">{finding.title}</p>
                      {finding.description && (
                        <p className="text-xs text-muted-foreground mt-0.5 line-clamp-1">
                          {finding.description}
                        </p>
                      )}
                    </TableCell>
                    <TableCell>
                      <span className="text-xs text-muted-foreground">
                        {finding.owasp_category ?? '—'}
                      </span>
                    </TableCell>
                    <TableCell>
                      <StatusBadge status={finding.status as FindingStatus} />
                    </TableCell>
                    <TableCell>
                      <span className="text-xs text-muted-foreground">
                        {formatRelativeTime(finding.first_seen_at)}
                      </span>
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
