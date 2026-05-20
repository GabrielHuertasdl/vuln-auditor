import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { dashboardApi, postureApi } from '@/lib/api'
import { formatRelativeTime, formatDuration, postureScoreColor, getHostname } from '@/lib/utils'
import { StatCard } from '@/components/StatCard'
import { ScanStatusBadge } from '@/components/ScanStatusBadge'
import { PostureTrendChart } from '@/components/charts/PostureTrendChart'
import { SeverityBarChart } from '@/components/charts/SeverityBarChart'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/Table'
import { DashboardSkeleton } from '@/components/LoadingSkeleton'
import { EmptyState } from '@/components/EmptyState'
import { t } from '@/lib/i18n'

// Icons
const TargetIcon = () => (
  <svg className="h-5 w-5 text-blue-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <circle cx="12" cy="12" r="10" /><circle cx="12" cy="12" r="6" /><circle cx="12" cy="12" r="2" />
  </svg>
)
const ScanIcon = () => (
  <svg className="h-5 w-5 text-purple-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2" />
    <rect width="7" height="5" x="8.5" y="9.5" rx="1" />
  </svg>
)
const CritIcon = () => (
  <svg className="h-5 w-5 text-red-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
    <path d="M12 9v4M12 17h.01" />
  </svg>
)

export default function Dashboard() {
  const navigate = useNavigate()

  const { data: dashboard, isLoading: dashLoading } = useQuery({
    queryKey: ['dashboard'],
    queryFn: () => dashboardApi.get().then((r) => r.data),
    refetchInterval: 30_000,
  })

  const { data: postureTrend } = useQuery({
    queryKey: ['posture', 'trend'],
    queryFn: () => postureApi.trend({ limit: 30 }).then((r) => r.data),
  })

  if (dashLoading) return <DashboardSkeleton />

  if (!dashboard) {
    return <EmptyState title="Could not load dashboard" description="Please refresh the page." />
  }

  const sev = dashboard.open_findings_by_severity

  // Build chart data from recent scans
  const severityChartData = dashboard.recent_scans.slice(0, 10).map((s) => ({
    label: s.id.slice(0, 6),
    summary: s.severity_summary,
  }))

  return (
    <div className="space-y-6">
      {/* Org quota bar */}
      <div className="flex items-center justify-between rounded-xl border border-border bg-card px-5 py-3">
        <div>
          <span className="text-sm font-medium">{dashboard.org.name}</span>
          <span className="ml-2 rounded bg-primary/10 px-1.5 py-0.5 text-xs text-primary font-medium capitalize">
            {dashboard.org.plan}
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-muted-foreground">
            {dashboard.org.scans_this_month} / {dashboard.org.scan_quota} scans this month
          </span>
          <div className="w-24 h-1.5 rounded-full bg-muted overflow-hidden">
            <div
              className="h-full rounded-full bg-primary transition-all"
              style={{
                width: `${Math.min(100, (dashboard.org.scans_this_month / dashboard.org.scan_quota) * 100)}%`,
              }}
            />
          </div>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5">
        <StatCard
          title={t('dashboard.total_targets')}
          value={dashboard.total_targets}
          icon={<TargetIcon />}
        />
        <StatCard
          title={t('dashboard.total_scans')}
          value={dashboard.total_scans}
          icon={<ScanIcon />}
        />
        <StatCard
          title={t('dashboard.critical')}
          value={sev.critical}
          colorClass="text-red-500"
          icon={<CritIcon />}
        />
        <StatCard
          title={t('dashboard.high')}
          value={sev.high}
          colorClass="text-orange-500"
        />
        <StatCard
          title={t('dashboard.medium')}
          value={sev.medium}
          colorClass="text-yellow-500"
        />
      </div>

      {/* ASPM Coverage */}
      <Card>
        <CardHeader>
          <CardTitle>ASPM Coverage</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            {[
              { key: 'DAST', active: true, icon: '🌐', desc: 'Dynamic scanning with ZAP + Nmap', detail: 'Active' },
              { key: 'SAST', active: false, icon: '🔍', desc: 'Semgrep static analysis', detail: 'Run scan with SAST tool' },
              { key: 'SCA',  active: false, icon: '📦', desc: 'Trivy + npm audit', detail: 'Run scan with SCA tool' },
              { key: 'IaC',  active: false, icon: '⚙️', desc: 'Checkov Terraform/K8s', detail: 'Run scan with IaC tool' },
            ].map((pillar) => (
              <div key={pillar.key} className={`rounded-xl border p-4 transition-colors ${pillar.active ? 'border-green-500/30 bg-green-500/5' : 'border-border bg-card opacity-70'}`}>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-lg">{pillar.icon}</span>
                  <span className={`text-xs font-bold rounded-full px-2 py-0.5 ${pillar.active ? 'bg-green-500/20 text-green-400' : 'bg-muted text-muted-foreground'}`}>
                    {pillar.active ? '● Active' : '○ Inactive'}
                  </span>
                </div>
                <p className="font-semibold text-sm">{pillar.key}</p>
                <p className="text-xs text-muted-foreground mt-0.5">{pillar.desc}</p>
                {!pillar.active && <p className="text-xs text-primary mt-2 cursor-pointer hover:underline">{pillar.detail}</p>}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Charts row */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>{t('dashboard.posture_trend')}</CardTitle>
          </CardHeader>
          <CardContent>
            {postureTrend && postureTrend.length > 0 ? (
              <PostureTrendChart data={postureTrend} height={220} />
            ) : (
              <div className="flex h-[220px] items-center justify-center text-sm text-muted-foreground">
                No posture data yet. Run some scans first.
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>{t('dashboard.severity_breakdown')}</CardTitle>
          </CardHeader>
          <CardContent>
            {severityChartData.length > 0 ? (
              <SeverityBarChart data={severityChartData} height={220} />
            ) : (
              <div className="flex h-[220px] items-center justify-center text-sm text-muted-foreground">
                No scan data yet.
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Recent scans */}
      <Card>
        <CardHeader>
          <CardTitle>{t('dashboard.recent_scans')}</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {dashboard.recent_scans.length === 0 ? (
            <EmptyState
              title={t('scans.empty')}
              description={t('scans.empty_desc')}
              action={{ label: 'Go to Targets', onClick: () => navigate('/targets') }}
              className="py-12"
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Target</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Findings</TableHead>
                  <TableHead>New / Regressed</TableHead>
                  <TableHead>Duration</TableHead>
                  <TableHead>Started</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {dashboard.recent_scans.map((scan) => (
                  <TableRow
                    key={scan.id}
                    className="cursor-pointer"
                    onClick={() => navigate(`/scans/${scan.id}`)}
                  >
                    <TableCell>
                      <span className="text-sm font-medium font-mono">
                        {scan.target_url ? getHostname(scan.target_url) : scan.target_id.slice(0, 8)}
                      </span>
                    </TableCell>
                    <TableCell>
                      <ScanStatusBadge status={scan.status} />
                    </TableCell>
                    <TableCell>
                      <span className="font-medium">{scan.finding_count}</span>
                      {scan.severity_summary.critical > 0 && (
                        <span className="ml-2 text-xs text-red-500 font-semibold">
                          {scan.severity_summary.critical}C
                        </span>
                      )}
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-2 text-xs">
                        {scan.new_finding_count > 0 && (
                          <span className="text-green-500">+{scan.new_finding_count}</span>
                        )}
                        {scan.regressed_finding_count > 0 && (
                          <span className="text-orange-500">{scan.regressed_finding_count} regr.</span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs text-muted-foreground">
                        {formatDuration(scan.duration_seconds)}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs text-muted-foreground">
                        {formatRelativeTime(scan.started_at)}
                      </span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Top risky targets */}
      {dashboard.top_targets_by_risk.length > 0 && (
        <div>
          <h2 className="mb-3 text-base font-semibold">{t('dashboard.top_risky')}</h2>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {dashboard.top_targets_by_risk.map((target) => (
              <button
                key={target.id}
                onClick={() => navigate(`/targets/${target.id}`)}
                className="rounded-xl border border-border bg-card p-4 text-left hover:border-primary/50 transition-colors"
              >
                <p className="font-semibold text-sm truncate">{target.name}</p>
                <p className="text-xs text-muted-foreground font-mono mt-0.5 truncate">{target.url}</p>
                <div className="mt-3 flex items-center gap-4">
                  <div>
                    <p className="text-2xl font-bold text-foreground">{target.open_findings}</p>
                    <p className="text-xs text-muted-foreground">open findings</p>
                  </div>
                  {target.critical_high > 0 && (
                    <div>
                      <p className="text-2xl font-bold text-red-500">{target.critical_high}</p>
                      <p className="text-xs text-muted-foreground">crit/high</p>
                    </div>
                  )}
                </div>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
