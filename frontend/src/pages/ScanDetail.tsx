import React, { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { scansApi, reportsApi, reachabilityApi, remediationApi, type Finding, type ReachabilityResult, type RemediationTemplate } from '@/lib/api'
import { useScanWebSocket } from '@/hooks/useScanWebSocket'
import { AspmCoverage } from '@/components/AspmCoverage'
import {
  formatRelativeTime,
  formatDuration,
  postureScoreColor,
  shortId,
  type Severity,
  type FindingStatus,
} from '@/lib/utils'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '@/components/ui/Table'
import { ScanStatusBadge } from '@/components/ScanStatusBadge'
import { SeverityBadge } from '@/components/SeverityBadge'
import { StatusBadge } from '@/components/StatusBadge'
import { DetailSkeleton } from '@/components/LoadingSkeleton'
import { EmptyState } from '@/components/EmptyState'
import { useToast } from '@/hooks/useToast'

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

const EXPOSURE_COLORS: Record<string, string> = {
  public: 'bg-red-500/10 text-red-400 border-red-500/30',
  api: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
  authenticated: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
  admin: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
  unknown: 'bg-muted text-muted-foreground border-border',
}

function RemediationPanel({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  const [activeStack, setActiveStack] = useState<string | null>(null)
  const { data: templates, isLoading } = useQuery({
    queryKey: ['remediation', finding.id],
    queryFn: () => remediationApi.forFinding(finding.id).then((r) => r.data),
  })

  const allStacks = templates
    ? [...new Set(templates.flatMap((t) => t.snippets.map((s) => s.stack)))]
    : []

  const filtered = templates?.map((t) => ({
    ...t,
    snippets: activeStack ? t.snippets.filter((s) => s.stack === activeStack) : t.snippets,
  })).filter((t) => t.snippets.length > 0)

  return (
    <div className="fixed inset-y-0 right-0 z-50 flex w-full max-w-xl flex-col border-l border-border bg-background shadow-2xl">
      <div className="flex items-center justify-between border-b border-border px-5 py-4">
        <div>
          <p className="text-xs text-muted-foreground uppercase tracking-wider">Remediation</p>
          <h3 className="font-semibold text-sm mt-0.5 line-clamp-2">{finding.title}</h3>
        </div>
        <button onClick={onClose} className="rounded-md p-1.5 hover:bg-muted text-muted-foreground">
          <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M18 6 6 18M6 6l12 12"/>
          </svg>
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-5 space-y-4">
        {isLoading ? (
          <div className="space-y-3">
            {[1,2,3].map(i => <div key={i} className="h-20 rounded-lg bg-muted animate-shimmer" />)}
          </div>
        ) : !filtered?.length ? (
          <p className="text-sm text-muted-foreground">No remediation templates available for this finding.</p>
        ) : (
          <>
            {allStacks.length > 1 && (
              <div className="flex flex-wrap gap-1.5">
                <button
                  onClick={() => setActiveStack(null)}
                  className={`rounded px-2 py-1 text-xs font-medium border transition-colors ${!activeStack ? 'border-primary bg-primary/10 text-primary' : 'border-border hover:border-primary/40'}`}
                >
                  All stacks
                </button>
                {allStacks.map((s) => (
                  <button
                    key={s}
                    onClick={() => setActiveStack(s === activeStack ? null : s)}
                    className={`rounded px-2 py-1 text-xs font-medium border transition-colors capitalize ${activeStack === s ? 'border-primary bg-primary/10 text-primary' : 'border-border hover:border-primary/40'}`}
                  >
                    {s}
                  </button>
                ))}
              </div>
            )}

            {filtered.map((template) => (
              <div key={template.id} className="rounded-lg border border-border overflow-hidden">
                <div className="bg-muted/30 px-4 py-3">
                  <div className="flex items-center justify-between">
                    <p className="text-sm font-semibold">{template.title}</p>
                    <span className="text-xs text-muted-foreground border border-border rounded px-1.5 py-0.5">{template.effort}</span>
                  </div>
                  <p className="text-xs text-muted-foreground mt-1">{template.description}</p>
                </div>
                {template.snippets.map((s) => (
                  <div key={s.stack} className="border-t border-border">
                    <div className="flex items-center justify-between bg-zinc-900/50 px-3 py-1.5">
                      <span className="text-xs font-medium text-zinc-400">{s.label}</span>
                      <button
                        className="text-xs text-zinc-500 hover:text-zinc-300"
                        onClick={() => navigator.clipboard.writeText(s.code)}
                      >
                        Copy
                      </button>
                    </div>
                    <pre className="overflow-x-auto bg-zinc-950 px-4 py-3 text-xs text-green-400 font-mono leading-relaxed">
                      {s.code}
                    </pre>
                  </div>
                ))}
              </div>
            ))}
          </>
        )}
      </div>
    </div>
  )
}

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { toast } = useToast()
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)

  const [urlArchOpen, setUrlArchOpen] = useState(false)
  const [surfaceOpen, setSurfaceOpen] = useState(false)
  const [hooksOpen, setHooksOpen] = useState(false)
  const [resistanceOpen, setResistanceOpen] = useState(false)

  const queryClient = useQueryClient()

  const { data: scan, isLoading, isError, error } = useQuery({
    queryKey: ['scan', id],
    queryFn: () => scansApi.get(id!).then((r) => r.data),
    enabled: !!id,
    // Polling fallback: only when WS isn't delivering updates (terminal statuses stop polling)
    refetchInterval: (query) => {
      const status = query.state.data?.status
      return status === 'running' || status === 'pending' || status === 'analyzing' ? 5000 : false
    },
  })

  const isActive = scan?.status === 'running' || scan?.status === 'pending' || scan?.status === 'analyzing'
  const { progress: wsProgress, connected: wsConnected } = useScanWebSocket(id, !!isActive)

  // When WS delivers a terminal status, trigger a one-time refetch to pull the full scan result
  useEffect(() => {
    if (wsProgress?.status && ['done', 'failed', 'partial'].includes(wsProgress.status)) {
      queryClient.invalidateQueries({ queryKey: ['scan', id] })
    }
  }, [wsProgress?.status, id, queryClient])

  const { data: diff } = useQuery({
    queryKey: ['scan', id, 'diff'],
    queryFn: () => scansApi.diff(id!).then((r) => r.data),
    enabled: !!id && scan?.status === 'done',
  })

  const downloadMd = async () => {
    try {
      const { data } = await reportsApi.markdown(id!)
      const blob = new Blob([data], { type: 'text/markdown' })
      downloadBlob(blob, `report-${shortId(id!)}.md`)
    } catch {
      toast('Failed to download report', 'error')
    }
  }

  const downloadPdf = async () => {
    try {
      const { data } = await reportsApi.pdf(id!)
      downloadBlob(data as Blob, `report-${shortId(id!)}.pdf`)
    } catch {
      toast('Failed to download PDF', 'error')
    }
  }

  if (isLoading) return <DetailSkeleton />
  if (isError) return (
    <EmptyState
      title="Failed to load scan"
      description={(error as Error)?.message ?? 'An unexpected error occurred.'}
      action={{ label: 'Go back', onClick: () => navigate('/scans') }}
    />
  )
  if (!scan) return <EmptyState title="Scan not found" description="This scan may have been deleted." />

  const posture = scan.posture_score
  const findings = scan.findings ?? []
  const tools = scan.tools ?? []

  const dast = tools.some((t) => t === 'nmap' || t === 'zap')
  const sast = tools.includes('semgrep')
  const sca = tools.includes('trivy')
  const iac = tools.includes('checkov')

  return (
    <div className="space-y-6">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <button onClick={() => navigate('/scans')} className="hover:text-foreground">Scans</button>
        <span>/</span>
        <span className="font-mono text-foreground">{shortId(scan.id)}</span>
      </div>

      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <h1 className="text-2xl font-bold font-mono">{shortId(scan.id)}</h1>
            <ScanStatusBadge status={scan.status} />
            {scan.ai_generated && (
              <Badge variant="purple">
                <svg className="h-3 w-3" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M12 2a7 7 0 0 1 7 7c0 2.38-1.19 4.47-3 5.74V17a1 1 0 0 1-1 1H9a1 1 0 0 1-1-1v-2.26C6.19 13.47 5 11.38 5 9a7 7 0 0 1 7-7zm1 18H11v1h2v-1zm-3 0v-1h4v1H10z"/>
                </svg>
                AI Triage
              </Badge>
            )}
          </div>
          <div className="flex flex-wrap gap-3 text-sm text-muted-foreground">
            <span>Mode: <span className="text-foreground font-medium capitalize">{scan.scan_mode}</span></span>
            <span>Duration: <span className="text-foreground font-medium">{formatDuration(scan.duration_seconds)}</span></span>
            <span>Started: <span className="text-foreground font-medium">{formatRelativeTime(scan.started_at)}</span></span>
          </div>
          {(scan.tools ?? []).length > 0 && (
            <div className="mt-2 flex gap-1.5 flex-wrap">
              {(scan.tools ?? []).map((tool) => (
                <span key={tool} className="rounded bg-muted px-2 py-0.5 text-xs font-mono text-muted-foreground">
                  {tool}
                </span>
              ))}
            </div>
          )}
        </div>

        {/* Download buttons */}
        {scan.status === 'done' && (
          <div className="flex gap-2 shrink-0">
            <Button variant="outline" size="sm" onClick={downloadMd}>
              <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3" />
              </svg>
              Download MD
            </Button>
            <Button variant="outline" size="sm" onClick={downloadPdf}>
              <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                <polyline points="14,2 14,8 20,8" />
              </svg>
              Download PDF
            </Button>
          </div>
        )}
      </div>

      {/* ASPM Coverage */}
      <div className="flex items-center gap-3">
        <span className="text-xs text-muted-foreground font-medium">Coverage:</span>
        <AspmCoverage dast={dast} sast={sast} sca={sca} iac={iac} tools={tools} />
      </div>

      {/* Progress bar — shown while scan is active */}
      {(scan.status === 'running' || scan.status === 'pending' || scan.status === 'analyzing') && (
        <Card>
          <CardContent className="py-4">
            {(() => {
              const pct = wsConnected && wsProgress ? wsProgress.progress_pct : (scan.progress_pct ?? 0)
              const msg = wsConnected && wsProgress ? wsProgress.progress_message : null
              const label = scan.status === 'analyzing' ? 'AI Analysis in Progress' : 'Scan in Progress'
              return (
                <>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-foreground">
                      {msg ?? label}
                      {wsConnected && (
                        <span className="ml-2 inline-block h-1.5 w-1.5 rounded-full bg-green-500 align-middle" title="Live" />
                      )}
                    </span>
                    <span className="text-sm font-mono text-muted-foreground">{pct}%</span>
                  </div>
                  <div className="h-2 rounded-full bg-muted overflow-hidden">
                    <div
                      className="h-full rounded-full bg-primary transition-all duration-500"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </>
              )
            })()}
          </CardContent>
        </Card>
      )}

      {/* Partial status banner */}
      {scan.status === 'partial' && (
        <Card className="border-amber-500/30 bg-amber-500/5">
          <CardContent className="py-3">
            <p className="text-sm text-amber-400">
              Scan completed with partial results — some tools did not finish. Findings reflect data from tools that succeeded.
            </p>
          </CardContent>
        </Card>
      )}

      {/* Tools failed banner */}
      {scan.tools_failed && Object.keys(scan.tools_failed).length > 0 && (
        <Card className="border-amber-500/30 bg-amber-500/5">
          <CardHeader><CardTitle className="text-amber-500 text-sm">Tools with Errors</CardTitle></CardHeader>
          <CardContent>
            <ul className="space-y-1">
              {Object.entries(scan.tools_failed).map(([tool, reason]) => (
                <li key={tool} className="flex gap-2 text-xs">
                  <span className="font-mono font-semibold text-amber-400">{tool}:</span>
                  <span className="text-muted-foreground">{reason}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}

      {/* Posture + Diff row */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        {/* Posture score */}
        {posture !== undefined && (
          <Card>
            <CardHeader><CardTitle>Posture Score</CardTitle></CardHeader>
            <CardContent>
              <div className="flex items-center gap-6">
                <div className="text-center">
                  <p className={`text-5xl font-bold ${postureScoreColor(posture)}`}>
                    {Math.round(posture)}
                  </p>
                  <p className="text-xs text-muted-foreground mt-1">Overall</p>
                </div>
                <div className="grid grid-cols-3 gap-3 flex-1">
                  {[
                    { label: 'Coverage', value: scan.coverage_score },
                    { label: 'Confidence', value: scan.confidence_score },
                    { label: 'Exposure', value: scan.exposure_score },
                  ].map(({ label, value }) => (
                    value !== undefined && (
                      <div key={label} className="text-center">
                        <p className={`text-xl font-bold ${postureScoreColor(value)}`}>
                          {Math.round(value)}
                        </p>
                        <p className="text-xs text-muted-foreground">{label}</p>
                      </div>
                    )
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Diff summary */}
        {diff && (
          <Card>
            <CardHeader><CardTitle>Diff vs Previous Scan</CardTitle></CardHeader>
            <CardContent>
              <div className="flex gap-4">
                <div className="flex-1 rounded-lg bg-green-500/10 p-3 text-center">
                  <p className="text-2xl font-bold text-green-500">{diff.new_findings.length}</p>
                  <p className="text-xs text-muted-foreground">New</p>
                </div>
                <div className="flex-1 rounded-lg bg-blue-500/10 p-3 text-center">
                  <p className="text-2xl font-bold text-blue-400">{diff.resolved_findings.length}</p>
                  <p className="text-xs text-muted-foreground">Resolved</p>
                </div>
                <div className="flex-1 rounded-lg bg-orange-500/10 p-3 text-center">
                  <p className="text-2xl font-bold text-orange-500">{diff.regressed_findings.length}</p>
                  <p className="text-xs text-muted-foreground">Regressed</p>
                </div>
                <div className="flex-1 rounded-lg bg-muted p-3 text-center">
                  <p className="text-2xl font-bold text-muted-foreground">{diff.unchanged_count}</p>
                  <p className="text-xs text-muted-foreground">Unchanged</p>
                </div>
              </div>
            </CardContent>
          </Card>
        )}
      </div>

      {/* Findings table */}
      <Card>
        <CardHeader>
          <CardTitle>
            Findings <span className="ml-2 text-base font-normal text-muted-foreground">({findings.length})</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {findings.length === 0 ? (
            <EmptyState title="No findings" description="No issues were found in this scan." className="py-12" />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Severity</TableHead>
                  <TableHead>Title</TableHead>
                  <TableHead>Host</TableHead>
                  <TableHead>OWASP</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Fix</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {findings.map((finding) => (
                  <TableRow
                    key={finding.id}
                    className="cursor-pointer hover:bg-muted/40"
                    onClick={() => setSelectedFinding(finding)}
                  >
                    <TableCell>
                      <SeverityBadge severity={finding.severity as Severity} />
                    </TableCell>
                    <TableCell className="max-w-[260px]">
                      <p className="font-medium text-sm line-clamp-2">{finding.title}</p>
                      {finding.cwe_ids.length > 0 && (
                        <p className="text-xs text-muted-foreground mt-0.5">
                          CWE-{finding.cwe_ids.join(', CWE-')}
                        </p>
                      )}
                    </TableCell>
                    <TableCell>
                      <span className="text-xs font-mono text-muted-foreground">
                        {finding.host ?? '—'}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs text-muted-foreground">{finding.owasp_category ?? '—'}</span>
                    </TableCell>
                    <TableCell>
                      <StatusBadge status={finding.status as FindingStatus} />
                    </TableCell>
                    <TableCell>
                      <span className="text-xs text-blue-400 underline">Fix →</span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* URL Architecture */}
      {scan.url_architecture && (
        <Card>
          <CardHeader className="cursor-pointer" onClick={() => setUrlArchOpen(!urlArchOpen)}>
            <div className="flex items-center justify-between">
              <CardTitle>
                URL Architecture
                <span className="ml-2 text-sm font-normal text-muted-foreground">
                  ({scan.url_architecture.crawled_urls.length} URLs)
                </span>
              </CardTitle>
              <span className="text-muted-foreground text-xs">{urlArchOpen
                  ? <svg className="h-4 w-4 text-muted-foreground" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="m18 15-6-6-6 6"/></svg>
                  : <svg className="h-4 w-4 text-muted-foreground" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="m6 9 6 6 6-6"/></svg>}</span>
            </div>
          </CardHeader>
          {urlArchOpen && (
            <CardContent>
              <div className="grid grid-cols-2 gap-4 mb-4 sm:grid-cols-4">
                {[
                  { label: 'Discovered', value: scan.url_architecture.total_urls_discovered },
                  { label: 'Forms', value: scan.url_architecture.forms_found },
                  { label: 'Redirects', value: scan.url_architecture.redirects_found },
                  { label: 'robots.txt', value: scan.url_architecture.robots_url ? 'Found' : 'Missing' },
                ].map(({ label, value }) => (
                  <div key={label} className="rounded-lg bg-muted/40 p-3 text-center">
                    <p className="text-xl font-bold">{value}</p>
                    <p className="text-xs text-muted-foreground">{label}</p>
                  </div>
                ))}
              </div>
              <div className="max-h-64 overflow-y-auto space-y-0 divide-y divide-border/50">
                {scan.url_architecture.crawled_urls.map((u) => (
                  <div key={u.url} className="flex items-center gap-2 text-xs py-1.5">
                    <span className={`w-10 text-center font-mono rounded px-1 shrink-0 ${
                      u.status_code && u.status_code < 300 ? 'text-green-400' :
                      u.status_code && u.status_code < 400 ? 'text-blue-400' : 'text-red-400'
                    }`}>{u.status_code ?? '?'}</span>
                    <span className="text-muted-foreground font-mono truncate flex-1">{u.url}</span>
                    {u.has_forms && <span className="text-amber-400 shrink-0">form</span>}
                    {u.has_auth_signals && <span className="text-red-400 shrink-0">auth</span>}
                  </div>
                ))}
              </div>
            </CardContent>
          )}
        </Card>
      )}

      {/* HTTP Surface Analysis */}
      {scan.surface_scan && (
        <Card>
          <CardHeader className="cursor-pointer" onClick={() => setSurfaceOpen(!surfaceOpen)}>
            <div className="flex items-center justify-between">
              <CardTitle>
                HTTP Surface Analysis
                {scan.surface_scan.total_issues > 0 && (
                  <span className="ml-2 text-sm font-normal text-amber-400">
                    {scan.surface_scan.total_issues} issue{scan.surface_scan.total_issues !== 1 ? 's' : ''}
                  </span>
                )}
              </CardTitle>
              <span className="text-muted-foreground text-xs">{surfaceOpen
                  ? <svg className="h-4 w-4 text-muted-foreground" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="m18 15-6-6-6 6"/></svg>
                  : <svg className="h-4 w-4 text-muted-foreground" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="m6 9 6 6 6-6"/></svg>}</span>
            </div>
          </CardHeader>
          {surfaceOpen && (
            <CardContent>
              <div className="space-y-4">
                {scan.surface_scan.analyzed_urls.map((a) => (
                  <div key={a.url} className="rounded-lg border border-border p-3">
                    <p className="text-xs font-mono text-muted-foreground mb-2 truncate">{a.url}</p>
                    <div className="flex flex-wrap gap-2 mb-2">
                      {a.hsts && <span className="inline-flex items-center gap-1 text-xs text-green-400 bg-green-500/10 rounded px-1.5 py-0.5"><svg className="h-3 w-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M20 6 9 17l-5-5"/></svg>HSTS</span>}
                      {a.x_content_type_options && <span className="inline-flex items-center gap-1 text-xs text-green-400 bg-green-500/10 rounded px-1.5 py-0.5"><svg className="h-3 w-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M20 6 9 17l-5-5"/></svg>X-Content-Type</span>}
                      {a.cors_policy && <span className="text-xs text-orange-400 bg-orange-500/10 rounded px-1.5 py-0.5">CORS: {a.cors_policy}</span>}
                      {a.server_header && <span className="text-xs text-muted-foreground bg-muted rounded px-1.5 py-0.5">Server: {a.server_header}</span>}
                    </div>
                    {a.issues.length > 0 && (
                      <ul className="space-y-1">
                        {a.issues.map((issue, i) => (
                          <li key={i} className="flex items-start gap-2 text-xs">
                            <span className={`shrink-0 font-semibold ${
                              issue.severity === 'high' ? 'text-red-400' :
                              issue.severity === 'medium' ? 'text-amber-400' :
                              issue.severity === 'low' ? 'text-blue-400' : 'text-muted-foreground'
                            }`}>{issue.severity.toUpperCase()}</span>
                            <span className="text-muted-foreground">{issue.header}: {issue.issue}</span>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                ))}
              </div>
            </CardContent>
          )}
        </Card>
      )}

      {/* Client-Side Security (Frontend Hooks) */}
      {scan.frontend_hooks && (
        <Card>
          <CardHeader className="cursor-pointer" onClick={() => setHooksOpen(!hooksOpen)}>
            <div className="flex items-center justify-between">
              <CardTitle>
                Client-Side Security
                {scan.frontend_hooks.total_issues > 0 ? (
                  <span className="ml-2 text-sm font-normal text-amber-400">
                    {scan.frontend_hooks.total_issues} issue{scan.frontend_hooks.total_issues !== 1 ? 's' : ''}
                  </span>
                ) : (
                  <span className="ml-2 text-sm font-normal text-green-400">clean</span>
                )}
              </CardTitle>
              <span className="text-muted-foreground text-xs">{hooksOpen
                  ? <svg className="h-4 w-4 text-muted-foreground" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="m18 15-6-6-6 6"/></svg>
                  : <svg className="h-4 w-4 text-muted-foreground" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="m6 9 6 6 6-6"/></svg>}</span>
            </div>
          </CardHeader>
          {hooksOpen && (
            <CardContent>
              <div className="grid grid-cols-2 gap-3 mb-4 sm:grid-cols-3">
                <div className="rounded-lg bg-muted/40 p-3 text-center">
                  <p className="text-xl font-bold">{scan.frontend_hooks.analyzed_urls}</p>
                  <p className="text-xs text-muted-foreground">Pages Analyzed</p>
                </div>
                <div className="rounded-lg bg-muted/40 p-3 text-center">
                  <p className="text-xl font-bold">{scan.frontend_hooks.total_issues}</p>
                  <p className="text-xs text-muted-foreground">Issues Found</p>
                </div>
              </div>
              {scan.frontend_hooks.issues.length === 0 ? (
                <p className="text-sm text-muted-foreground">No client-side security issues detected.</p>
              ) : (
                <div className="space-y-2">
                  {scan.frontend_hooks.issues.map((issue, i) => (
                    <div key={i} className="rounded-lg border border-border p-3 space-y-1">
                      <div className="flex items-center gap-2">
                        <span className={`text-xs font-semibold shrink-0 ${
                          issue.severity === 'high' ? 'text-red-400' :
                          issue.severity === 'medium' ? 'text-amber-400' :
                          issue.severity === 'low' ? 'text-blue-400' : 'text-muted-foreground'
                        }`}>{issue.severity.toUpperCase()}</span>
                        <span className="text-xs font-mono bg-muted px-1.5 py-0.5 rounded">
                          {issue.sink_name ?? issue.issue_type}
                        </span>
                        {issue.line_hint && (
                          <span className="text-xs text-muted-foreground">{issue.line_hint}</span>
                        )}
                      </div>
                      <p className="text-xs font-mono text-muted-foreground truncate">{issue.url}</p>
                      <pre className="text-xs text-amber-300 bg-zinc-950 rounded px-2 py-1 overflow-x-auto font-mono whitespace-pre-wrap break-all">
                        {issue.evidence}
                      </pre>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          )}
        </Card>
      )}

      {/* Resistance Testing */}
      {scan.resistance_test && (
        <Card>
          <CardHeader className="cursor-pointer" onClick={() => setResistanceOpen(!resistanceOpen)}>
            <div className="flex items-center justify-between">
              <CardTitle>
                Resistance Testing
                {scan.resistance_test.vulnerable_count > 0 ? (
                  <span className="ml-2 text-sm font-normal text-red-400">
                    {scan.resistance_test.vulnerable_count} potential vuln{scan.resistance_test.vulnerable_count !== 1 ? 's' : ''}
                  </span>
                ) : (
                  <span className="ml-2 text-sm font-normal text-green-400">
                    {scan.resistance_test.probed_endpoints} probed, none triggered
                  </span>
                )}
              </CardTitle>
              <span className="text-muted-foreground text-xs">{resistanceOpen
                  ? <svg className="h-4 w-4 text-muted-foreground" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="m18 15-6-6-6 6"/></svg>
                  : <svg className="h-4 w-4 text-muted-foreground" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="m6 9 6 6 6-6"/></svg>}</span>
            </div>
          </CardHeader>
          {resistanceOpen && (
            <CardContent>
              <div className="grid grid-cols-2 gap-3 mb-4 sm:grid-cols-3">
                <div className="rounded-lg bg-muted/40 p-3 text-center">
                  <p className="text-xl font-bold">{scan.resistance_test.probed_endpoints}</p>
                  <p className="text-xs text-muted-foreground">Endpoints Probed</p>
                </div>
                <div className="rounded-lg bg-muted/40 p-3 text-center">
                  <p className={`text-xl font-bold ${scan.resistance_test.vulnerable_count > 0 ? 'text-red-400' : 'text-green-400'}`}>
                    {scan.resistance_test.vulnerable_count}
                  </p>
                  <p className="text-xs text-muted-foreground">Triggered</p>
                </div>
              </div>
              {scan.resistance_test.probes.filter((p) => p.vulnerable).length === 0 ? (
                <p className="text-sm text-muted-foreground">All probes returned expected results.</p>
              ) : (
                <div className="space-y-2">
                  {scan.resistance_test.probes.filter((p) => p.vulnerable).map((probe, i) => (
                    <div key={i} className="rounded-lg border border-red-500/30 bg-red-500/5 p-3 space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`text-xs font-semibold ${
                          probe.severity === 'high' ? 'text-red-400' :
                          probe.severity === 'medium' ? 'text-amber-400' : 'text-blue-400'
                        }`}>{probe.severity.toUpperCase()}</span>
                        <span className="text-xs font-mono bg-muted px-1.5 py-0.5 rounded">{probe.probe_type}</span>
                        {probe.parameter && (
                          <span className="text-xs text-muted-foreground">param: <code className="font-mono">{probe.parameter}</code></span>
                        )}
                        <span className="text-xs text-muted-foreground ml-auto">{probe.request_count} req</span>
                      </div>
                      <p className="text-xs font-mono text-muted-foreground truncate">{probe.url}</p>
                      <p className="text-xs text-amber-300 bg-zinc-950 rounded px-2 py-1 font-mono break-all">{probe.evidence}</p>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          )}
        </Card>
      )}

      {selectedFinding && (
        <>
          <div className="fixed inset-0 z-40 bg-black/50" onClick={() => setSelectedFinding(null)} />
          <RemediationPanel finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
        </>
      )}
    </div>
  )
}
