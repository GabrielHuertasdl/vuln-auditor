import React from 'react'
import { useNavigate } from 'react-router-dom'
import { type ScanSummary } from '@/lib/api'
import { formatRelativeTime, formatDuration, shortId } from '@/lib/utils'
import { ScanStatusBadge } from './ScanStatusBadge'
import { TableRow, TableCell } from './ui/Table'

interface ScanRowProps {
  scan: ScanSummary
  targetName?: string
}

export function ScanRow({ scan, targetName }: ScanRowProps) {
  const navigate = useNavigate()

  const totalFindings = scan.finding_count
  const sev = scan.severity_summary

  const isActive = scan.status === 'running' || scan.status === 'pending' || scan.status === 'analyzing'
  const pct = scan.progress_pct ?? 0

  return (
    <TableRow
      className={`cursor-pointer transition-colors ${isActive ? 'bg-primary/5 hover:bg-primary/10' : ''}`}
      onClick={() => navigate(`/scans/${scan.id}`)}
    >
      <TableCell>
        <span className="font-mono text-xs text-muted-foreground">{shortId(scan.id)}</span>
      </TableCell>
      <TableCell>
        <span className="text-sm font-medium">{targetName ?? scan.target_url ?? scan.target_id.slice(0, 8)}</span>
      </TableCell>
      <TableCell>
        <div className="flex flex-col gap-1.5">
          <ScanStatusBadge status={scan.status} />
          {isActive && (
            <div className="flex items-center gap-2">
              <div className="h-1.5 w-28 rounded-full bg-muted overflow-hidden">
                <div
                  className="h-full rounded-full bg-primary transition-all duration-700"
                  style={{ width: `${pct}%` }}
                />
              </div>
              <span className="text-xs font-mono text-muted-foreground tabular-nums">{pct}%</span>
            </div>
          )}
        </div>
      </TableCell>
      <TableCell>
        <div className="flex gap-1 flex-wrap">
          {(scan.tools ?? []).map((tool) => (
            <span
              key={tool}
              className="rounded bg-muted px-1.5 py-0.5 text-xs font-mono text-muted-foreground"
            >
              {tool}
            </span>
          ))}
        </div>
      </TableCell>
      <TableCell>
        <div className="flex items-center gap-3 text-sm">
          <span className="font-medium">{totalFindings}</span>
          {sev.critical > 0 && (
            <span className="text-xs text-red-500 font-semibold">{sev.critical}C</span>
          )}
          {sev.high > 0 && (
            <span className="text-xs text-orange-500 font-semibold">{sev.high}H</span>
          )}
        </div>
      </TableCell>
      <TableCell>
        <div className="flex gap-2 text-xs">
          {scan.new_finding_count > 0 && (
            <span className="text-green-500 font-medium">+{scan.new_finding_count} new</span>
          )}
          {scan.regressed_finding_count > 0 && (
            <span className="text-orange-500 font-medium">
              {scan.regressed_finding_count} regressed
            </span>
          )}
        </div>
      </TableCell>
      <TableCell>
        <span className="text-xs text-muted-foreground">
          {formatRelativeTime(scan.started_at)}
        </span>
      </TableCell>
      <TableCell>
        <span className="text-xs text-muted-foreground">
          {formatDuration(scan.duration_seconds)}
        </span>
      </TableCell>
    </TableRow>
  )
}
