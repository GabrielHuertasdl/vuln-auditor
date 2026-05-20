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

  return (
    <TableRow
      className="cursor-pointer"
      onClick={() => navigate(`/scans/${scan.id}`)}
    >
      <TableCell>
        <span className="font-mono text-xs text-muted-foreground">{shortId(scan.id)}</span>
      </TableCell>
      <TableCell>
        <span className="text-sm font-medium">{targetName ?? scan.target_url ?? scan.target_id.slice(0, 8)}</span>
      </TableCell>
      <TableCell>
        <ScanStatusBadge status={scan.status} />
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
