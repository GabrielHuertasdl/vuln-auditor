import React from 'react'
import { useNavigate } from 'react-router-dom'
import { type Target } from '@/lib/api'
import { formatRelativeTime } from '@/lib/utils'
import { TableRow, TableCell } from './ui/Table'
import { Badge } from './ui/Badge'
import { Button } from './ui/Button'

interface TargetRowProps {
  target: Target
  onScanNow: (target: Target) => void
  onEdit: (target: Target) => void
  onDelete: (target: Target) => void
  isScanning?: boolean
}

const scheduleLabel: Record<string, string> = {
  daily: 'Daily',
  weekly: 'Weekly',
  monthly: 'Monthly',
}

export function TargetRow({ target, onScanNow, onEdit, onDelete, isScanning }: TargetRowProps) {
  const navigate = useNavigate()

  return (
    <TableRow>
      <TableCell>
        <button
          className="text-left hover:underline"
          onClick={() => navigate(`/targets/${target.id}`)}
        >
          <div className="font-medium text-foreground">{target.name}</div>
          <div className="text-xs text-muted-foreground font-mono mt-0.5 truncate max-w-[200px]">
            {target.url}
          </div>
        </button>
      </TableCell>
      <TableCell>
        {target.schedule ? (
          <Badge variant="outline">{scheduleLabel[target.schedule]}</Badge>
        ) : (
          <span className="text-xs text-muted-foreground">Manual</span>
        )}
      </TableCell>
      <TableCell>
        <span className="text-sm text-muted-foreground">
          {formatRelativeTime(target.last_scan_at)}
        </span>
      </TableCell>
      <TableCell>
        <span className="text-sm font-medium">{target.scan_count}</span>
      </TableCell>
      <TableCell>
        {target.open_finding_count !== undefined && (
          <span
            className={
              target.open_finding_count > 0
                ? 'text-sm font-semibold text-red-500'
                : 'text-sm text-muted-foreground'
            }
          >
            {target.open_finding_count}
          </span>
        )}
      </TableCell>
      <TableCell>
        <div className="flex items-center gap-1">
          <Button
            size="sm"
            variant="outline"
            onClick={() => onScanNow(target)}
            isLoading={isScanning}
            disabled={isScanning}
          >
            <svg className="h-3 w-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="m5 3 14 9-14 9V3z" />
            </svg>
            Scan
          </Button>
          <Button size="icon-sm" variant="ghost" onClick={() => onEdit(target)}>
            <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" />
              <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" />
            </svg>
          </Button>
          <Button size="icon-sm" variant="ghost" onClick={() => onDelete(target)} className="text-red-500 hover:text-red-400">
            <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6" />
            </svg>
          </Button>
        </div>
      </TableCell>
    </TableRow>
  )
}
