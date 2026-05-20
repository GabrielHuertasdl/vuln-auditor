import React, { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { type Finding, findingsApi } from '@/lib/api'
import { formatRelativeTime, getHostname, truncate } from '@/lib/utils'
import { SeverityBadge } from './SeverityBadge'
import { StatusBadge } from './StatusBadge'
import { TableRow, TableCell } from './ui/Table'
import { Select } from './ui/Select'
import { useToast } from '@/hooks/useToast'

const STATUS_OPTIONS = [
  { value: 'open', label: 'Open' },
  { value: 'acknowledged', label: 'Acknowledged' },
  { value: 'resolved', label: 'Resolved' },
  { value: 'false_positive', label: 'False Positive' },
  { value: 'retest_needed', label: 'Retest Needed' },
]

interface FindingRowProps {
  finding: Finding
  showTarget?: boolean
  targetName?: string
}

export function FindingRow({ finding, showTarget, targetName }: FindingRowProps) {
  const [editing, setEditing] = useState(false)
  const qc = useQueryClient()
  const { toast } = useToast()

  const mutation = useMutation({
    mutationFn: (status: string) =>
      findingsApi.updateStatus(finding.id, { status }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['findings'] })
      void qc.invalidateQueries({ queryKey: ['scan', finding.target_id] })
      toast('Finding status updated', 'success')
      setEditing(false)
    },
    onError: () => toast('Failed to update status', 'error'),
  })

  return (
    <TableRow>
      <TableCell>
        <SeverityBadge severity={finding.severity} />
      </TableCell>
      <TableCell>
        {finding.cwe_ids.length > 0 ? (
          <a
            href={`https://nvd.nist.gov/vuln/search/results?query=${finding.cwe_ids[0]}`}
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-primary hover:underline"
            onClick={(e) => e.stopPropagation()}
          >
            Check CVE
          </a>
        ) : (
          <span className="text-xs text-muted-foreground">—</span>
        )}
      </TableCell>
      <TableCell className="max-w-[260px]">
        <div className="font-medium text-foreground">{truncate(finding.title, 60)}</div>
        {finding.owasp_category && (
          <div className="text-xs text-muted-foreground mt-0.5">{finding.owasp_category}</div>
        )}
      </TableCell>
      {showTarget && (
        <TableCell>
          <span className="text-sm text-muted-foreground">{targetName ?? finding.target_id.slice(0, 8)}</span>
        </TableCell>
      )}
      <TableCell>
        <span className="text-sm text-muted-foreground font-mono">
          {finding.host ? getHostname(finding.host) : '—'}
        </span>
      </TableCell>
      <TableCell>
        {editing ? (
          <Select
            options={STATUS_OPTIONS}
            value={finding.status}
            onChange={(e) => mutation.mutate(e.target.value)}
            className="w-36 text-xs h-7"
          />
        ) : (
          <button onClick={() => setEditing(true)} className="group">
            <StatusBadge status={finding.status} className="cursor-pointer group-hover:opacity-80" />
          </button>
        )}
      </TableCell>
      <TableCell>
        <span className="text-xs text-muted-foreground">{formatRelativeTime(finding.first_seen_at)}</span>
      </TableCell>
      <TableCell>
        <span className="text-xs text-muted-foreground">{formatRelativeTime(finding.last_seen_at)}</span>
      </TableCell>
    </TableRow>
  )
}
