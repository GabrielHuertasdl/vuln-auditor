import { useEffect, useRef, useState } from 'react'

export interface ScanProgressEvent {
  status: 'pending' | 'running' | 'analyzing' | 'done' | 'failed' | 'partial'
  progress_pct: number
  progress_message: string | null
  error?: string
}

const TERMINAL_STATUSES = new Set(['done', 'failed', 'partial'])

/**
 * Opens a WebSocket to /api/v1/scan/{scanId}/ws and streams progress events.
 * Closes automatically once the scan reaches a terminal state.
 * Falls back gracefully if the WS connection fails (caller can use polling as backup).
 */
export function useScanWebSocket(
  scanId: string | undefined,
  enabled: boolean,
): {
  progress: ScanProgressEvent | null
  connected: boolean
  error: string | null
} {
  const [progress, setProgress] = useState<ScanProgressEvent | null>(null)
  const [connected, setConnected] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const retryTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    if (!scanId || !enabled) return

    let cancelled = false

    const connect = () => {
      if (cancelled) return

      const token = localStorage.getItem('access_token')
      const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
      const host = window.location.host
      const url = `${proto}://${host}/api/v1/scan/${scanId}/ws${token ? `?token=${encodeURIComponent(token)}` : ''}`

      const ws = new WebSocket(url)
      wsRef.current = ws

      ws.onopen = () => {
        if (!cancelled) setConnected(true)
      }

      ws.onmessage = (evt) => {
        if (cancelled) return
        try {
          const data = JSON.parse(evt.data) as ScanProgressEvent
          setProgress(data)
          if (data.status && TERMINAL_STATUSES.has(data.status)) {
            ws.close(1000)
          }
        } catch {
          // ignore malformed frame
        }
      }

      ws.onerror = () => {
        if (!cancelled) setError('WebSocket connection failed')
        setConnected(false)
      }

      ws.onclose = (evt) => {
        setConnected(false)
        if (!cancelled && evt.code !== 1000 && evt.code !== 4001) {
          // Reconnect after 3 s for unexpected closes (not auth failure)
          retryTimerRef.current = setTimeout(connect, 3000)
        }
      }
    }

    connect()

    return () => {
      cancelled = true
      if (retryTimerRef.current) clearTimeout(retryTimerRef.current)
      if (wsRef.current) {
        wsRef.current.close(1000)
        wsRef.current = null
      }
    }
  }, [scanId, enabled])

  return { progress, connected, error }
}
