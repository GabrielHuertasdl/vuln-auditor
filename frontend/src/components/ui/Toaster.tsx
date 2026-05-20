import React, { useEffect, useState } from 'react'
import { cn } from '@/lib/utils'
import { type Toast, type ToastVariant, registerDispatch } from '@/hooks/useToast'

// ─── Shared in-memory store (module-level, singleton) ────────────────────────
type Listener = (toasts: Toast[]) => void
const _listeners = new Set<Listener>()
let _toasts: Toast[] = []
let _counter = 0

function dispatch(message: string, variant: ToastVariant = 'info', duration = 4000) {
  const id = String(++_counter)
  const toast: Toast = { id, message, variant, duration }
  _toasts = [..._toasts, toast]
  _listeners.forEach((l) => l([..._toasts]))
  if (duration > 0) setTimeout(() => dismiss(id), duration)
  return id
}

function dismiss(id: string) {
  _toasts = _toasts.filter((t) => t.id !== id)
  _listeners.forEach((l) => l([..._toasts]))
}

// ─── Icons ────────────────────────────────────────────────────────────────────
const icons: Record<ToastVariant, React.ReactNode> = {
  success: (
    <svg className="h-4 w-4 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M20 6 9 17l-5-5" />
    </svg>
  ),
  error: (
    <svg className="h-4 w-4 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="12" cy="12" r="10" />
      <path d="m15 9-6 6M9 9l6 6" />
    </svg>
  ),
  warning: (
    <svg className="h-4 w-4 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
      <path d="M12 9v4M12 17h.01" />
    </svg>
  ),
  info: (
    <svg className="h-4 w-4 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="12" cy="12" r="10" />
      <path d="M12 16v-4M12 8h.01" />
    </svg>
  ),
}

const variantStyles: Record<ToastVariant, string> = {
  success: 'border-green-500/40 bg-green-500/10 text-green-400',
  error:   'border-red-500/40 bg-red-500/10 text-red-400',
  warning: 'border-yellow-500/40 bg-yellow-500/10 text-yellow-400',
  info:    'border-blue-500/40 bg-blue-500/10 text-blue-400',
}

// ─── Single toast item ────────────────────────────────────────────────────────
function ToastItem({ toast }: { toast: Toast }) {
  const [visible, setVisible] = useState(false)

  useEffect(() => {
    const raf = requestAnimationFrame(() => setVisible(true))
    return () => cancelAnimationFrame(raf)
  }, [])

  return (
    <div
      className={cn(
        'flex items-start gap-3 rounded-lg border p-4 shadow-xl w-full max-w-sm transition-all duration-300',
        variantStyles[toast.variant],
        visible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-2',
      )}
      role="alert"
    >
      {icons[toast.variant]}
      <p className="flex-1 text-sm font-medium leading-snug">{toast.message}</p>
      <button
        onClick={() => dismiss(toast.id)}
        className="shrink-0 opacity-60 hover:opacity-100 transition-opacity mt-0.5"
        aria-label="Dismiss"
      >
        <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M18 6 6 18M6 6l12 12" />
        </svg>
      </button>
    </div>
  )
}

// ─── Toaster container ────────────────────────────────────────────────────────
export function Toaster() {
  const [toasts, setToasts] = useState<Toast[]>([])

  useEffect(() => {
    // Register the dispatch function so useToast() can call it synchronously
    registerDispatch(dispatch)
    setToasts([..._toasts])
    _listeners.add(setToasts)
    return () => {
      _listeners.delete(setToasts)
    }
  }, [])

  if (toasts.length === 0) return null

  return (
    <div
      aria-live="polite"
      aria-label="Notifications"
      className="fixed bottom-4 right-4 z-[100] flex flex-col gap-2 items-end pointer-events-none"
    >
      {toasts.map((toast) => (
        <div key={toast.id} className="pointer-events-auto">
          <ToastItem toast={toast} />
        </div>
      ))}
    </div>
  )
}
