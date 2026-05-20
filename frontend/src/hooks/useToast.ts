import { useCallback } from 'react'

export type ToastVariant = 'success' | 'error' | 'warning' | 'info'

export interface Toast {
  id: string
  message: string
  variant: ToastVariant
  duration?: number
}

// ─── Synchronous toast dispatch (no dynamic import needed) ───────────────────
// The Toaster component registers the real dispatch function here on mount.
let _dispatch: ((msg: string, variant: ToastVariant, duration?: number) => void) | null = null

export function registerDispatch(fn: (msg: string, variant: ToastVariant, duration?: number) => void) {
  _dispatch = fn
}

export function addToast(message: string, variant: ToastVariant = 'info', duration?: number) {
  _dispatch?.(message, variant, duration)
}

// ─── Hook ────────────────────────────────────────────────────────────────────
export function useToast() {
  const toast = useCallback(
    (message: string, variant: ToastVariant = 'info', duration?: number) => {
      addToast(message, variant, duration)
    },
    [],
  )

  return { toast }
}
