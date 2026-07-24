import React, { useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'

/**
 * Landing page for OIDC callbacks.
 * The backend redirects here after a successful SSO login with:
 *   /auth/callback?access_token=<jwt>&refresh_token=<rt>&user=<json>
 * We store the tokens and redirect to /dashboard.
 */
export default function AuthCallback() {
  const navigate = useNavigate()
  const handled = useRef(false)

  useEffect(() => {
    if (handled.current) return
    handled.current = true

    const params = new URLSearchParams(window.location.search)
    const accessToken = params.get('access_token')
    const refreshToken = params.get('refresh_token')
    const userJson = params.get('user')

    if (accessToken) {
      localStorage.setItem('access_token', accessToken)
    }
    if (refreshToken) {
      localStorage.setItem('refresh_token', refreshToken)
    }
    if (userJson) {
      try {
        localStorage.setItem('user', userJson)
      } catch {
        // ignore parse errors
      }
    }

    // Remove tokens from URL so they don't appear in browser history
    window.history.replaceState({}, document.title, '/auth/callback')

    navigate('/dashboard', { replace: true })
  }, [navigate])

  return (
    <div className="flex min-h-screen items-center justify-center bg-background">
      <div className="text-center space-y-3">
        <div className="mx-auto h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent" />
        <p className="text-sm text-muted-foreground">Signing you in…</p>
      </div>
    </div>
  )
}
