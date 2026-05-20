import React, { createContext, useContext, useEffect, useState, useCallback } from 'react'
import { authEndpoints, type TokenResponse, type UserInfo } from './api'

interface AuthContextValue {
  user: UserInfo | null
  isLoading: boolean
  isAuthenticated: boolean
  login: (email: string, password: string) => Promise<void>
  register: (data: { name: string; email: string; password: string; org_name?: string }) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthContextValue | null>(null)

function storeTokens(data: TokenResponse) {
  localStorage.setItem('access_token', data.access_token)
  localStorage.setItem('refresh_token', data.refresh_token)
}

function clearTokens() {
  localStorage.removeItem('access_token')
  localStorage.removeItem('refresh_token')
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<UserInfo | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  const fetchMe = useCallback(async () => {
    const token = localStorage.getItem('access_token')
    if (!token) {
      setIsLoading(false)
      return
    }
    try {
      const { data } = await authEndpoints.me()
      setUser(data)
    } catch {
      clearTokens()
      setUser(null)
    } finally {
      setIsLoading(false)
    }
  }, [])

  useEffect(() => {
    void fetchMe()
  }, [fetchMe])

  const login = useCallback(async (email: string, password: string) => {
    const { data } = await authEndpoints.login({ email, password })
    storeTokens(data)
    setUser(data.user)
  }, [])

  const register = useCallback(
    async (payload: { name: string; email: string; password: string; org_name?: string }) => {
      const { data } = await authEndpoints.register(payload)
      storeTokens(data)
      setUser(data.user)
    },
    [],
  )

  const logout = useCallback(() => {
    clearTokens()
    setUser(null)
  }, [])

  return (
    <AuthContext.Provider
      value={{ user, isLoading, isAuthenticated: !!user, login, register, logout }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
