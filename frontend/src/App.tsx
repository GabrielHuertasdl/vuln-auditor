import React, { Suspense, lazy } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AuthProvider } from '@/lib/auth'
import { ThemeProvider } from '@/lib/theme'
import { Layout } from '@/components/layout/Layout'
import { PublicLayout } from '@/components/layout/PublicLayout'
import { Toaster } from '@/components/ui/Toaster'
import { RequireAuth } from '@/components/RequireAuth'

const Login = lazy(() => import('@/pages/Login'))
const Register = lazy(() => import('@/pages/Register'))
const Dashboard = lazy(() => import('@/pages/Dashboard'))
const Targets = lazy(() => import('@/pages/Targets'))
const TargetDetail = lazy(() => import('@/pages/TargetDetail'))
const Scans = lazy(() => import('@/pages/Scans'))
const ScanDetail = lazy(() => import('@/pages/ScanDetail'))
const Findings = lazy(() => import('@/pages/Findings'))
const Reports = lazy(() => import('@/pages/Reports'))
const Settings = lazy(() => import('@/pages/Settings'))
const Pricing = lazy(() => import('@/pages/Pricing'))
const AuthCallback = lazy(() => import('@/pages/AuthCallback'))

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 30_000, retry: 1 },
  },
})

function PageLoader() {
  return (
    <div className="flex h-64 items-center justify-center">
      <div className="h-6 w-6 animate-spin rounded-full border-2 border-primary border-t-transparent" />
    </div>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <ThemeProvider>
        <QueryClientProvider client={queryClient}>
          <AuthProvider>
            <Suspense fallback={<PageLoader />}>
              <Routes>
                <Route path="/login" element={<Login />} />
                <Route path="/register" element={<Register />} />
                <Route path="/auth/callback" element={<AuthCallback />} />
                {/* Pricing is publicly accessible */}
                <Route path="/pricing" element={<PublicLayout><Pricing /></PublicLayout>} />
                <Route path="/dashboard" element={<RequireAuth><Layout><Dashboard /></Layout></RequireAuth>} />
                <Route path="/targets" element={<RequireAuth><Layout><Targets /></Layout></RequireAuth>} />
                <Route path="/targets/:id" element={<RequireAuth><Layout><TargetDetail /></Layout></RequireAuth>} />
                <Route path="/scans" element={<RequireAuth><Layout><Scans /></Layout></RequireAuth>} />
                <Route path="/scans/:id" element={<RequireAuth><Layout><ScanDetail /></Layout></RequireAuth>} />
                <Route path="/findings" element={<RequireAuth><Layout><Findings /></Layout></RequireAuth>} />
                <Route path="/reports" element={<RequireAuth><Layout><Reports /></Layout></RequireAuth>} />
                <Route path="/settings" element={<RequireAuth><Layout><Settings /></Layout></RequireAuth>} />
                <Route path="/" element={<Navigate to="/dashboard" replace />} />
                <Route path="*" element={<Navigate to="/login" replace />} />
              </Routes>
            </Suspense>
          </AuthProvider>
          {/* Global toaster — handles auth pages that have no Layout */}
          <Toaster />
        </QueryClientProvider>
      </ThemeProvider>
    </BrowserRouter>
  )
}
