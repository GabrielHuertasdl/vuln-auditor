import React, { Suspense, lazy } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AuthProvider } from '@/lib/auth'
import { ThemeProvider } from '@/lib/theme'
import { Layout } from '@/components/layout/Layout'
import { PublicLayout } from '@/components/layout/PublicLayout'
import { Toaster } from '@/components/ui/Toaster'

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
                {/* Pricing is publicly accessible */}
                <Route path="/pricing" element={<PublicLayout><Pricing /></PublicLayout>} />
                <Route path="/dashboard" element={<Layout><Dashboard /></Layout>} />
                <Route path="/targets" element={<Layout><Targets /></Layout>} />
                <Route path="/targets/:id" element={<Layout><TargetDetail /></Layout>} />
                <Route path="/scans" element={<Layout><Scans /></Layout>} />
                <Route path="/scans/:id" element={<Layout><ScanDetail /></Layout>} />
                <Route path="/findings" element={<Layout><Findings /></Layout>} />
                <Route path="/reports" element={<Layout><Reports /></Layout>} />
                <Route path="/settings" element={<Layout><Settings /></Layout>} />
                <Route path="/" element={<Navigate to="/dashboard" replace />} />
                <Route path="*" element={<Navigate to="/dashboard" replace />} />
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
