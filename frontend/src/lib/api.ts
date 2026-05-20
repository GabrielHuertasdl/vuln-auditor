import axios, { type AxiosError, type InternalAxiosRequestConfig } from 'axios'

// ─── Types ───────────────────────────────────────────────────────────────────
export interface TokenResponse {
  access_token: string
  refresh_token: string
  token_type: string
  user: UserInfo
}

export interface UserInfo {
  id: string
  email: string
  name: string
  role: string
  org_id: string
  org_name: string
}

export interface SeveritySummary {
  critical: number
  high: number
  medium: number
  low: number
  informational: number
}

export interface ScanSummary {
  id: string
  org_id: string
  target_id: string
  status: 'pending' | 'running' | 'done' | 'failed' | 'partial'
  scan_mode: 'full' | 'quick'
  finding_count: number
  new_finding_count: number
  regressed_finding_count: number
  severity_summary: SeveritySummary
  started_at: string | null
  completed_at: string | null
  duration_seconds: number | null
  ai_generated: boolean
  tools?: string[]
  target_url?: string
}

export interface ScanResult extends ScanSummary {
  findings: Finding[]
  posture_score?: number
  coverage_score?: number
  confidence_score?: number
  exposure_score?: number
}

export interface ScanDiff {
  scan_id: string
  previous_scan_id: string | null
  new_findings: Finding[]
  resolved_findings: Finding[]
  regressed_findings: Finding[]
  unchanged_count: number
}

export interface Finding {
  id: string
  org_id: string
  target_id: string
  title: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational'
  priority: number
  confidence: number
  status: 'open' | 'acknowledged' | 'resolved' | 'false_positive' | 'retest_needed'
  owasp_category: string | null
  cwe_ids: string[]
  sources: string[]
  evidence: string | null
  solution: string | null
  ai_mitigation: string | null
  first_seen_at: string
  last_seen_at: string
  is_noise: boolean
  host?: string
  path?: string
}

export interface StatusHistory {
  id: string
  finding_id: string
  status: string
  note: string | null
  changed_by: string
  changed_at: string
}

export interface Target {
  id: string
  org_id: string
  url: string
  name: string
  tags: string[]
  schedule: 'daily' | 'weekly' | 'monthly' | null
  created_at: string
  last_scan_at: string | null
  scan_count: number
  open_finding_count?: number
}

export interface DashboardData {
  org: {
    id: string
    name: string
    plan: string
    scans_this_month: number
    scan_quota: number
  }
  total_targets: number
  total_scans: number
  open_findings_by_severity: SeveritySummary
  recent_scans: ScanSummary[]
  top_targets_by_risk: Array<{
    id: string
    name: string
    url: string
    open_findings: number
    critical_high: number
  }>
}

export interface PostureTrendPoint {
  date: string
  overall_score: number
  coverage_score: number
  confidence_score: number
  exposure_score: number
  scan_id: string
}

export interface OrgInfo {
  id: string
  name: string
  plan: string
  scan_quota: number
  scans_this_month: number
  quota_reset_at: string
  created_at: string
}

export interface FindingsFilter {
  status?: string
  severity?: string
  target_id?: string
  limit?: number
  offset?: number
}

// ─── Axios Instance ──────────────────────────────────────────────────────────
const api = axios.create({
  baseURL: '/api',
  headers: { 'Content-Type': 'application/json' },
})

const authApi = axios.create({
  baseURL: '/auth',
  headers: { 'Content-Type': 'application/json' },
})

// ─── Request Interceptor ─────────────────────────────────────────────────────
api.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const token = localStorage.getItem('access_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// ─── Response Interceptor (token refresh) ───────────────────────────────────
let isRefreshing = false
let failedQueue: Array<{ resolve: (value: string) => void; reject: (reason: unknown) => void }> = []

function processQueue(error: unknown, token: string | null = null) {
  failedQueue.forEach((prom) => {
    if (error) prom.reject(error)
    else prom.resolve(token!)
  })
  failedQueue = []
}

api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean }

    if (error.response?.status === 401 && !originalRequest._retry) {
      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject })
        })
          .then((token) => {
            originalRequest.headers.Authorization = `Bearer ${token}`
            return api(originalRequest)
          })
          .catch((err) => Promise.reject(err))
      }

      originalRequest._retry = true
      isRefreshing = true

      const refreshToken = localStorage.getItem('refresh_token')
      if (!refreshToken) {
        isRefreshing = false
        localStorage.removeItem('access_token')
        localStorage.removeItem('refresh_token')
        window.location.href = '/login'
        return Promise.reject(error)
      }

      try {
        const { data } = await authApi.post<TokenResponse>('/refresh', {
          refresh_token: refreshToken,
        })
        localStorage.setItem('access_token', data.access_token)
        localStorage.setItem('refresh_token', data.refresh_token)
        api.defaults.headers.common.Authorization = `Bearer ${data.access_token}`
        processQueue(null, data.access_token)
        originalRequest.headers.Authorization = `Bearer ${data.access_token}`
        return api(originalRequest)
      } catch (refreshError) {
        processQueue(refreshError, null)
        localStorage.removeItem('access_token')
        localStorage.removeItem('refresh_token')
        window.location.href = '/login'
        return Promise.reject(refreshError)
      } finally {
        isRefreshing = false
      }
    }

    return Promise.reject(error)
  },
)

// ─── Auth API ────────────────────────────────────────────────────────────────
export const authEndpoints = {
  register: (data: { name: string; email: string; password: string; org_name?: string }) =>
    authApi.post<TokenResponse>('/register', data),
  login: (data: { email: string; password: string }) =>
    authApi.post<TokenResponse>('/login', data),
  me: () =>
    authApi.get<UserInfo>('/me', {
      headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` },
    }),
}

// ─── Dashboard ───────────────────────────────────────────────────────────────
export const dashboardApi = {
  get: () => api.get<DashboardData>('/dashboard'),
}

// ─── Targets ─────────────────────────────────────────────────────────────────
export const targetsApi = {
  list: () => api.get<Target[]>('/targets'),
  get: (id: string) => api.get<Target>(`/targets/${id}`),
  create: (data: { url: string; name: string; tags?: string[]; schedule?: string | null }) =>
    api.post<Target>('/targets', data),
  update: (id: string, data: { url: string; name: string; tags?: string[]; schedule?: string | null }) =>
    api.put<Target>(`/targets/${id}`, data),
  delete: (id: string) => api.delete(`/targets/${id}`),
  scans: (id: string) => api.get<ScanSummary[]>(`/targets/${id}/scans`),
  findings: (id: string) => api.get<Finding[]>(`/targets/${id}/findings`),
}

// ─── Scans ───────────────────────────────────────────────────────────────────
export const scansApi = {
  list: () => api.get<ScanSummary[]>('/scan'),
  get: (id: string) => api.get<ScanResult>(`/scan/${id}`),
  diff: (id: string) => api.get<ScanDiff>(`/scan/${id}/diff`),
  start: (data: { target_url: string; tools: string[]; scan_mode: 'full' | 'quick'; schedule?: string }) =>
    api.post<{ scan_id: string; target: string; poll_url: string }>('/scan', data),
}

// ─── Findings ────────────────────────────────────────────────────────────────
export const findingsApi = {
  list: (params?: FindingsFilter) => api.get<Finding[]>('/findings', { params }),
  updateStatus: (id: string, data: { status: string; note?: string }) =>
    api.patch<Finding>(`/findings/${id}/status`, data),
  history: (id: string) => api.get<StatusHistory[]>(`/findings/${id}/history`),
}

// ─── Reports ─────────────────────────────────────────────────────────────────
export const reportsApi = {
  markdown: (id: string) => api.get<string>(`/report/${id}`, { responseType: 'text' }),
  pdf: (id: string) =>
    api.get(`/report/${id}/pdf`, { responseType: 'blob' }),
}

// ─── Posture ─────────────────────────────────────────────────────────────────
export const postureApi = {
  trend: (params?: { target_id?: string; limit?: number }) =>
    api.get<PostureTrendPoint[]>('/posture/trend', { params }),
}

// ─── Org ─────────────────────────────────────────────────────────────────────
export const orgApi = {
  me: () => api.get<OrgInfo>('/orgs/me'),
}

// ─── Reachability ─────────────────────────────────────────────────────────────
export interface ReachabilityResult {
  finding_id: string
  path: string
  method: string
  exposure_level: 'public' | 'authenticated' | 'admin' | 'api' | 'unknown'
  requires_auth: boolean
  is_api_endpoint: boolean
  is_public: boolean
  risk_multiplier: number
  rationale: string
}

export const reachabilityApi = {
  forScan: (scanId: string) => api.get<ReachabilityResult[]>(`/scan/${scanId}/reachability`),
}

// ─── Remediation ──────────────────────────────────────────────────────────────
export interface RemediationSnippet {
  stack: string
  language: string
  label: string
  code: string
}

export interface RemediationTemplate {
  id: string
  title: string
  description: string
  effort: string
  owasp_refs: string[]
  cwe_refs: number[]
  snippets: RemediationSnippet[]
}

export const remediationApi = {
  forFinding: (findingId: string) => api.get<RemediationTemplate[]>(`/findings/${findingId}/remediation`),
  templates: () => api.get<{ id: string; title: string; effort: string; stacks: string[] }[]>('/remediation/templates'),
}

// ─── CI/CD Templates ──────────────────────────────────────────────────────────
export interface CiTemplate {
  provider: string
  label: string
  filename: string
  content: string
}

export const ciApi = {
  list: () => api.get<{ provider: string; label: string; file: string }[]>('/ci/templates'),
  get: (provider: string) => api.get<CiTemplate>(`/ci/templates/${provider}`),
}

// ─── EPSS / KEV ───────────────────────────────────────────────────────────────
export interface EpssResult {
  cve_id: string
  epss_score: number | null    // 0-1 probability
  percentile: number | null
  in_kev: boolean
  kev_due_date: string | null
  risk_level: 'critical' | 'high' | 'medium' | 'low' | 'none'
}

export interface AspmCoverage {
  dast: boolean
  sast: boolean
  sca: boolean
  iac: boolean
  tools_used: string[]
}

export const epssApi = {
  forFinding: (findingId: string) => api.get<EpssResult>(`/findings/${findingId}/epss`),
  forScan: (scanId: string) => api.get<EpssResult[]>(`/scan/${scanId}/epss`),
}

export const aspmApi = {
  coverage: (scanId: string) => api.get<AspmCoverage>(`/scan/${scanId}/aspm-coverage`),
}

export default api
