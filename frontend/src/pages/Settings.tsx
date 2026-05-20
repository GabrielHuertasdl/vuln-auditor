import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { orgApi, ciApi, type CiTemplate } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { formatDate } from '@/lib/utils'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { useToast } from '@/hooks/useToast'
import { t } from '@/lib/i18n'

type BadgeVariant = 'default' | 'secondary' | 'outline' | 'success' | 'warning' | 'destructive' | 'info' | 'purple' | 'muted'

const PLAN_COLORS: Record<string, BadgeVariant> = {
  free: 'muted',
  pro: 'info',
  enterprise: 'purple',
}

const CI_PROVIDERS = [
  { id: 'github-actions', label: 'GitHub Actions', icon: '🐙' },
  { id: 'gitlab-ci',      label: 'GitLab CI',      icon: '🦊' },
  { id: 'jenkins',        label: 'Jenkins',         icon: '☕' },
  { id: 'circleci',       label: 'CircleCI',        icon: '⭕' },
]

function CiTemplateViewer() {
  const [selected, setSelected] = useState('github-actions')
  const { toast } = useToast()

  const { data, isLoading } = useQuery({
    queryKey: ['ci-template', selected],
    queryFn: () => ciApi.get(selected).then((r) => r.data),
  })

  const copy = () => {
    if (data?.content) {
      navigator.clipboard.writeText(data.content).catch(() => {})
      toast('Template copied to clipboard', 'success')
    }
  }

  const download = () => {
    if (!data) return
    const blob = new Blob([data.content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = data.filename
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-3">
      <div className="flex gap-2 flex-wrap">
        {CI_PROVIDERS.map((p) => (
          <button
            key={p.id}
            onClick={() => setSelected(p.id)}
            className={`flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-sm font-medium transition-colors ${
              selected === p.id
                ? 'border-primary bg-primary/10 text-primary'
                : 'border-border bg-card hover:border-primary/50'
            }`}
          >
            <span>{p.icon}</span>
            {p.label}
          </button>
        ))}
      </div>

      {isLoading ? (
        <div className="h-64 rounded-lg bg-muted animate-shimmer" />
      ) : data ? (
        <div className="relative">
          <pre className="max-h-96 overflow-auto rounded-lg border border-border bg-zinc-950 p-4 text-xs text-green-400 font-mono leading-relaxed">
            {data.content}
          </pre>
          <div className="absolute top-2 right-2 flex gap-1.5">
            <Button size="sm" variant="outline" onClick={copy} className="h-7 text-xs bg-zinc-900 border-zinc-700 text-zinc-300 hover:bg-zinc-800">
              Copy
            </Button>
            <Button size="sm" variant="outline" onClick={download} className="h-7 text-xs bg-zinc-900 border-zinc-700 text-zinc-300 hover:bg-zinc-800">
              Download
            </Button>
          </div>
        </div>
      ) : null}

      <div className="rounded-lg border border-border bg-muted/30 p-3 text-xs text-muted-foreground space-y-1">
        <p className="font-medium text-foreground">Required secrets / variables:</p>
        <p><code className="bg-muted rounded px-1">VULNAUDITOR_API_KEY</code> — Your org API key (from above)</p>
        <p><code className="bg-muted rounded px-1">VULNAUDITOR_URL</code> — Your VulnAuditor instance URL</p>
        <p><code className="bg-muted rounded px-1">SCAN_TARGET_URL</code> — URL to scan (e.g. staging environment)</p>
      </div>
    </div>
  )
}

export default function Settings() {
  const { user } = useAuth()
  const navigate = useNavigate()
  const { toast } = useToast()
  const [apiKeyRevealed, setApiKeyRevealed] = useState(false)

  const { data: org } = useQuery({
    queryKey: ['org', 'me'],
    queryFn: () => orgApi.me().then((r) => r.data),
  })

  const quotaPercent = org
    ? Math.min(100, (org.scans_this_month / org.scan_quota) * 100)
    : 0

  const copyApiKey = () => {
    navigator.clipboard.writeText('va_••••••••••••••••').catch(() => {})
    toast(t('toast.copied'), 'success')
  }

  return (
    <div className="space-y-6 max-w-3xl">
      {/* Org card */}
      <Card>
        <CardHeader>
          <CardTitle>{t('settings.org')}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {org ? (
            <>
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">{t('settings.org')}</p>
                  <p className="text-lg font-semibold">{org.name}</p>
                </div>
                <Badge variant={PLAN_COLORS[org.plan] ?? 'default'}>
                  {org.plan.toUpperCase()}
                </Badge>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <p className="text-sm text-muted-foreground">{t('settings.quota')}</p>
                  <p className="text-sm font-medium">
                    {org.scans_this_month} / {org.scan_quota} scans
                  </p>
                </div>
                <div className="h-2 w-full rounded-full bg-muted overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all ${
                      quotaPercent > 80 ? 'bg-red-500' : 'bg-primary'
                    }`}
                    style={{ width: `${quotaPercent}%` }}
                  />
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  Resets {formatDate(org.quota_reset_at)}
                </p>
              </div>

              <div className="rounded-lg border border-border p-4 bg-muted/30">
                <p className="text-sm font-medium mb-1">Organization since</p>
                <p className="text-sm text-muted-foreground">{formatDate(org.created_at)}</p>
              </div>
            </>
          ) : (
            <div className="space-y-3">
              <div className="h-4 w-1/3 rounded bg-muted animate-shimmer" />
              <div className="h-2 w-full rounded bg-muted animate-shimmer" />
            </div>
          )}

          {/* Upgrade CTA */}
          {org?.plan === 'free' && (
            <div className="rounded-xl border border-primary/30 bg-primary/5 p-4">
              <p className="text-sm font-semibold text-primary">Upgrade to Pro</p>
              <p className="text-xs text-muted-foreground mt-0.5 mb-3">
                Get unlimited scans, AI triage, and PDF reports.
              </p>
              <Button size="sm" onClick={() => navigate('/pricing')}>
                {t('settings.upgrade')} →
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {/* API Key */}
      <Card>
        <CardHeader>
          <CardTitle>{t('settings.api_key')}</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground mb-3">
            Use this key to authenticate API requests directly.
          </p>
          <div className="flex items-center gap-2">
            <code className="flex-1 rounded-lg border border-border bg-muted px-3 py-2 text-sm font-mono">
              {apiKeyRevealed ? 'va_sk_live_example_key_here_replace_me' : 'va_••••••••••••••••••••••••••••••••'}
            </code>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setApiKeyRevealed((v) => !v)}
            >
              {apiKeyRevealed ? 'Hide' : 'Reveal'}
            </Button>
            <Button variant="outline" size="sm" onClick={copyApiKey}>
              Copy
            </Button>
          </div>
          <p className="mt-2 text-xs text-muted-foreground">
            Pass as <code className="rounded bg-muted px-1">X-API-Key</code> header or{' '}
            <code className="rounded bg-muted px-1">Authorization: Bearer</code>.
          </p>
          <Button variant="outline" size="sm" className="mt-3" onClick={() => toast('API key regeneration coming soon', 'info')}>
            Regenerate Key
          </Button>
        </CardContent>
      </Card>

      {/* CI/CD Integration */}
      <Card>
        <CardHeader>
          <CardTitle>CI/CD Integration</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground mb-4">
            Add a security gate to your pipeline. The scan fails if new critical/high findings are introduced.
          </p>
          <CiTemplateViewer />
        </CardContent>
      </Card>

      {/* User info */}
      {user && (
        <Card>
          <CardHeader>
            <CardTitle>{t('settings.user')}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-4">
              <div className="flex h-14 w-14 items-center justify-center rounded-full bg-primary/20 text-xl font-bold text-primary">
                {user.name.charAt(0).toUpperCase()}
              </div>
              <div className="flex-1">
                <p className="font-semibold">{user.name}</p>
                <p className="text-sm text-muted-foreground">{user.email}</p>
                <div className="mt-1 flex gap-1.5">
                  <Badge variant="outline" className="text-xs capitalize">{user.role}</Badge>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
