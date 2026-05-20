import React from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '@/lib/auth'
import { Button } from '@/components/ui/Button'
import { t } from '@/lib/i18n'

interface PlanFeature {
  text: string
  included: boolean
}

interface Plan {
  name: string
  price: string
  description: string
  features: PlanFeature[]
  cta: string
  highlighted?: boolean
  badge?: string
}

const plans: Plan[] = [
  {
    name: t('pricing.free'),
    price: '$0',
    description: 'Perfect for individuals and small projects.',
    features: [
      { text: '1 target', included: true },
      { text: '10 scans/month', included: true },
      { text: 'DAST scanning (ZAP + Nikto)', included: true },
      { text: 'Basic findings report', included: true },
      { text: 'Community support', included: true },
      { text: 'AI triage', included: false },
      { text: 'PDF reports', included: false },
      { text: 'Scheduled scans', included: false },
      { text: 'SAST + IaC scanning', included: false },
      { text: 'Team RBAC', included: false },
    ],
    cta: t('pricing.get_started'),
  },
  {
    name: t('pricing.pro'),
    price: '$49',
    description: 'For growing teams that need full ASPM coverage.',
    features: [
      { text: '10 targets', included: true },
      { text: 'Unlimited scans', included: true },
      { text: 'DAST scanning (ZAP + Nikto + Nmap)', included: true },
      { text: 'AI-powered triage & mitigation', included: true },
      { text: 'PDF reports', included: true },
      { text: 'Scheduled scans (daily/weekly/monthly)', included: true },
      { text: 'Email support', included: true },
      { text: 'Posture trend analytics', included: true },
      { text: 'SAST + IaC scanning', included: false },
      { text: 'Team RBAC & SSO', included: false },
    ],
    cta: t('pricing.get_started'),
    highlighted: true,
    badge: 'Most Popular',
  },
  {
    name: t('pricing.enterprise'),
    price: '$499',
    description: 'For organizations that need enterprise-grade security.',
    features: [
      { text: 'Unlimited targets', included: true },
      { text: 'Unlimited scans', included: true },
      { text: 'Full DAST stack', included: true },
      { text: 'SAST + IaC + Cloud scanning', included: true },
      { text: 'AI triage & mitigation', included: true },
      { text: 'PDF + custom reports', included: true },
      { text: 'Team RBAC', included: true },
      { text: 'SSO (SAML/OIDC)', included: true },
      { text: 'SLA + dedicated support', included: true },
      { text: 'On-premise deployment', included: true },
    ],
    cta: t('pricing.contact_sales'),
  },
]

function CheckIcon({ included }: { included: boolean }) {
  if (included) {
    return (
      <svg className="h-4 w-4 text-green-500 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
        <path d="M20 6 9 17l-5-5" />
      </svg>
    )
  }
  return (
    <svg className="h-4 w-4 text-muted-foreground/40 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M18 6 6 18M6 6l12 12" />
    </svg>
  )
}

export default function Pricing() {
  const navigate = useNavigate()
  const { isAuthenticated } = useAuth()

  const handleCta = (plan: Plan) => {
    if (plan.cta === t('pricing.contact_sales')) {
      window.open('mailto:sales@vulnauditor.com', '_blank')
    } else {
      navigate(isAuthenticated ? '/settings' : '/register')
    }
  }

  return (
    <div className="space-y-8">
      {/* Hero */}
      <div className="text-center py-4">
        <h1 className="text-3xl font-bold">{t('pricing.title')}</h1>
        <p className="mt-2 text-muted-foreground max-w-xl mx-auto">
          Start free, scale as you grow. No credit card required for the Free plan.
        </p>
      </div>

      {/* Plans grid */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {plans.map((plan) => (
          <div
            key={plan.name}
            className={`relative flex flex-col rounded-2xl border ${
              plan.highlighted
                ? 'border-primary shadow-lg shadow-primary/10 bg-card'
                : 'border-border bg-card'
            } p-6`}
          >
            {plan.badge && (
              <div className="absolute -top-3 left-1/2 -translate-x-1/2">
                <span className="rounded-full bg-primary px-3 py-1 text-xs font-semibold text-primary-foreground">
                  {plan.badge}
                </span>
              </div>
            )}

            <div className="mb-6">
              <h2 className="text-lg font-semibold">{plan.name}</h2>
              <div className="mt-2 flex items-baseline gap-1">
                <span className="text-4xl font-bold">{plan.price}</span>
                <span className="text-muted-foreground">{t('common.per_month')}</span>
              </div>
              <p className="mt-2 text-sm text-muted-foreground">{plan.description}</p>
            </div>

            <ul className="flex-1 space-y-3 mb-8">
              {plan.features.map((feature) => (
                <li key={feature.text} className="flex items-center gap-2.5">
                  <CheckIcon included={feature.included} />
                  <span
                    className={`text-sm ${
                      feature.included ? 'text-foreground' : 'text-muted-foreground/60'
                    }`}
                  >
                    {feature.text}
                  </span>
                </li>
              ))}
            </ul>

            <Button
              variant={plan.highlighted ? 'default' : 'outline'}
              className="w-full"
              onClick={() => handleCta(plan)}
            >
              {plan.cta}
            </Button>
          </div>
        ))}
      </div>

      {/* FAQ / trust */}
      <div className="rounded-2xl border border-border bg-card p-8">
        <h2 className="text-xl font-semibold mb-4">Frequently Asked Questions</h2>
        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2">
          {[
            {
              q: 'Can I upgrade or downgrade at any time?',
              a: 'Yes. Plan changes take effect immediately and are prorated.',
            },
            {
              q: 'What scanning tools are included?',
              a: 'We integrate OWASP ZAP, Nikto, and Nmap for DAST. Enterprise adds SAST and IaC analysis.',
            },
            {
              q: 'Is my data secure?',
              a: 'All data is encrypted at rest and in transit. We are SOC 2 Type II certified.',
            },
            {
              q: 'Do you offer a trial of Pro?',
              a: 'Yes — email us for a 14-day Pro trial with no credit card required.',
            },
          ].map(({ q, a }) => (
            <div key={q}>
              <p className="font-medium text-sm">{q}</p>
              <p className="text-sm text-muted-foreground mt-1">{a}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
