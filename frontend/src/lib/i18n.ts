// Simple i18n dictionary — all UI strings in one place
// Replace values or add locales as needed

const en = {
  // Nav
  'nav.dashboard': 'Dashboard',
  'nav.targets': 'Targets',
  'nav.scans': 'Scans',
  'nav.findings': 'Findings',
  'nav.reports': 'Reports',
  'nav.settings': 'Settings',
  'nav.pricing': 'Pricing',

  // Auth
  'auth.login': 'Sign In',
  'auth.register': 'Create Account',
  'auth.logout': 'Log Out',
  'auth.email': 'Email',
  'auth.password': 'Password',
  'auth.name': 'Full Name',
  'auth.org_name': 'Organization Name',
  'auth.login_cta': 'Already have an account? Sign in',
  'auth.register_cta': "Don't have an account? Sign up",

  // Dashboard
  'dashboard.title': 'Dashboard',
  'dashboard.total_targets': 'Total Targets',
  'dashboard.total_scans': 'Total Scans',
  'dashboard.critical': 'Critical',
  'dashboard.high': 'High',
  'dashboard.medium': 'Medium',
  'dashboard.posture_trend': 'Security Posture Trend',
  'dashboard.severity_breakdown': 'Severity Breakdown',
  'dashboard.recent_scans': 'Recent Scans',
  'dashboard.top_risky': 'Top Risky Targets',

  // Targets
  'targets.title': 'Targets',
  'targets.add': 'Add Target',
  'targets.edit': 'Edit Target',
  'targets.delete': 'Delete Target',
  'targets.url': 'URL',
  'targets.name': 'Name',
  'targets.schedule': 'Schedule',
  'targets.tags': 'Tags',
  'targets.last_scan': 'Last Scan',
  'targets.scan_count': 'Scans',
  'targets.open_findings': 'Open Findings',
  'targets.scan_now': 'Scan Now',
  'targets.empty': 'No targets yet',
  'targets.empty_desc': 'Add your first target to start scanning.',
  'targets.delete_confirm': 'Are you sure you want to delete this target?',
  'targets.delete_desc': 'This will remove the target and all associated scans and findings.',

  // Scans
  'scans.title': 'Scans',
  'scans.id': 'Scan ID',
  'scans.target': 'Target',
  'scans.status': 'Status',
  'scans.tools': 'Tools',
  'scans.findings': 'Findings',
  'scans.new': 'New',
  'scans.regressed': 'Regressed',
  'scans.started': 'Started',
  'scans.duration': 'Duration',
  'scans.mode': 'Mode',
  'scans.empty': 'No scans yet',
  'scans.empty_desc': 'Run your first scan from the Targets page.',

  // Findings
  'findings.title': 'Findings',
  'findings.severity': 'Severity',
  'findings.title_col': 'Title',
  'findings.target': 'Target',
  'findings.host': 'Host',
  'findings.owasp': 'OWASP',
  'findings.status': 'Status',
  'findings.first_seen': 'First Seen',
  'findings.last_seen': 'Last Seen',
  'findings.empty': 'No findings',
  'findings.empty_desc': 'No findings match the current filters.',
  'findings.filter_severity': 'Filter by severity',
  'findings.filter_status': 'Filter by status',
  'findings.search': 'Search findings…',

  // Reports
  'reports.title': 'Reports',
  'reports.download_md': 'Download MD',
  'reports.download_pdf': 'Download PDF',
  'reports.empty': 'No reports yet',
  'reports.empty_desc': 'Complete scans will appear here for download.',

  // Settings
  'settings.title': 'Settings',
  'settings.org': 'Organization',
  'settings.plan': 'Plan',
  'settings.api_key': 'API Key',
  'settings.quota': 'Scan Quota',
  'settings.user': 'Your Account',
  'settings.upgrade': 'Upgrade Plan',

  // Pricing
  'pricing.title': 'Pricing',
  'pricing.free': 'Free',
  'pricing.pro': 'Pro',
  'pricing.enterprise': 'Enterprise',
  'pricing.get_started': 'Get Started',
  'pricing.contact_sales': 'Contact Sales',

  // Common
  'common.loading': 'Loading…',
  'common.save': 'Save',
  'common.cancel': 'Cancel',
  'common.delete': 'Delete',
  'common.edit': 'Edit',
  'common.confirm': 'Confirm',
  'common.close': 'Close',
  'common.submit': 'Submit',
  'common.search': 'Search',
  'common.filter': 'Filter',
  'common.all': 'All',
  'common.none': 'None',
  'common.yes': 'Yes',
  'common.no': 'No',
  'common.or': 'or',
  'common.and': 'and',
  'common.per_month': '/mo',
  'common.error': 'Something went wrong',
  'common.retry': 'Retry',
  'common.actions': 'Actions',

  // Toasts
  'toast.scan_started': 'Scan started successfully',
  'toast.scan_failed': 'Failed to start scan',
  'toast.target_created': 'Target created',
  'toast.target_updated': 'Target updated',
  'toast.target_deleted': 'Target deleted',
  'toast.finding_updated': 'Finding status updated',
  'toast.error': 'An error occurred',
  'toast.copied': 'Copied to clipboard',
} as const

type I18nKey = keyof typeof en

export function t(key: I18nKey, replacements?: Record<string, string | number>): string {
  let value: string = en[key] ?? key
  if (replacements) {
    for (const [k, v] of Object.entries(replacements)) {
      value = value.replace(`{{${k}}}`, String(v))
    }
  }
  return value
}
