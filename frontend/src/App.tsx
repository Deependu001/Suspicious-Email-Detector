import { useCallback, useEffect, useState } from 'react'
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  ArrowRight,
  ArrowUpRight,
  Check,
  CheckCircle2,
  Clock3,
  Copy,
  Cpu,
  Database,
  Download,
  ExternalLink,
  FileCode,
  FileSearch,
  FileText,
  Fingerprint,
  History,
  Info,
  Layers,
  LayoutDashboard,
  Mail,
  Menu,
  Network,
  Play,
  Radio,
  RefreshCw,
  Search,
  Server,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  Terminal,
  Trash2,
  X,
  Zap,
} from 'lucide-react'
import './App.css'
import {
  getReplyToPresentation,
  getRiskPresentation,
  getRuleStatusLabel,
} from './presentation'

type Page = 'Overview' | 'Email Analysis' | 'Analysis History' | 'Settings'
type ForensicTab = 'explanations' | 'headers' | 'urls' | 'attachments' | 'json'
type HistoryFilter = 'all' | 'critical' | 'warn' | 'safe'

interface EmailAttachment {
  filename?: string | null
  content_type?: string | null
  size_bytes?: number | null
}

interface EmailData {
  sender?: string | null
  recipients?: string[]
  cc?: string[]
  bcc?: string[]
  subject?: string | null
  date?: string | null
  reply_to?: string | null
  return_path?: string | null
  urls?: string[]
  attachments?: EmailAttachment[]
  headers?: Record<string, string[]>
  authentication?: {
    authentication_results?: string[]
    received_spf?: string[]
    dkim_signature?: string[]
  }
}

interface URLAnalysis {
  original_url: string
  normalized_url: string
  scheme?: string | null
  hostname?: string | null
  port?: number | null
  domain?: string | null
  registered_domain?: string | null
  url_length?: number
  has_ip_address: boolean
  has_unusual_port: boolean
  has_suspicious_characters: boolean
  has_encoding: boolean
  suspicious_indicators: string[]
}

interface HeaderAnalysis {
  from_present: boolean
  reply_to_present: boolean
  return_path_present: boolean
  from_domain?: string | null
  reply_to_domain?: string | null
  return_path_domain?: string | null
  from_reply_to_domain_mismatch: boolean
  from_return_path_domain_mismatch: boolean
  received_header_count: number
  authentication_results_present: boolean
  received_spf_present: boolean
  dkim_signature_present: boolean
  spf_statuses: string[]
  dkim_statuses: string[]
  dmarc_statuses: string[]
}

interface AttachmentItem {
  filename?: string | null
  extension?: string | null
  content_type?: string | null
  size_bytes?: number | null
  is_double_extension: boolean
  is_potentially_dangerous_extension: boolean
  is_filename_mime_mismatch: boolean
}

interface AttachmentAnalysis {
  attachment_present: boolean
  attachment_count: number
  attachments: AttachmentItem[]
  dangerous_extensions: string[]
  double_extensions: string[]
  mime_mismatches: string[]
  unusual_filenames: string[]
}

interface RuleResult {
  rule_id: string
  description: string
  triggered: boolean
  observations: string[]
}

interface Explanation {
  rule_id: string
  category: string
  message: string
  observations: string[]
}

interface PipelineResult {
  email: EmailData
  ml_phishing_probability: number
  url_analyses: URLAnalysis[]
  header_analysis: HeaderAnalysis
  attachment_analysis: AttachmentAnalysis
  rule_results: RuleResult[]
  risk_score: number
  explainability: {
    risk_score: number
    ml_phishing_probability: number
    explanations: Explanation[]
  }
}

interface HistorySummary {
  id: string
  analyzed_at: string
  sender?: string | null
  subject?: string | null
  risk_score: number
  ml_phishing_probability: number
}

interface HistoryRecord extends HistorySummary {
  result: Record<string, unknown>
}

interface HistoryResponse {
  items: HistorySummary[]
  total: number
}

interface EmailPreset {
  id: string
  title: string
  badge: string
  badgeType: 'critical' | 'warn' | 'safe'
  summary: string
  payload: string
}

const DEFAULT_API_URL = 'http://127.0.0.1:8000'

const SAMPLE_PRESETS: EmailPreset[] = [
  {
    id: 'preset-m365',
    title: 'M365 Credential Phishing',
    badge: 'Critical Threat',
    badgeType: 'critical',
    summary: 'Deceptive suspension warning with IP link host and mismatched domain',
    payload: `From: Microsoft Security Team <account-verify@security-alerts-office365.com>
To: target.user@enterprise.corp
Subject: CRITICAL: Immediate Verification Required for Microsoft 365 Account
Date: Sun, 25 Oct 2026 14:12:00 +0000
Reply-To: security-drop@credential-harvest-portal.net
Return-Path: bounce@suspicious-relay-server.org
Authentication-Results: spf=fail (sender IP is 198.51.100.24) smtp.mailfrom=suspicious-relay-server.org; dkim=fail header.d=security-alerts-office365.com; dmarc=fail
Received-SPF: fail (domain of suspicious-relay-server.org does not designate 198.51.100.24 as permitted sender)

Dear Customer,

Your Microsoft 365 enterprise account access has been temporarily suspended due to multiple unauthorized login attempts originating from an unrecognized IP address (Moscow, Russian Federation).

To restore your services and prevent permanent account decommissioning, you must authenticate your credentials immediately:
http://192.168.1.100:8080/login?auth_token=8f9a2b&redirect=https%3A%2F%2Flogin.microsoftonline.com

Failure to complete this verification within 4 hours will result in permanent deletion of your mailbox and cloud storage data.

Reference Incident Ticket: SEC-99420-EXP
Microsoft Global Security Operations Center`,
  },
  {
    id: 'preset-spear',
    title: 'CEO Urgent Wire Transfer',
    badge: 'High Threat',
    badgeType: 'critical',
    summary: 'Spear-phishing wire transfer request with deceptive reply-to routing',
    payload: `From: Jonathan Vance - Chief Executive Officer <ceo@enterprise-holdings.co>
To: finance.controller@enterprise.corp
Subject: Urgent: Confidential Acquisition Wire Payment Authorization Required
Date: Sun, 25 Oct 2026 15:45:00 +0000
Reply-To: executive.direct.wire@offshore-escrow-routing.com
Return-Path: daemon@untrusted-mailserver.net

Attention Finance Team,

I am currently in closed-door discussions regarding our confidential European acquisition. Due to non-disclosure restrictions, I cannot discuss this over standard phone channels.

Please review the attached closing term sheet and initiate an immediate confidential wire transfer of $185,000 to the escrow account details provided in the link below:
http://secure-escrow-routing.com:8443/transfer/verify?invoice_id=99281%2Foverride

This is time-sensitive and needs to be settled before close of business today. Please confirm receipt and transaction reference code directly to this email address.

Jonathan Vance
President & Chief Executive Officer
Enterprise Holdings Group`,
  },
  {
    id: 'preset-attachment',
    title: 'Weaponized Invoice (.pdf.exe)',
    badge: 'Suspicious Payload',
    badgeType: 'warn',
    summary: 'Phishing bill notification containing double-extension executable attachment',
    payload: `From: Accounts Payable Billing <billing-notice@global-vendor-network.net>
To: accounts@enterprise.corp
Subject: Overdue Invoice Notification: Ref #INV-882049 Past Due
Date: Sun, 25 Oct 2026 11:30:00 +0000
Reply-To: accounts@global-vendor-network.net
Content-Type: multipart/mixed; boundary="====BOUNDARY_123456789===="

--====BOUNDARY_123456789====
Content-Type: text/plain; charset="utf-8"

Dear Accounts Payable,

Attached is the final reminder for outstanding Invoice #INV-882049 in the amount of $4,820.00. 
Your account is subject to late penalties if payment is not scheduled immediately.

Please open the attached PDF statement to inspect remittance banking coordinates:
Attachment: Remittance_Invoice_Receipt.pdf.exe

Thank you for your prompt cooperation.
Global Vendor Billing Solutions LLC
--====BOUNDARY_123456789====
Content-Type: application/octet-stream; name="Remittance_Invoice_Receipt.pdf.exe"
Content-Disposition: attachment; filename="Remittance_Invoice_Receipt.pdf.exe"

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcAAAAA==
--====BOUNDARY_123456789====--`,
  },
  {
    id: 'preset-legit',
    title: 'Enterprise IT Notice',
    badge: 'Clean / Low Risk',
    badgeType: 'safe',
    summary: 'Legitimate internal scheduled maintenance notice with valid domains',
    payload: `From: IT Security Awareness <security@enterprise.corp>
To: all-staff@enterprise.corp
Subject: Scheduled Infrastructure Maintenance: Sunday 22:00 UTC
Date: Sun, 25 Oct 2026 09:00:00 +0000
Reply-To: security@enterprise.corp
Return-Path: security@enterprise.corp
Authentication-Results: spf=pass (sender IP is 192.0.2.1) smtp.mailfrom=enterprise.corp; dkim=pass header.d=enterprise.corp; dmarc=pass
Received-SPF: pass (domain of enterprise.corp designates 192.0.2.1 as permitted sender)

Hi Team,

This is an advance notice that the enterprise identity gateway will undergo routine maintenance this Sunday starting at 22:00 UTC. 

Expected impact:
- Single Sign-On (SSO) may experience brief intermittent reconnects between 22:00 and 22:30 UTC.
- Email and chat services will remain operational without downtime.

No action is required on your part. For questions or support, please submit a ticket through the internal IT service desk portal at https://helpdesk.enterprise.corp/maintenance.

Best regards,
Enterprise Information Security & Infrastructure Operations`,
  },
]

const navigation = [
  { label: 'Overview' as Page, icon: LayoutDashboard },
  { label: 'Email Analysis' as Page, icon: FileSearch },
  { label: 'Settings' as Page, icon: Settings },
]

function getStoredApiUrl(): string {
  return (
    localStorage.getItem('sentinel-api-url')?.replace(/\/+$/, '') ||
    DEFAULT_API_URL
  )
}

function formatPercent(value: number): string {
  const percentage = value <= 1 ? value * 100 : value
  return `${percentage.toFixed(1)}%`
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

function isPipelineResult(value: unknown): value is PipelineResult {
  if (!isRecord(value)) return false

  return (
    typeof value.risk_score === 'number' &&
    Number.isFinite(value.risk_score) &&
    typeof value.ml_phishing_probability === 'number' &&
    Number.isFinite(value.ml_phishing_probability) &&
    isRecord(value.email) &&
    Array.isArray(value.url_analyses) &&
    isRecord(value.header_analysis) &&
    isRecord(value.attachment_analysis) &&
    Array.isArray(value.attachment_analysis.attachments) &&
    Array.isArray(value.rule_results) &&
    isRecord(value.explainability) &&
    Array.isArray(value.explainability.explanations)
  )
}

function isHistorySummary(value: unknown): value is HistorySummary {
  return (
    isRecord(value) &&
    typeof value.id === 'string' &&
    typeof value.analyzed_at === 'string' &&
    typeof value.risk_score === 'number' &&
    Number.isFinite(value.risk_score) &&
    typeof value.ml_phishing_probability === 'number' &&
    Number.isFinite(value.ml_phishing_probability)
  )
}

function isHistoryResponse(value: unknown): value is HistoryResponse {
  return (
    isRecord(value) &&
    Array.isArray(value.items) &&
    value.items.every(isHistorySummary) &&
    typeof value.total === 'number' &&
    Number.isFinite(value.total)
  )
}

function isHistoryRecord(value: unknown): value is HistoryRecord {
  return isHistorySummary(value) && isRecord(value) && isRecord(value.result)
}

function formatDate(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return value
  }
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

function getScoreSeverity(score: number): {
  label: string
  colorClass: string
  bgClass: string
  glowClass: string
  badgeClass: string
  strokeColor: string
} {
  const risk = getRiskPresentation(score)

  if (risk.band === 'critical') {
    return {
      label: risk.label,
      colorClass: 'text-threat-critical',
      bgClass: 'sev-critical',
      glowClass: 'kpi-accent-red',
      badgeClass: 'chip-danger',
      strokeColor: '#ef4444',
    }
  }
  if (risk.band === 'high') {
    return {
      label: risk.label,
      colorClass: 'text-threat-high',
      bgClass: 'sev-high',
      glowClass: 'kpi-accent-red',
      badgeClass: 'chip-high',
      strokeColor: '#f97316',
    }
  }
  if (risk.band === 'elevated') {
    return {
      label: risk.label,
      colorClass: 'text-threat-warn',
      bgClass: 'sev-warn',
      glowClass: 'kpi-accent-amber',
      badgeClass: 'chip-warn',
      strokeColor: '#eab308',
    }
  }
  if (risk.band === 'lower') {
    return {
      label: risk.label,
      colorClass: 'text-threat-safe',
      bgClass: 'sev-safe',
      glowClass: 'kpi-accent-green',
      badgeClass: 'chip-safe',
      strokeColor: '#10b981',
    }
  }

  return {
    label: risk.label,
    colorClass: 'text-threat-safe',
    bgClass: 'sev-warn',
    glowClass: 'kpi-accent-amber',
    badgeClass: 'chip-warn',
    strokeColor: '#9a6240',
  }
}

async function readError(response: Response): Promise<string> {
  try {
    const body = await response.json()
    if (typeof body.detail === 'string') {
      return body.detail
    }
    return JSON.stringify(body)
  } catch {
    return `Request failed with HTTP ${response.status}.`
  }
}

function App() {
  const [activePage, setActivePage] = useState<Page>('Overview')
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [rawEmail, setRawEmail] = useState('')
  const [notice, setNotice] = useState<{ text: string; type: 'success' | 'error' | 'info' } | null>(null)
  const [apiUrl, setApiUrl] = useState(getStoredApiUrl)
  const [apiOnline, setApiOnline] = useState(false)
  const [checkingApi, setCheckingApi] = useState(false)
  const [apiLatencyMs, setApiLatencyMs] = useState<number | null>(null)
  const [analyzing, setAnalyzing] = useState(false)
  const [loadingHistory, setLoadingHistory] = useState(false)
  const [result, setResult] = useState<PipelineResult | null>(null)
  const [history, setHistory] = useState<HistorySummary[]>([])
  const [historyTotal, setHistoryTotal] = useState(0)
  const [selectedRecord, setSelectedRecord] = useState<HistoryRecord | null>(null)
  const [historySearch, setHistorySearch] = useState('')
  const [historyFilter, setHistoryFilter] = useState<HistoryFilter>('all')
  const [activeForensicTab, setActiveForensicTab] = useState<ForensicTab>('explanations')
  const [selectedPresetId, setSelectedPresetId] = useState<string | null>(null)
  const [copiedJson, setCopiedJson] = useState(false)

  const baseUrl = apiUrl.trim().replace(/\/+$/, '')

  const checkApi = useCallback(async () => {
    setCheckingApi(true)
    const startTime = performance.now()

    try {
      const response = await fetch(`${baseUrl}/health`, {
        signal: AbortSignal.timeout(5000),
      })

      const endTime = performance.now()
      setApiLatencyMs(Math.round(endTime - startTime))

      if (!response.ok) {
        throw new Error(`Health check returned HTTP ${response.status}.`)
      }

      const body = await response.json()
      if (body.status !== 'healthy') {
        throw new Error('The API did not report a healthy status.')
      }

      setApiOnline(true)
    } catch {
      setApiOnline(false)
      setApiLatencyMs(null)
    } finally {
      setCheckingApi(false)
    }
  }, [baseUrl])

  const loadHistory = useCallback(async () => {
    setLoadingHistory(true)
    try {
      const response = await fetch(`${baseUrl}/history?limit=100`, {
        signal: AbortSignal.timeout(10000),
      })

      if (!response.ok) {
        throw new Error(await readError(response))
      }

      const data: unknown = await response.json()
      if (!isHistoryResponse(data)) {
        throw new Error('The API returned an unexpected history response format.')
      }

      setHistory(data.items)
      setHistoryTotal(data.total)
    } catch (error) {
      setNotice({
        text: `Could not load telemetry audit history: ${error instanceof Error ? error.message : 'Unknown error'}`,
        type: 'error',
      })
    } finally {
      setLoadingHistory(false)
    }
  }, [baseUrl])

  useEffect(() => {
    void checkApi()
  }, [checkApi])

  const navigate = (page: Page) => {
    setActivePage(page)
    setSidebarOpen(false)
    setNotice(null)
  }

  const handleSelectPreset = (preset: EmailPreset) => {
    setSelectedPresetId(preset.id)
    setRawEmail(preset.payload)
    setNotice({
      text: `Loaded preset: "${preset.title}". Ready for automated analysis.`,
      type: 'info',
    })
  }

  const handleAnalyze = async () => {
    if (!rawEmail.trim()) {
      setNotice({
        text: 'Please paste raw RFC 5322 email headers and body or choose a preset payload above.',
        type: 'error',
      })
      return
    }

    if (!apiOnline) {
      setNotice({
        text: 'FastAPI threat detection service is offline. Please verify endpoint connection in Settings.',
        type: 'error',
      })
      await checkApi()
      return
    }

    setAnalyzing(true)
    setNotice(null)
    setResult(null)
    setSelectedRecord(null)

    try {
      const response = await fetch(`${baseUrl}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_email: rawEmail }),
        signal: AbortSignal.timeout(60000),
      })

      if (!response.ok) {
        throw new Error(await readError(response))
      }

      const data: unknown = await response.json()

      if (!isPipelineResult(data)) {
        throw new Error('The API returned an unexpected analysis response format.')
      }

      setResult(data)
      setNotice({
        text: 'Threat inspection completed. Live findings and explainability vectors generated.',
        type: 'success',
      })
      setActivePage('Email Analysis')
    } catch (error) {
      setNotice({
        text: `Analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        type: 'error',
      })
      if (error instanceof TypeError) {
        setApiOnline(false)
      }
    } finally {
      setAnalyzing(false)
    }
  }

  const openHistoryRecord = async (record: HistorySummary) => {
    setNotice(null)
    try {
      const response = await fetch(`${baseUrl}/history/${encodeURIComponent(record.id)}`, {
        signal: AbortSignal.timeout(10000),
      })

      if (!response.ok) {
        throw new Error(await readError(response))
      }

      const data: unknown = await response.json()
      if (!isHistoryRecord(data)) {
        throw new Error('The API returned an unexpected history record format.')
      }

      setSelectedRecord(data)
    } catch (error) {
      setNotice({
        text: `Could not load audit record: ${error instanceof Error ? error.message : 'Unknown error'}`,
        type: 'error',
      })
    }
  }

  const saveApiUrl = async () => {
    const cleanedUrl = apiUrl.trim().replace(/\/+$/, '')
    if (!/^https?:\/\/.+/i.test(cleanedUrl)) {
      setNotice({
        text: 'Please enter a valid HTTP or HTTPS base URL.',
        type: 'error',
      })
      return
    }

    localStorage.setItem('sentinel-api-url', cleanedUrl)
    setApiUrl(cleanedUrl)
    setNotice({
      text: 'API endpoint configured. Pinging service health...',
      type: 'info',
    })
    setApiOnline(false)

    try {
      const response = await fetch(`${cleanedUrl}/health`, {
        signal: AbortSignal.timeout(5000),
      })

      if (!response.ok) {
        throw new Error(`Health check returned HTTP ${response.status}.`)
      }

      const body = await response.json()
      if (body.status !== 'healthy') {
        throw new Error('API reported unhealthy status.')
      }

      setApiOnline(true)
      setNotice({
        text: 'FastAPI threat detection service connected successfully.',
        type: 'success',
      })
    } catch (error) {
      setApiOnline(false)
      setNotice({
        text: `Could not connect to service: ${error instanceof Error ? error.message : 'Connection failed'}`,
        type: 'error',
      })
    }
  }

  const handleCopyJson = (content: unknown) => {
    void navigator.clipboard.writeText(JSON.stringify(content, null, 2))
    setCopiedJson(true)
    setTimeout(() => setCopiedJson(false), 2000)
  }

  const handleExportCsv = () => {
    if (history.length === 0) return
    const headers = ['ID', 'Date', 'Sender', 'Subject', 'Risk Score', 'ML Phishing Probability']
    const rows = history.map((item) => [
      `"${item.id}"`,
      `"${item.analyzed_at}"`,
      `"${(item.sender ?? '').replace(/"/g, '""')}"`,
      `"${(item.subject ?? '').replace(/"/g, '""')}"`,
      item.risk_score.toFixed(2),
      (item.ml_phishing_probability * 100).toFixed(2) + '%',
    ])
    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map((r) => r.join(','))].join('\n')
    const encodedUri = encodeURI(csvContent)
    const link = document.createElement('a')
    link.setAttribute('href', encodedUri)
    link.setAttribute('download', `sentinel_threat_audit_${new Date().toISOString().slice(0, 10)}.csv`)
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
  }

  const handleExportJson = () => {
    if (history.length === 0) return
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(history, null, 2))
    const link = document.createElement('a')
    link.setAttribute('href', dataStr)
    link.setAttribute('download', `sentinel_audit_records_${new Date().toISOString().slice(0, 10)}.json`)
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
  }

  // Filtered History
  const filteredHistory = history.filter((record) => {
    const search = historySearch.toLowerCase()
    const matchesSearch =
      (record.sender ?? '').toLowerCase().includes(search) ||
      (record.subject ?? '').toLowerCase().includes(search) ||
      record.id.toLowerCase().includes(search)

    if (!matchesSearch) return false

    if (historyFilter === 'critical') return record.risk_score >= 65
    if (historyFilter === 'warn') return record.risk_score >= 35 && record.risk_score < 65
    if (historyFilter === 'safe') return record.risk_score < 35
    return true
  })

  // Telemetry Aggregations
  const criticalThreatsCount = history.filter((r) => r.risk_score >= 65).length
  const moderateThreatsCount = history.filter((r) => r.risk_score >= 35 && r.risk_score < 65).length
  const cleanCount = history.filter((r) => r.risk_score < 35).length

  return (
    <div className="soc-shell">
      <div className="soc-grid-overlay" aria-hidden="true" />

      {sidebarOpen && (
        <button
          className="mobile-backdrop"
          aria-label="Close navigation"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* =====================================================================
          SIDEBAR NAVIGATION
          ===================================================================== */}
      <aside className={`soc-sidebar ${sidebarOpen ? 'sidebar-open' : ''}`}>
        <div className="brand-header">
          <div className="brand-wrapper">
            <div className="brand-shield-glow">
              <ShieldCheck size={22} strokeWidth={2.2} />
            </div>
            <div className="brand-titles">
              <div className="brand-name">
                MAIL<span>GUARD</span>
              </div>
              <span className="brand-tagline">Explainable email security</span>
            </div>
          </div>
          <button
            className="mobile-menu-trigger"
            aria-label="Close sidebar"
            onClick={() => setSidebarOpen(false)}
          >
            <X size={18} />
          </button>
        </div>

        <div className="soc-enclave-pill">
          <span className={`enclave-indicator ${apiOnline ? '' : 'enclave-offline'}`} />
          <div className="enclave-info">
            <span className="enclave-label">Active Workspace</span>
            <span className="enclave-value">Local analysis workspace</span>
          </div>
        </div>

        <div className="nav-section-title">Workspace</div>
        <nav className="soc-nav" aria-label="Main navigation">
          {navigation.map(({ label, icon: Icon }) => (
            <button
              key={label}
              className={`soc-nav-item ${activePage === label ? 'active' : ''}`}
              onClick={() => navigate(label)}
            >
              <Icon size={17} strokeWidth={1.9} />
              <span>{label}</span>
              {label === 'Analysis History' && (
                <span className="soc-nav-badge">{apiOnline ? historyTotal : 'OFFLINE'}</span>
              )}
            </button>
          ))}
        </nav>

        <div className="sidebar-engine-section">
          <div className="nav-section-title">Detection Engines</div>
          <div className="engine-telemetry-list">
            <div className="engine-telemetry-item">
              <div className="engine-telemetry-name">
                <Zap size={14} color="#38bdf8" />
                <span>TF-IDF Classifier</span>
              </div>
              <span className={`engine-status-dot ${apiOnline ? '' : 'offline'}`} />
            </div>
            <div className="engine-telemetry-item">
              <div className="engine-telemetry-name">
                <Network size={14} color="#22d3ee" />
                <span>URL Intelligence</span>
              </div>
              <span className={`engine-status-dot ${apiOnline ? '' : 'offline'}`} />
            </div>
            <div className="engine-telemetry-item">
              <div className="engine-telemetry-name">
                <Fingerprint size={14} color="#818cf8" />
                <span>Header & Auth (SPF/DKIM)</span>
              </div>
              <span className={`engine-status-dot ${apiOnline ? '' : 'offline'}`} />
            </div>
            <div className="engine-telemetry-item">
              <div className="engine-telemetry-name">
                <FileCode size={14} color="#f472b6" />
                <span>MIME Attachment Guard</span>
              </div>
              <span className={`engine-status-dot ${apiOnline ? '' : 'offline'}`} />
            </div>
          </div>
        </div>

        <div className="sidebar-spacer" />

        <div className="sidebar-analyst-footer">
          <div className="analyst-avatar">SA</div>
          <div className="analyst-meta">
            <span className="analyst-name">Threat Analyst</span>
            <span className="analyst-role">SecOps Enclave</span>
          </div>
          <button
            className="mobile-menu-trigger"
            aria-label="Settings"
            onClick={() => navigate('Settings')}
          >
            <SlidersHorizontal size={15} />
          </button>
        </div>
      </aside>

      {/* =====================================================================
          MAIN DASHBOARD WORKSPACE
          ===================================================================== */}
      <main className="soc-main">
        {/* Topbar Telemetry Header */}
        <header className="soc-topbar">
          <div className="topbar-left">
            <button
              className="mobile-menu-trigger"
              aria-label="Open navigation menu"
              onClick={() => setSidebarOpen(true)}
            >
              <Menu size={20} />
            </button>
            <div className="soc-breadcrumbs">
              <span className="breadcrumb-path">Email Security</span>
              <span className="breadcrumb-sep">/</span>
              <span className="breadcrumb-active">{activePage}</span>
            </div>
          </div>

          <div className="topbar-right">
            <div className="soc-telemetry-pill">
              <span className={`telemetry-pulse ${apiOnline ? '' : 'offline'}`} />
              <span>{checkingApi ? 'Pinging API...' : apiOnline ? 'FASTAPI LIVE' : 'BACKEND OFFLINE'}</span>
            </div>

            {apiLatencyMs !== null && (
              <div className="topbar-latency">
                <Activity size={13} />
                <span>{apiLatencyMs}ms</span>
              </div>
            )}

            <div className="topbar-divider" />

            <button
              className="topbar-cta-button"
              onClick={() => navigate('Email Analysis')}
            >
              <Play size={13} fill="currentColor" />
              <span>Scan Email</span>
            </button>
          </div>
        </header>

        {/* Content Body Area */}
        <div className="soc-content">
          <div className="page-header-row">
            <div className="page-header-titles">
              <div className="page-eyebrow">
                <span className="eyebrow-dot" /> Explainable Threat Platform
              </div>
              <h1 className="page-title">
                {activePage === 'Overview' && (
                  <>Email <span>Security Analysis</span></>
                )}
                {activePage === 'Email Analysis' && (
                  <>Analyze <span>An Email</span></>
                )}
                {activePage === 'Analysis History' && (
                  <>Analysis <span>History</span></>
                )}
                {activePage === 'Settings' && (
                  <>System <span>Diagnostics & Setup</span></>
                )}
              </h1>
              <p className="page-subtitle">
                {activePage === 'Overview' &&
                  'Understand recent email analyses and the security signals behind every score.'}
                {activePage === 'Email Analysis' &&
                  'Paste a raw email to inspect its headers, URLs, attachments, ML probability, and detection rules.'}
                {activePage === 'Analysis History' &&
                  'Review privacy-conscious summaries of analyses stored in the local SQLite database.'}
                {activePage === 'Settings' &&
                  'Backend API endpoint configuration, latency ping diagnostic, and portfolio architectural specifications.'}
              </p>
            </div>
          </div>

          {/* Global Alert Banner */}
          {notice && (
            <div className={`soc-notification ${notice.type}`} role="status">
              {notice.type === 'error' ? (
                <AlertCircle size={18} />
              ) : notice.type === 'success' ? (
                <CheckCircle2 size={18} />
              ) : (
                <Info size={18} />
              )}
              <span>{notice.text}</span>
              <button
                className="notification-dismiss"
                aria-label="Dismiss notice"
                onClick={() => setNotice(null)}
              >
                <X size={16} />
              </button>
            </div>
          )}

          {/* =================================================================
              VIEW 1: OVERVIEW DASHBOARD
              ================================================================= */}
          {activePage === 'Overview' && (
            <>
              {/* Hero Threat Banner */}
              <section className="soc-hero-banner">
                <div className="hero-left-content">
                  <div className="hero-badge-tag">
                    <Sparkles size={13} /> Real-Time Telemetry Active
                  </div>
                  <h2 className="hero-title">
                    See Beyond The <span>Inbox.</span>
                  </h2>
                  <p className="hero-desc">
                    Defend your perimeter with transparent, explainable threat intelligence. 
                    Sentinel combines logistic regression machine learning with deterministic 
                    heuristic validation to demystify complex phishing payloads.
                  </p>
                  <div className="hero-actions">
                    <button
                      className="btn-primary-glow"
                      onClick={() => navigate('Email Analysis')}
                    >
                      <FileSearch size={16} />
                      Launch Threat Scanner
                    </button>
                    <button
                      className="btn-glass"
                      onClick={() => navigate('Settings')}
                    >
                      <Settings size={16} />
                      Configure API
                    </button>
                  </div>
                </div>

                <div className="hero-radar-container" aria-hidden="true">
                  <div className="radar-circle radar-c1" />
                  <div className="radar-circle radar-c2" />
                  <div className="radar-circle radar-c3" />
                  <div className="radar-sweep" />
                  <div className="radar-shield-core">
                    <ShieldCheck size={28} />
                  </div>
                </div>
              </section>

              {/* Telemetry KPI Cards */}
              <section className="soc-kpi-grid" aria-label="Security Metrics">
                <div className="soc-kpi-card">
                  <div className="kpi-accent-glow kpi-accent-cyan" />
                  <div className="kpi-header">
                    <div className="kpi-icon-pill kpi-icon-cyan">
                      <Mail size={19} />
                    </div>
                    <span className="kpi-tag">TOTAL INGESTION</span>
                  </div>
                  <div className="kpi-label">Audited Emails</div>
                  <div className="kpi-value">{apiOnline ? historyTotal : '—'}</div>
                  <div className="kpi-meta">
                    <Clock3 size={12} />
                    <span>Stored in persistent SQLite database</span>
                  </div>
                </div>

                <div className="soc-kpi-card">
                  <div className="kpi-accent-glow kpi-accent-red" />
                  <div className="kpi-header">
                    <div className="kpi-icon-pill kpi-icon-red">
                      <ShieldAlert size={19} />
                    </div>
                    <span className="kpi-tag">SCORE &ge; 65</span>
                  </div>
                  <div className="kpi-label">Critical / High Threats</div>
                  <div className="kpi-value">{apiOnline ? criticalThreatsCount : '—'}</div>
                  <div className="kpi-meta">
                    <AlertTriangle size={12} color="#f87171" />
                    <span>Weaponized phishing & spoofing</span>
                  </div>
                </div>

                <div className="soc-kpi-card">
                  <div className="kpi-accent-glow kpi-accent-amber" />
                  <div className="kpi-header">
                    <div className="kpi-icon-pill kpi-icon-amber">
                      <AlertCircle size={19} />
                    </div>
                    <span className="kpi-tag">SCORE 35 - 64</span>
                  </div>
                  <div className="kpi-label">Suspicious Inquiries</div>
                  <div className="kpi-value">{apiOnline ? moderateThreatsCount : '—'}</div>
                  <div className="kpi-meta">
                    <Radio size={12} color="#fbbf24" />
                    <span>Unusual ports, domain mismatches</span>
                  </div>
                </div>

                <div className="soc-kpi-card">
                  <div className="kpi-accent-glow kpi-accent-green" />
                  <div className="kpi-header">
                    <div className="kpi-icon-pill kpi-icon-green">
                      <ShieldCheck size={19} />
                    </div>
                    <span className="kpi-tag">SCORE &lt; 35</span>
                  </div>
                  <div className="kpi-label">Clean / Verified</div>
                  <div className="kpi-value">{apiOnline ? cleanCount : '—'}</div>
                  <div className="kpi-meta">
                    <CheckCircle2 size={12} color="#34d399" />
                    <span>Valid authentication headers</span>
                  </div>
                </div>
              </section>

              {/* Two Column Split: Recent Stream & Detection Architecture */}
              <section className="overview-split-grid">
                {/* Recent Detections Stream */}
                <div className="soc-glass-panel">
                  <div className="panel-header-row">
                    <div className="panel-title-wrap">
                      <Clock3 size={18} />
                      <h2 className="panel-title">Recent Telemetry Stream</h2>
                    </div>
                    <button
                      className="panel-action-btn"
                      onClick={() => navigate('Analysis History')}
                    >
                      Audit Trail <ArrowRight size={14} />
                    </button>
                  </div>

                  {history.length === 0 ? (
                    <div style={{ textAlign: 'center', padding: '36px 0', color: 'var(--text-muted)' }}>
                      <FileSearch size={32} style={{ margin: '0 auto 12px', display: 'block', opacity: 0.5 }} />
                      <strong style={{ display: 'block', color: 'var(--text-secondary)' }}>
                        {apiOnline ? 'No telemetry events recorded yet' : 'FastAPI Service Offline'}
                      </strong>
                      <span style={{ fontSize: '12px' }}>
                        {apiOnline
                          ? 'Scan an email or use a preset to generate forensic telemetry.'
                          : 'Please start the FastAPI service to stream records.'}
                      </span>
                    </div>
                  ) : (
                    <div className="recent-scans-list">
                      {history.slice(0, 5).map((record) => {
                        const sev = getScoreSeverity(record.risk_score)
                        return (
                          <button
                            key={record.id}
                            className="recent-scan-item"
                            onClick={() => {
                              navigate('Analysis History')
                              void openHistoryRecord(record)
                            }}
                          >
                            <span className={`scan-severity-indicator ${sev.bgClass}`} />
                            <div className="scan-info-block">
                              <span className="scan-subject-title">{record.subject || '(Untitled Email)'}</span>
                              <span className="scan-sender-text">{record.sender || 'Unknown Sender'}</span>
                            </div>
                            <span
                              className={`scan-score-badge ${
                                record.risk_score >= 65
                                  ? 'score-badge-red'
                                  : record.risk_score >= 35
                                    ? 'score-badge-amber'
                                    : 'score-badge-green'
                              }`}
                            >
                              {record.risk_score.toFixed(1)}
                            </span>
                            <ArrowUpRight size={15} color="var(--text-muted)" />
                          </button>
                        )
                      })}
                    </div>
                  )}
                </div>

                {/* Pipeline Capabilities */}
                <div className="soc-glass-panel">
                  <div className="panel-header-row">
                    <div className="panel-title-wrap">
                      <Layers size={18} />
                      <h2 className="panel-title">Multi-Layer Detection</h2>
                    </div>
                    <span className="kpi-tag">ENGINE SPECS</span>
                  </div>

                  <div className="capabilities-list">
                    <div className="capability-card">
                      <div className="cap-icon-box">
                        <Zap size={16} />
                      </div>
                      <div className="cap-content">
                        <span className="cap-heading">NLP Phishing Classifier</span>
                        <span className="cap-desc">
                          Scikit-learn Logistic Regression pipeline with calibrated TF-IDF n-grams trained on phishing corpora.
                        </span>
                      </div>
                    </div>

                    <div className="capability-card">
                      <div className="cap-icon-box">
                        <Network size={16} />
                      </div>
                      <div className="cap-content">
                        <span className="cap-heading">URL Structural Analysis</span>
                        <span className="cap-desc">
                          Detects IP host routing, abnormal network ports, obfuscated hex percent-encodings, and redirect traps.
                        </span>
                      </div>
                    </div>

                    <div className="capability-card">
                      <div className="cap-icon-box">
                        <Fingerprint size={16} />
                      </div>
                      <div className="cap-content">
                        <span className="cap-heading">Header & Auth Forensics</span>
                        <span className="cap-desc">
                          RFC 5322 validation, sender vs reply-to domain mismatch checks, and SPF / DKIM / DMARC verification.
                        </span>
                      </div>
                    </div>

                    <div className="capability-card">
                      <div className="cap-icon-box">
                        <FileCode size={16} />
                      </div>
                      <div className="cap-content">
                        <span className="cap-heading">Attachment Metadata Guard</span>
                        <span className="cap-desc">
                          Identifies double extensions (.pdf.exe), executable MIME mismatches, and weaponized document payloads.
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </section>
            </>
          )}

          {/* =================================================================
              VIEW 2: FORENSIC EMAIL SCANNER & INSPECTOR
              ================================================================= */}
          {activePage === 'Email Analysis' && (
            <>
              {/* One-Click Presets */}
              <section className="presets-section">
                <div className="presets-label">
                  <Sparkles size={14} color="var(--cyan-400)" />
                  <span>Interactive Test Scenarios (One-Click Presets)</span>
                </div>
                <div className="presets-grid">
                  {SAMPLE_PRESETS.map((preset) => (
                    <button
                      key={preset.id}
                      className={`preset-card-btn ${selectedPresetId === preset.id ? 'selected' : ''}`}
                      onClick={() => handleSelectPreset(preset)}
                    >
                      <div className="preset-header">
                        <span className="preset-title">{preset.title}</span>
                        <span
                          className={`preset-badge ${
                            preset.badgeType === 'critical'
                              ? 'preset-badge-critical'
                              : preset.badgeType === 'warn'
                                ? 'preset-badge-warn'
                                : 'preset-badge-safe'
                          }`}
                        >
                          {preset.badge}
                        </span>
                      </div>
                      <span className="preset-summary">{preset.summary}</span>
                    </button>
                  ))}
                </div>
              </section>

              {/* Scanner Input Console */}
              <section className="scanner-split-container">
                <div className="soc-glass-panel scanner-input-card">
                  <div className="editor-toolbar">
                    <div className="editor-badge">
                      <Terminal size={14} />
                      <span>RFC 5322 RAW MIME PAYLOAD</span>
                    </div>
                    <div className="editor-actions">
                      {rawEmail && (
                        <button
                          className="editor-clear-btn"
                          onClick={() => {
                            setRawEmail('')
                            setSelectedPresetId(null)
                            setResult(null)
                          }}
                          disabled={analyzing}
                        >
                          <Trash2 size={13} />
                          <span>Clear</span>
                        </button>
                      )}
                    </div>
                  </div>

                  <textarea
                    id="raw-email-input"
                    className="mail-source-textarea"
                    placeholder="From: sender@domain.com&#10;To: recipient@domain.com&#10;Subject: Urgent Security Alert&#10;Date: Sun, 25 Oct 2026 12:00:00 +0000&#10;&#10;Paste raw email RFC 5322 message headers and body or choose an interactive scenario above..."
                    value={rawEmail}
                    onChange={(e) => setRawEmail(e.target.value)}
                    disabled={analyzing}
                    spellCheck={false}
                  />

                  <div className="editor-footer-stats">
                    <span>{rawEmail.length.toLocaleString()} characters · {rawEmail.split('\n').length} lines</span>
                    <span>Local-first zero retention preview</span>
                  </div>

                  <div className="scanner-launch-row">
                    <button
                      className="analyze-execute-btn"
                      onClick={() => void handleAnalyze()}
                      disabled={analyzing || !apiOnline}
                    >
                      {analyzing ? (
                        <>
                          <RefreshCw size={17} className="spin-icon" />
                          <span>Evaluating Threat Indicators...</span>
                        </>
                      ) : (
                        <>
                          <Play size={16} fill="currentColor" />
                          <span>Execute Threat Analysis</span>
                          <ArrowRight size={16} />
                        </>
                      )}
                    </button>
                  </div>
                </div>

                {/* Pipeline Flow Guide */}
                <div className="soc-glass-panel pipeline-flow-card">
                  <div className="panel-header-row">
                    <div className="panel-title-wrap">
                      <Activity size={18} />
                      <h2 className="panel-title">Inspection Pipeline</h2>
                    </div>
                    <span className="kpi-tag">SOC FLOW</span>
                  </div>

                  <div className="pipeline-step-item">
                    <div className="pipeline-step-number">01</div>
                    <div className="pipeline-step-body">
                      <span className="pipeline-step-title">RFC 5322 Decomposition</span>
                      <span className="pipeline-step-desc">
                        Parse multipart MIME boundaries, extract raw headers, text bodies, URLs, and attachment streams.
                      </span>
                    </div>
                  </div>

                  <div className="pipeline-step-item">
                    <div className="pipeline-step-number">02</div>
                    <div className="pipeline-step-body">
                      <span className="pipeline-step-title">Feature Extraction</span>
                      <span className="pipeline-step-desc">
                        Extract sender alignment, inspect SPF/DKIM authentication, test URL hostnames, and flag double extensions.
                      </span>
                    </div>
                  </div>

                  <div className="pipeline-step-item">
                    <div className="pipeline-step-number">03</div>
                    <div className="pipeline-step-body">
                      <span className="pipeline-step-title">ML & Heuristic Fusion</span>
                      <span className="pipeline-step-desc">
                        Calculate TF-IDF probability and combine with weighted rule engine triggers into normalized 0-100 risk score.
                      </span>
                    </div>
                  </div>

                  <div className="pipeline-step-item">
                    <div className="pipeline-step-number">04</div>
                    <div className="pipeline-step-body">
                      <span className="pipeline-step-title">Explainability Synthesis</span>
                      <span className="pipeline-step-desc">
                        Generate human-readable justification findings explaining why the email is flagged or cleared.
                      </span>
                    </div>
                  </div>
                </div>
              </section>

              {/* =============================================================
                  FORENSIC RESULTS CONSOLE (WHEN ANALYSIS IS COMPLETE)
                  ============================================================= */}
              {result && (
                <section className="forensics-results-wrapper">
                  {/* Verdict Banner */}
                  {(() => {
                    const sev = getScoreSeverity(result.risk_score)
                    const riskPresentation = getRiskPresentation(result.risk_score)
                    const replyToPresentation = getReplyToPresentation(
                      result.email.reply_to,
                    )
                    const radius = 45
                    const circumference = 2 * Math.PI * radius
                    const strokeDashoffset = circumference - (Math.min(100, Math.max(0, result.risk_score)) / 100) * circumference

                    return (
                      <div className="forensics-verdict-banner">
                        <div className="verdict-grid">
                          {/* Circular Threat Gauge */}
                          <div className="threat-gauge-box">
                            <svg className="gauge-svg" width="120" height="120" viewBox="0 0 120 120">
                              <circle
                                className="gauge-bg-circle"
                                cx="60"
                                cy="60"
                                r={radius}
                              />
                              <circle
                                className="gauge-progress-circle"
                                cx="60"
                                cy="60"
                                r={radius}
                                stroke={sev.strokeColor}
                                strokeDasharray={circumference}
                                strokeDashoffset={strokeDashoffset}
                              />
                            </svg>
                            <div className="gauge-inner-stats">
                              <span className="gauge-score-num">{result.risk_score.toFixed(1)}</span>
                              <span className="gauge-score-total">/ 100 RISK</span>
                            </div>
                          </div>

                          {/* Verdict Text Center */}
                          <div className="verdict-info-center">
                            <div className="verdict-chip-row">
                              <span className={`verdict-threat-chip ${sev.badgeClass}`}>
                                {sev.label}
                              </span>
                              <span className="kpi-tag">
                                {result.rule_results.filter((r) => r.triggered).length} RULES TRIGGERED
                              </span>
                            </div>
                            <h2 className="verdict-heading">
                              {riskPresentation.explanation}
                            </h2>
                            <p className="verdict-summary-text">
                              Subject: "{result.email.subject || '(No Subject)'}" · From:{' '}
                              <strong>{result.email.sender || 'Unknown Sender'}</strong>
                            </p>
                          </div>

                          {/* ML Confidence Gauge */}
                          <div className="ml-meter-box">
                            <div className="ml-meter-label">
                              <span>ML Phishing Probability</span>
                              <span className="ml-meter-pct">
                                {formatPercent(result.ml_phishing_probability)}
                              </span>
                            </div>
                            <div className="ml-meter-track">
                              <div
                                className="ml-meter-fill"
                                style={{
                                  width: `${Math.min(100, Math.max(0, result.ml_phishing_probability * 100))}%`,
                                }}
                              />
                            </div>
                            <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
                              Model output only — not the combined risk score
                            </span>
                          </div>
                        </div>

                        {/* Envelope Metadata Strip */}
                        <div className="forensic-meta-strip">
                          <div className="meta-strip-item">
                            <span className="meta-strip-label">Sender Address</span>
                            <span className="meta-strip-val" title={result.email.sender || 'None'}>
                              {result.email.sender || 'None Provided'}
                            </span>
                          </div>
                          <div className="meta-strip-item">
                            <span className="meta-strip-label">Reply-To Routing</span>
                            <span className="meta-strip-val" title={replyToPresentation}>
                              {replyToPresentation}
                            </span>
                          </div>
                          <div className="meta-strip-item">
                            <span className="meta-strip-label">URLs Identified</span>
                            <span className="meta-strip-val">
                              {result.url_analyses.length} link{result.url_analyses.length === 1 ? '' : 's'} scanned
                            </span>
                          </div>
                          <div className="meta-strip-item">
                            <span className="meta-strip-label">Attachments</span>
                            <span className="meta-strip-val">
                              {result.attachment_analysis.attachment_count} file{result.attachment_analysis.attachment_count === 1 ? '' : 's'} inspected
                            </span>
                          </div>
                        </div>
                      </div>
                    )
                  })()}

                  {/* Forensic Sub-Navigation Tabs */}
                  <div className="forensics-nav-tabs">
                    <button
                      className={`forensics-tab-btn ${activeForensicTab === 'explanations' ? 'active' : ''}`}
                      onClick={() => setActiveForensicTab('explanations')}
                    >
                      <Sparkles size={15} />
                      <span>Explainable AI & Rules</span>
                      <span className="tab-badge">
                        {result.explainability.explanations.length}
                      </span>
                    </button>

                    <button
                      className={`forensics-tab-btn ${activeForensicTab === 'headers' ? 'active' : ''}`}
                      onClick={() => setActiveForensicTab('headers')}
                    >
                      <Fingerprint size={15} />
                      <span>Header & Auth Forensics</span>
                    </button>

                    <button
                      className={`forensics-tab-btn ${activeForensicTab === 'urls' ? 'active' : ''}`}
                      onClick={() => setActiveForensicTab('urls')}
                    >
                      <Network size={15} />
                      <span>URL Intelligence</span>
                      <span className="tab-badge">{result.url_analyses.length}</span>
                    </button>

                    <button
                      className={`forensics-tab-btn ${activeForensicTab === 'attachments' ? 'active' : ''}`}
                      onClick={() => setActiveForensicTab('attachments')}
                    >
                      <FileCode size={15} />
                      <span>Attachment Guard</span>
                      <span className="tab-badge">
                        {result.attachment_analysis.attachment_count}
                      </span>
                    </button>

                    <button
                      className={`forensics-tab-btn ${activeForensicTab === 'json' ? 'active' : ''}`}
                      onClick={() => setActiveForensicTab('json')}
                    >
                      <FileText size={15} />
                      <span>Raw Security JSON</span>
                    </button>
                  </div>

                  {/* TAB 1: EXPLANATIONS & TRIGGERED RULES */}
                  {activeForensicTab === 'explanations' && (
                    <div className="findings-container">
                      {result.explainability.explanations.length === 0 ? (
                        <div className="soc-glass-panel" style={{ textAlign: 'center', padding: '36px' }}>
                          <CheckCircle2 size={36} color="var(--threat-safe)" style={{ margin: '0 auto 12px' }} />
                          <h3 style={{ color: '#ffffff' }}>No Anomaly Rules Triggered</h3>
                          <p style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>
                            All deterministic security heuristics and ML criteria passed without raising threat flags.
                          </p>
                        </div>
                      ) : (
                        result.explainability.explanations.map((exp, idx) => (
                          <div key={idx} className="finding-card triggered">
                            <div className="finding-icon-wrap finding-icon-triggered">
                              <AlertTriangle size={18} />
                            </div>
                            <div className="finding-body">
                              <div className="finding-top-row">
                                <span className="finding-category-pill">{exp.category}</span>
                                <span className="finding-rule-id">{exp.rule_id}</span>
                              </div>
                              <span className="finding-message">{exp.message}</span>
                              {exp.observations.length > 0 && (
                                <ul className="finding-observations">
                                  {exp.observations.map((obs, obsIdx) => (
                                    <li key={obsIdx}>{obs}</li>
                                  ))}
                                </ul>
                              )}
                            </div>
                          </div>
                        ))
                      )}

                      {/* Evaluated Rules Overview */}
                      <div className="soc-glass-panel" style={{ marginTop: '16px' }}>
                        <div className="panel-header-row">
                          <div className="panel-title-wrap">
                            <Shield size={17} />
                            <h2 className="panel-title">All Evaluated Rules ({result.rule_results.length})</h2>
                          </div>
                        </div>
                        <p className="rule-status-note">
                          Rule status shows whether a configured condition was detected. “Not triggered” is not a verification result.
                        </p>
                        <div className="rule-results-grid">
                          {result.rule_results.map((rule) => (
                            <div
                              key={rule.rule_id}
                              className={`rule-result-card ${rule.triggered ? 'is-triggered' : 'is-not-triggered'}`}
                            >
                              <span className="rule-result-id">
                                {rule.rule_id}
                              </span>
                              <span
                                className="rule-result-status"
                              >
                                {getRuleStatusLabel(rule.triggered)}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* TAB 2: HEADER & AUTH FORENSICS */}
                  {activeForensicTab === 'headers' && (
                    <div className="findings-container">
                      <div className="auth-signals-grid">
                        <div className="auth-badge-card">
                          <div>
                            <span className="auth-badge-title">SPF Verification</span>
                            <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                              Sender Policy Framework
                            </div>
                          </div>
                          <span
                            className={`status-pill ${
                              result.header_analysis.spf_statuses.some((s) => s.toLowerCase().includes('fail'))
                                ? 'status-fail'
                                : result.header_analysis.spf_statuses.some((s) => s.toLowerCase().includes('pass'))
                                  ? 'status-pass'
                                  : 'status-none'
                            }`}
                          >
                            {result.header_analysis.spf_statuses.join(', ') || 'NOT SPECIFIED'}
                          </span>
                        </div>

                        <div className="auth-badge-card">
                          <div>
                            <span className="auth-badge-title">DKIM Signature</span>
                            <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                              DomainKeys Identified Mail
                            </div>
                          </div>
                          <span
                            className={`status-pill ${
                              result.header_analysis.dkim_statuses.some((s) => s.toLowerCase().includes('fail'))
                                ? 'status-fail'
                                : result.header_analysis.dkim_statuses.some((s) => s.toLowerCase().includes('pass'))
                                  ? 'status-pass'
                                  : 'status-none'
                            }`}
                          >
                            {result.header_analysis.dkim_statuses.join(', ') || 'NOT SPECIFIED'}
                          </span>
                        </div>

                        <div className="auth-badge-card">
                          <div>
                            <span className="auth-badge-title">DMARC Policy</span>
                            <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                              Message Authentication
                            </div>
                          </div>
                          <span
                            className={`status-pill ${
                              result.header_analysis.dmarc_statuses.some((s) => s.toLowerCase().includes('fail'))
                                ? 'status-fail'
                                : result.header_analysis.dmarc_statuses.some((s) => s.toLowerCase().includes('pass'))
                                  ? 'status-pass'
                                  : 'status-none'
                            }`}
                          >
                            {result.header_analysis.dmarc_statuses.join(', ') || 'NOT SPECIFIED'}
                          </span>
                        </div>
                      </div>

                      <div className="soc-glass-panel">
                        <div className="panel-header-row">
                          <div className="panel-title-wrap">
                            <Fingerprint size={18} />
                            <h2 className="panel-title">Domain Alignment Matrix</h2>
                          </div>
                        </div>

                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '16px' }}>
                          <div style={{ padding: '14px', borderRadius: '8px', background: 'rgba(18, 28, 49, 0.5)' }}>
                            <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>
                              From Domain
                            </span>
                            <div style={{ fontSize: '13px', fontWeight: 600, color: '#ffffff', fontFamily: 'var(--font-mono)', marginTop: '4px' }}>
                              {result.header_analysis.from_domain || 'N/A'}
                            </div>
                          </div>

                          <div style={{ padding: '14px', borderRadius: '8px', background: 'rgba(18, 28, 49, 0.5)' }}>
                            <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>
                              Reply-To Domain
                            </span>
                            <div style={{ fontSize: '13px', fontWeight: 600, color: '#ffffff', fontFamily: 'var(--font-mono)', marginTop: '4px' }}>
                              {result.header_analysis.reply_to_domain || 'N/A'}
                            </div>
                            {result.header_analysis.from_reply_to_domain_mismatch && (
                              <span style={{ color: '#f87171', fontSize: '11px', fontWeight: 600, display: 'block', marginTop: '4px' }}>
                                ⚠ Domain Mismatch Detected
                              </span>
                            )}
                          </div>

                          <div style={{ padding: '14px', borderRadius: '8px', background: 'rgba(18, 28, 49, 0.5)' }}>
                            <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>
                              Return-Path Domain
                            </span>
                            <div style={{ fontSize: '13px', fontWeight: 600, color: '#ffffff', fontFamily: 'var(--font-mono)', marginTop: '4px' }}>
                              {result.header_analysis.return_path_domain || 'N/A'}
                            </div>
                            {result.header_analysis.from_return_path_domain_mismatch && (
                              <span style={{ color: '#f87171', fontSize: '11px', fontWeight: 600, display: 'block', marginTop: '4px' }}>
                                ⚠ Return-Path Mismatch Detected
                              </span>
                            )}
                          </div>
                        </div>

                        <div style={{ marginTop: '18px', paddingTop: '16px', borderTop: '1px solid var(--border-subtle)', display: 'flex', gap: '20px', fontSize: '12px', color: 'var(--text-secondary)' }}>
                          <span>Received Hops: <strong>{result.header_analysis.received_header_count}</strong></span>
                          <span>Auth Headers Present: <strong>{result.header_analysis.authentication_results_present ? 'Yes' : 'No'}</strong></span>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* TAB 3: URL INTELLIGENCE */}
                  {activeForensicTab === 'urls' && (
                    <div className="findings-container">
                      {result.url_analyses.length === 0 ? (
                        <div className="soc-glass-panel" style={{ textAlign: 'center', padding: '36px' }}>
                          <Network size={36} color="var(--sky-400)" style={{ margin: '0 auto 12px' }} />
                          <h3 style={{ color: '#ffffff' }}>No Embedded URLs Found</h3>
                          <p style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>
                            The email body does not contain any web addresses or hyperlinks.
                          </p>
                        </div>
                      ) : (
                        <div className="urls-list-grid">
                          {result.url_analyses.map((url, uIdx) => (
                            <div key={uIdx} className="url-analysis-card">
                              <div className="url-title-row">
                                <ExternalLink size={16} />
                                <span>{url.original_url}</span>
                              </div>

                              <div className="url-meta-row">
                                <span>Host: <strong>{url.hostname || 'None'}</strong></span>
                                <span>Domain: <strong>{url.registered_domain || 'None'}</strong></span>
                                <span>Port: <strong>{url.port ?? 'Standard (80/443)'}</strong></span>
                                <span>Length: <strong>{url.url_length ?? url.original_url.length} chars</strong></span>
                              </div>

                              <div className="url-tags-row">
                                {url.has_ip_address && (
                                  <span className="url-threat-flag">⚠ IP Address Host</span>
                                )}
                                {url.has_unusual_port && (
                                  <span className="url-threat-flag">⚠ Unusual Port</span>
                                )}
                                {url.has_suspicious_characters && (
                                  <span className="url-threat-flag">⚠ Suspicious Characters</span>
                                )}
                                {url.has_encoding && (
                                  <span className="url-threat-flag">⚠ Percent Encoding Traps</span>
                                )}
                                {!url.has_ip_address &&
                                  !url.has_unusual_port &&
                                  !url.has_suspicious_characters &&
                                  !url.has_encoding && (
                                    <span style={{ fontSize: '11px', color: '#34d399', fontWeight: 600 }}>
                                      ✓ No structural heuristic flags
                                    </span>
                                  )}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}

                  {/* TAB 4: ATTACHMENT FORENSICS */}
                  {activeForensicTab === 'attachments' && (
                    <div className="findings-container">
                      {result.attachment_analysis.attachments.length === 0 ? (
                        <div className="soc-glass-panel" style={{ textAlign: 'center', padding: '36px' }}>
                          <FileCode size={36} color="var(--cyan-400)" style={{ margin: '0 auto 12px' }} />
                          <h3 style={{ color: '#ffffff' }}>No File Attachments Detected</h3>
                          <p style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>
                            The email MIME headers declare no attached files or binary payloads.
                          </p>
                        </div>
                      ) : (
                        <div className="urls-list-grid">
                          {result.attachment_analysis.attachments.map((att, aIdx) => (
                            <div key={aIdx} className="url-analysis-card">
                              <div className="url-title-row">
                                <FileText size={16} />
                                <span>{att.filename || '(Unnamed Attachment)'}</span>
                              </div>
                              <div className="url-meta-row">
                                <span>Extension: <strong>{att.extension || 'None'}</strong></span>
                                <span>Declared MIME: <strong>{att.content_type || 'Unknown'}</strong></span>
                                <span>
                                  Size:{' '}
                                  <strong>
                                    {att.size_bytes != null
                                      ? `${(att.size_bytes / 1024).toFixed(1)} KB`
                                      : 'Unknown'}
                                  </strong>
                                </span>
                              </div>
                              <div className="url-tags-row">
                                {att.is_double_extension && (
                                  <span className="url-threat-flag">⚠ Double Extension Masking</span>
                                )}
                                {att.is_potentially_dangerous_extension && (
                                  <span className="url-threat-flag">⚠ Dangerous Executable Extension</span>
                                )}
                                {att.is_filename_mime_mismatch && (
                                  <span className="url-threat-flag">⚠ MIME Type Mismatch</span>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}

                  {/* TAB 5: RAW SECURITY JSON */}
                  {activeForensicTab === 'json' && (
                    <div className="soc-glass-panel">
                      <div className="panel-header-row">
                        <div className="panel-title-wrap">
                          <FileCode size={18} />
                          <h2 className="panel-title">Forensic Audit JSON</h2>
                        </div>
                        <div style={{ display: 'flex', gap: '8px' }}>
                          <button
                            className="btn-glass"
                            style={{ padding: '6px 12px', fontSize: '11.5px' }}
                            onClick={() => handleCopyJson(result)}
                          >
                            {copiedJson ? <Check size={14} color="#34d399" /> : <Copy size={14} />}
                            <span>{copiedJson ? 'Copied' : 'Copy JSON'}</span>
                          </button>
                        </div>
                      </div>
                      <pre className="json-viewer-box">
                        {JSON.stringify(result, null, 2)}
                      </pre>
                    </div>
                  )}
                </section>
              )}
            </>
          )}

          {/* =================================================================
              VIEW 3: AUDIT TRAIL & HISTORY
              ================================================================= */}
          {activePage === 'Analysis History' && (
            <section className="soc-glass-panel">
              <div className="panel-header-row" style={{ flexWrap: 'wrap', gap: '12px' }}>
                <div className="panel-title-wrap">
                  <Database size={18} />
                  <h2 className="panel-title">Cryptographic Threat Audit Trail</h2>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <button
                    className="btn-glass"
                    style={{ padding: '7px 13px', fontSize: '11.5px' }}
                    onClick={handleExportCsv}
                    disabled={history.length === 0}
                  >
                    <Download size={13} />
                    <span>Export CSV</span>
                  </button>
                  <button
                    className="btn-glass"
                    style={{ padding: '7px 13px', fontSize: '11.5px' }}
                    onClick={handleExportJson}
                    disabled={history.length === 0}
                  >
                    <Download size={13} />
                    <span>Export JSON</span>
                  </button>
                  <button
                    className="btn-glass"
                    style={{ padding: '7px 13px', fontSize: '11.5px' }}
                    onClick={() => void loadHistory()}
                    disabled={loadingHistory}
                  >
                    <RefreshCw size={13} className={loadingHistory ? 'spin-icon' : ''} />
                    <span>{loadingHistory ? 'Syncing...' : 'Sync'}</span>
                  </button>
                </div>
              </div>

              {/* Toolbar Search & Filters */}
              <div className="history-controls-bar">
                <div className="history-search-input">
                  <Search size={15} color="var(--text-muted)" />
                  <input
                    aria-label="Search telemetry records"
                    placeholder="Search sender, subject or UUID..."
                    value={historySearch}
                    onChange={(e) => setHistorySearch(e.target.value)}
                  />
                </div>

                <div className="history-filters-group">
                  <button
                    className={`filter-chip-btn ${historyFilter === 'all' ? 'active' : ''}`}
                    onClick={() => setHistoryFilter('all')}
                  >
                    All ({history.length})
                  </button>
                  <button
                    className={`filter-chip-btn ${historyFilter === 'critical' ? 'active' : ''}`}
                    onClick={() => setHistoryFilter('critical')}
                  >
                    Critical ({criticalThreatsCount})
                  </button>
                  <button
                    className={`filter-chip-btn ${historyFilter === 'warn' ? 'active' : ''}`}
                    onClick={() => setHistoryFilter('warn')}
                  >
                    Suspicious ({moderateThreatsCount})
                  </button>
                  <button
                    className={`filter-chip-btn ${historyFilter === 'safe' ? 'active' : ''}`}
                    onClick={() => setHistoryFilter('safe')}
                  >
                    Clean ({cleanCount})
                  </button>
                </div>
              </div>

              {/* Data Table */}
              <div className="soc-table-wrapper">
                <table className="soc-table">
                  <thead>
                    <tr>
                      <th>EMAIL THREAT / SUBJECT</th>
                      <th>RISK SCORE</th>
                      <th>ML INFERENCE</th>
                      <th>TIMESTAMP (UTC)</th>
                      <th>FORENSIC AUDIT</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredHistory.map((record) => {
                      const sev = getScoreSeverity(record.risk_score)
                      return (
                        <tr key={record.id}>
                          <td>
                            <div className="table-mail-cell">
                              <span className="table-mail-subject">
                                {record.subject || '(Untitled Email)'}
                              </span>
                              <span className="table-mail-sender">
                                {record.sender || 'Unknown Sender'}
                              </span>
                            </div>
                          </td>
                          <td>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                              <span className={`scan-severity-indicator ${sev.bgClass}`} />
                              <strong style={{ fontFamily: 'var(--font-mono)', color: '#ffffff' }}>
                                {record.risk_score.toFixed(1)}
                              </strong>
                            </div>
                          </td>
                          <td>
                            <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--sky-400)' }}>
                              {formatPercent(record.ml_phishing_probability)}
                            </span>
                          </td>
                          <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                            {formatDate(record.analyzed_at)}
                          </td>
                          <td>
                            <button
                              className="panel-action-btn"
                              onClick={() => void openHistoryRecord(record)}
                            >
                              <span>Inspect Details</span>
                              <ArrowRight size={13} />
                            </button>
                          </td>
                        </tr>
                      )
                    })}

                    {filteredHistory.length === 0 && (
                      <tr>
                        <td colSpan={5} style={{ textAlign: 'center', padding: '36px' }}>
                          <History size={32} style={{ margin: '0 auto 10px', display: 'block', opacity: 0.5 }} />
                          <strong style={{ display: 'block', color: 'var(--text-secondary)' }}>
                            {loadingHistory ? 'Retrieving Audit Records...' : 'No Matching Audit Records Found'}
                          </strong>
                          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                            {history.length === 0
                              ? 'Perform an email analysis to generate a permanent audit entry.'
                              : 'Try adjusting your search query or filter tags.'}
                          </span>
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>

              {/* Slide-Over Drawer for Selected Record */}
              {selectedRecord && (
                <div className="soc-drawer-backdrop" onClick={() => setSelectedRecord(null)}>
                  <div className="soc-drawer-panel" onClick={(e) => e.stopPropagation()}>
                    <div className="drawer-header">
                      <div>
                        <span className="page-eyebrow">Audit Record Dossier</span>
                        <h2 className="drawer-title">{selectedRecord.subject || '(Untitled Email)'}</h2>
                        <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                          ID: {selectedRecord.id}
                        </span>
                      </div>
                      <button
                        className="drawer-close-btn"
                        aria-label="Close dossier"
                        onClick={() => setSelectedRecord(null)}
                      >
                        <X size={18} />
                      </button>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '14px' }}>
                      <div className="soc-glass-panel" style={{ padding: '14px' }}>
                        <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>
                          Evaluated Risk Score
                        </span>
                        <div style={{ fontFamily: 'var(--font-display)', fontSize: '26px', fontWeight: 700, color: '#ffffff', marginTop: '4px' }}>
                          {selectedRecord.risk_score.toFixed(1)} / 100
                        </div>
                      </div>

                      <div className="soc-glass-panel" style={{ padding: '14px' }}>
                        <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>
                          ML Phishing Probability
                        </span>
                        <div style={{ fontFamily: 'var(--font-display)', fontSize: '26px', fontWeight: 700, color: 'var(--cyan-400)', marginTop: '4px' }}>
                          {formatPercent(selectedRecord.ml_phishing_probability)}
                        </div>
                      </div>
                    </div>

                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                        <span style={{ fontSize: '11.5px', fontWeight: 700, color: 'var(--text-secondary)' }}>
                          STORED AUDIT EVIDENCE (JSON)
                        </span>
                        <button
                          className="btn-glass"
                          style={{ padding: '4px 10px', fontSize: '11px' }}
                          onClick={() => handleCopyJson(selectedRecord.result)}
                        >
                          <Copy size={12} />
                          <span>Copy Raw</span>
                        </button>
                      </div>
                      <pre className="json-viewer-box">
                        {JSON.stringify(selectedRecord.result, null, 2)}
                      </pre>
                    </div>
                  </div>
                </div>
              )}
            </section>
          )}

          {/* =================================================================
              VIEW 4: SETTINGS & ARCHITECTURE
              ================================================================= */}
          {activePage === 'Settings' && (
            <div className="settings-grid-layout">
              {/* API Configuration */}
              <div className="soc-glass-panel">
                <div className="panel-header-row">
                  <div className="panel-title-wrap">
                    <Server size={18} />
                    <h2 className="panel-title">Backend API Connection</h2>
                  </div>
                </div>

                <div className="settings-input-group">
                  <label className="settings-label" htmlFor="api-url-input">
                    FastAPI Service Base URL
                  </label>
                  <input
                    id="api-url-input"
                    className="settings-text-input"
                    value={apiUrl}
                    onChange={(e) => setApiUrl(e.target.value)}
                    placeholder={DEFAULT_API_URL}
                  />
                  <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    Standard local development endpoint: <code>{DEFAULT_API_URL}</code>
                  </span>
                </div>

                <div
                  style={{
                    padding: '14px 16px',
                    borderRadius: '8px',
                    background: apiOnline ? 'rgba(16, 185, 129, 0.08)' : 'rgba(239, 68, 68, 0.08)',
                    border: `1px solid ${apiOnline ? 'rgba(16, 185, 129, 0.25)' : 'rgba(239, 68, 68, 0.25)'}`,
                    display: 'flex',
                    alignItems: 'center',
                    gap: '12px',
                    marginBottom: '20px',
                  }}
                >
                  <span className={`engine-status-dot ${apiOnline ? '' : 'offline'}`} />
                  <div>
                    <strong style={{ color: '#ffffff', fontSize: '12px', display: 'block' }}>
                      {apiOnline ? 'Service Operational' : 'Service Offline'}
                    </strong>
                    <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                      {apiOnline
                        ? `Health check verified. Latency: ${apiLatencyMs ?? 0}ms.`
                        : 'Ensure the Uvicorn server is running on localhost:8000.'}
                    </span>
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '10px' }}>
                  <button
                    className="btn-primary-glow"
                    onClick={() => void saveApiUrl()}
                    disabled={checkingApi}
                  >
                    <CheckCircle2 size={15} />
                    <span>Save & Test Ping</span>
                  </button>
                  <button
                    className="btn-glass"
                    onClick={() => {
                      setApiUrl(DEFAULT_API_URL)
                    }}
                  >
                    <span>Reset Default</span>
                  </button>
                </div>
              </div>

              {/* Technical Stack Specifications */}
              <div className="soc-glass-panel">
                <div className="panel-header-row">
                  <div className="panel-title-wrap">
                    <Cpu size={18} />
                    <h2 className="panel-title">Portfolio Architecture Specs</h2>
                  </div>
                </div>

                <div className="arch-specs-list">
                  <div className="arch-spec-item">
                    <span>Inference Pipeline</span>
                    <strong>Scikit-Learn TF-IDF + Logistic Reg</strong>
                  </div>
                  <div className="arch-spec-item">
                    <span>Heuristics Engine</span>
                    <strong>Deterministic Rule Engine (RFC 5322)</strong>
                  </div>
                  <div className="arch-spec-item">
                    <span>REST API Framework</span>
                    <strong>FastAPI + Pydantic v2</strong>
                  </div>
                  <div className="arch-spec-item">
                    <span>ASGI Server</span>
                    <strong>Uvicorn (Python 3.13)</strong>
                  </div>
                  <div className="arch-spec-item">
                    <span>Frontend Client</span>
                    <strong>React 19 + TypeScript + Vite</strong>
                  </div>
                  <div className="arch-spec-item">
                    <span>Persistence Storage</span>
                    <strong>SQLite 3 Thread-Safe DB</strong>
                  </div>
                </div>

                <div style={{ marginTop: '20px', paddingTop: '16px', borderTop: '1px solid var(--border-subtle)', display: 'flex', gap: '10px' }}>
                  <a
                    href="http://127.0.0.1:8000/docs"
                    target="_blank"
                    rel="noreferrer"
                    className="panel-action-btn"
                  >
                    <span>Swagger API Docs</span>
                    <ExternalLink size={12} />
                  </a>
                  <span style={{ color: 'var(--border-subtle)' }}>•</span>
                  <a
                    href="http://127.0.0.1:8000/redoc"
                    target="_blank"
                    rel="noreferrer"
                    className="panel-action-btn"
                  >
                    <span>Redoc Reference</span>
                    <ExternalLink size={12} />
                  </a>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Global Footer */}
        <footer className="soc-footer">
          <div>
            <strong>SENTINEL SOC</strong> · Explainable Email Threat Intelligence & Phishing Detection
          </div>
          <div>
            Engineered with Python, FastAPI, Scikit-learn, React 19 & TypeScript
          </div>
        </footer>
      </main>
    </div>
  )
}

export default App
