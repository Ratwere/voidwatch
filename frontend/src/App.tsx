import { useCallback, useEffect, useMemo, useState } from 'react'
import './App.css'

type Decision = 'allow' | 'deceive' | 'block'

type Check = {
  check_id: string
  timestamp: string
  score: number
  action: Decision
  reason: string
  content_sha256: string
  first_seen: string
  times_seen: number
}

type HoneypotAction = {
  event_id: string
  timestamp: string
  check_id: string | null
  action: string
  target: string
  target_domain: string | null
  payload_style: 'empty' | 'json' | 'text'
  payload_length: number
  payload_sha256: string | null
}

type CheckTrail = {
  check: Check
  honeypot_actions: HoneypotAction[]
}

async function fetchCheckTrails(): Promise<CheckTrail[]> {
  const response = await fetch('/checks?limit=50', {
    headers: { Accept: 'application/json' },
  })
  if (!response.ok) {
    throw new Error(`The API returned HTTP ${response.status}.`)
  }

  const data: unknown = await response.json()
  if (!Array.isArray(data)) {
    throw new Error('The API response was not a list of check trails.')
  }
  return data as CheckTrail[]
}

function getErrorMessage(error: unknown) {
  return error instanceof Error ? error.message : 'Could not load the attack trail.'
}

function formatTime(value: string) {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'medium',
  }).format(new Date(value))
}

function App() {
  const [trails, setTrails] = useState<CheckTrail[]>([])
  const [error, setError] = useState<string | null>(null)
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null)
  const [refreshing, setRefreshing] = useState(false)

  const refresh = useCallback(async () => {
    try {
      setTrails(await fetchCheckTrails())
      setError(null)
    } catch (caughtError) {
      setError(getErrorMessage(caughtError))
    } finally {
      setUpdatedAt(new Date())
    }
  }, [])

  const handleRefresh = async () => {
    setRefreshing(true)
    await refresh()
    setRefreshing(false)
  }

  useEffect(() => {
    let active = true
    const loadTrails = () => {
      void fetchCheckTrails().then(
        (data) => {
          if (!active) return
          setTrails(data)
          setError(null)
          setUpdatedAt(new Date())
        },
        (loadError: unknown) => {
          if (!active) return
          setError(getErrorMessage(loadError))
          setUpdatedAt(new Date())
        },
      )
    }

    loadTrails()
    const intervalId = window.setInterval(loadTrails, 5000)
    return () => {
      active = false
      window.clearInterval(intervalId)
    }
  }, [])

  const totals = useMemo(
    () => ({
      checks: trails.length,
      deceived: trails.filter(({ check }) => check.action === 'deceive').length,
      blocked: trails.filter(({ check }) => check.action === 'block').length,
      actions: trails.reduce(
        (total, trail) => total + trail.honeypot_actions.length,
        0,
      ),
    }),
    [trails],
  )

  return (
    <main className="app-shell">
      <header className="topbar">
        <a className="brand" href="/" aria-label="VoidWatch home">
          <img className="brand-mark" src="/voidwatch.jpg" alt="" />
          <span>VOID<span className="brand-accent">WATCH</span></span>
        </a>
        <div className="topbar-status">
          <span className={`status-dot ${error ? 'status-dot-error' : ''}`} />
          <span>{error ? 'API disconnected' : 'Monitoring'}</span>
        </div>
      </header>

      <section className="page-heading">
        <div>
          <p className="eyebrow">SECURITY OVERVIEW</p>
          <h1>Attack trail</h1>
          <p className="subtitle">
            Detection decisions and simulated honeypot activity, in one place.
          </p>
        </div>
        <button className="refresh-button" onClick={() => void handleRefresh()} disabled={refreshing}>
          <span aria-hidden="true" className={refreshing ? 'refresh-icon spinning' : 'refresh-icon'}>↻</span>
          Refresh
        </button>
      </section>

      {error && (
        <div className="error-banner" role="alert">
          <strong>Can’t load the attack trail.</strong>
          <span>{error} Start the FastAPI server and try again.</span>
          <button onClick={() => void handleRefresh()}>Retry</button>
        </div>
      )}

      <section className="stats-grid" aria-label="Trail summary">
        <StatCard label="Checks loaded" value={totals.checks} detail="Most recent 50" />
        <StatCard label="Routed to honeypot" value={totals.deceived} detail="Deceive decisions" tone="purple" />
        <StatCard label="Blocked" value={totals.blocked} detail="High-risk decisions" tone="red" />
        <StatCard label="Simulated actions" value={totals.actions} detail="Linked honeypot events" tone="green" />
      </section>

      <section className="feed-section">
        <div className="feed-heading">
          <div>
            <h2>Recent activity</h2>
            <p>Newest checks first · refreshes every 5 seconds</p>
          </div>
          <span className="updated-label">
            {updatedAt ? `Updated ${updatedAt.toLocaleTimeString()}` : 'Waiting for API'}
          </span>
        </div>

        {trails.length === 0 && !error ? (
          <div className="empty-state">
            <span className="empty-icon" aria-hidden="true">⌁</span>
            <h3>No checks yet</h3>
            <p>Send untrusted text to the API’s <code>POST /check</code> endpoint to begin a demo trail.</p>
          </div>
        ) : (
          <div className="trail-list">
            {trails.map((trail) => (
              <TrailCard key={trail.check.check_id} trail={trail} />
            ))}
          </div>
        )}
      </section>

      <footer className="footer">
        <span>VOIDWATCH · LOCAL DEMO</span>
        <span>In-memory data clears when the API restarts</span>
      </footer>
    </main>
  )
}

function StatCard({
  label,
  value,
  detail,
  tone = 'default',
}: {
  label: string
  value: number
  detail: string
  tone?: 'default' | 'purple' | 'red' | 'green'
}) {
  return (
    <article className={`stat-card stat-${tone}`}>
      <p>{label}</p>
      <strong>{value}</strong>
      <span>{detail}</span>
    </article>
  )
}

function TrailCard({ trail }: { trail: CheckTrail }) {
  const { check, honeypot_actions: actions } = trail

  return (
    <article className="trail-card">
      <div className="trail-main">
        <div className="trail-topline">
          <span className={`decision-badge decision-${check.action}`}>{check.action}</span>
          <span className="trail-time">{formatTime(check.timestamp)}</span>
          <span className="trail-id">ID {check.check_id.slice(0, 8)}</span>
        </div>
        <p className="trail-reason">{check.reason}</p>
        <div className="fingerprint-row">
          <span>FINGERPRINT</span>
          <code title={check.content_sha256}>{check.content_sha256.slice(0, 24)}…</code>
          <span className="repeat-count">seen {check.times_seen}×</span>
        </div>
        {actions.length > 0 ? (
          <div className="action-list">
            {actions.map((action) => (
              <div className="action-row" key={action.event_id}>
                <span className="action-icon" aria-hidden="true">↳</span>
                <div>
                  <strong>{action.action.replace('_', ' ')}</strong>
                  <span>{action.target_domain ?? action.target}</span>
                </div>
                <small>{action.payload_style} · {action.payload_length} chars</small>
              </div>
            ))}
          </div>
        ) : (
          <p className="no-action">No linked honeypot action recorded</p>
        )}
      </div>
      <div className="score-column">
        <strong>{check.score}</strong>
        <span>RISK SCORE</span>
        <div className="score-track" aria-label={`Risk score ${check.score} out of 100`}>
          <span style={{ width: `${check.score}%` }} />
        </div>
      </div>
    </article>
  )
}

export default App
