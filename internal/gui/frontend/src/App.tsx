import { useState, useEffect, useCallback } from 'react'
import { Events, Window } from '@wailsio/runtime'
import { TrayService } from '../bindings/github.com/neozmmv/blindspot/internal/gui'

interface Peer {
  virtualIP: string
  publicAddr: string
}

interface Status {
  connected: boolean
  myIP: string
  session: string
  peers: Peer[]
  busy: boolean
  receiving: boolean
  transfer: string
}

const emptyStatus: Status = {
  connected: false,
  myIP: '',
  session: '',
  peers: [],
  busy: false,
  receiving: false,
  transfer: '',
}

/* Minimal line icons, sized by the surrounding font. */
const stroke = {
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.75,
  strokeLinecap: 'round' as const,
  strokeLinejoin: 'round' as const,
}
const IconCopy = () => (
  <svg viewBox="0 0 24 24" width="15" height="15" {...stroke}><rect x="9" y="9" width="11" height="11" rx="2.5" /><path d="M5 15V6a2 2 0 0 1 2-2h8" /></svg>
)
const IconCheck = () => (
  <svg viewBox="0 0 24 24" width="15" height="15" {...stroke}><path d="M20 6L9 17l-5-5" /></svg>
)
const IconMonitor = () => (
  <svg viewBox="0 0 24 24" width="18" height="18" {...stroke}><rect x="3" y="4" width="18" height="12" rx="2" /><path d="M8 20h8M12 16v4" /></svg>
)
const IconSend = () => (
  <svg viewBox="0 0 24 24" width="16" height="16" {...stroke}><path d="M21 3L11 13M21 3l-6.5 18-3.8-8.2L2.5 9 21 3z" /></svg>
)
const IconDownload = () => (
  <svg viewBox="0 0 24 24" width="16" height="16" {...stroke}><path d="M12 4v10m0 0l-3.5-3.5M12 14l3.5-3.5M5 19h14" /></svg>
)
const IconPower = () => (
  <svg viewBox="0 0 24 24" width="16" height="16" {...stroke}><path d="M12 4v8" /><path d="M7.2 7.2a7 7 0 1 0 9.6 0" /></svg>
)
/* const IconMinimize = () => (
  <svg viewBox="0 0 24 24" width="16" height="16" {...stroke}><path d="M6 12h12" /></svg>
) */

function App() {
  const [status, setStatus] = useState<Status>(emptyStatus)
  const [notice, setNotice] = useState('')
  const [session, setSession] = useState('')
  const [password, setPassword] = useState('')
  const [isNew, setIsNew] = useState(false)
  const [useCustomRendezvous, setUseCustomRendezvous] = useState(false)
  const [hostname, setHostname] = useState('')
  const [copied, setCopied] = useState(false)
  const [copiedPeer, setCopiedPeer] = useState('')
  const [version, setVersion] = useState('')

  const refresh = useCallback(async () => {
    try {
      setStatus((await TrayService.GetStatus()) as Status)
    } catch (e) {
      console.error(e)
    }
  }, [])

  useEffect(() => {
    refresh()
    TrayService.Version()
      .then((v) => {
        // Release builds report a clean tag (e.g. "v1.3.10"); dev builds report a Go
        // pseudo-version ("v1.3.10-0.<timestamp>-<hash>+dirty") — trim that noise.
        const clean = String(v)
          .replace(/^blindspot\s+/i, '')
          .replace(/\+.*$/, '')
          .replace(/-0\.\d{12,14}-[0-9a-f]+$/i, '')
        setVersion(clean)
      })
      .catch(() => {})
    const off = Events.On('status', (ev: any) => {
      if (ev?.data) setStatus(ev.data as Status)
    })
    return () => { off?.() }
  }, [refresh])

  const flash = (msg: string) => {
    setNotice(msg)
    window.clearTimeout((flash as any)._t)
    ;(flash as any)._t = window.setTimeout(() => setNotice(''), 5000)
  }

  const doConnect = async () => {
    setNotice('')
    try {
      const rendezvous = useCustomRendezvous ? hostname : ''
      const msg = await TrayService.Connect(session, password, isNew, rendezvous)
      flash(msg || 'Connected.')
      setPassword('')
    } catch (e: any) {
      flash(String(e?.message ?? e))
    }
  }

  const doDisconnect = async () => {
    try { flash(await TrayService.Disconnect()) }
    catch (e: any) { flash(String(e?.message ?? e)) }
  }

  const copyIP = async () => {
    if (!status.myIP) return
    try {
      await navigator.clipboard.writeText(status.myIP)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1400)
    } catch { /* clipboard unavailable */ }
  }

  const copyPeer = async (ip: string) => {
    try {
      await navigator.clipboard.writeText(ip)
      setCopiedPeer(ip)
      window.setTimeout(() => setCopiedPeer(''), 1400)
    } catch { /* clipboard unavailable */ }
  }

  const sendTo = async (peerIP: string) => {
    try {
      const path = await TrayService.SelectFile()
      if (path) await TrayService.SendFile(peerIP, path)
    } catch (e: any) {
      flash(String(e?.message ?? e))
    }
  }

  const doReceive = async () => {
    try { await TrayService.StartReceive(false) }
    catch (e: any) { flash(String(e?.message ?? e)) }
  }
  const stopReceive = async () => {
    try { await TrayService.CancelReceive() } catch { /* ignore */ }
  }

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <img className="logo" src="/blindspot-logo.png" alt="Blindspot" />
          <span className="brand-name">Blindspot</span>
        </div>
        <div className="topbar-right">
          {version && <span className="version" title={version}>{version}</span>}
          <button className="win-btn" onClick={() => Window.Hide()} title="Minimize" aria-label="Minimize">
            —
          </button>
        </div>
      </header>

      {status.connected ? (
        <main className="content">
          <section className="card summary">
            <div className="summary-label">Your device</div>
            <button className="ip-value" onClick={copyIP} title="Copy IP address">
              <span className="ip-text">{status.myIP || '—'}</span>
              <span className="copy-btn">{copied ? <><IconCheck /> Copied</> : <><IconCopy /> Copy</>}</span>
            </button>
            <div className="summary-meta">
              {status.session && <span className="chip">{status.session}</span>}
              <span className="meta-dim">{status.peers.length} {status.peers.length === 1 ? 'peer' : 'peers'} connected</span>
            </div>
          </section>

          <section className="peers-block">
            <div className="section-title">
              <h2>Peers</h2>
              <span className="hint-line">Drag a file onto a peer to send it</span>
            </div>

            {status.peers.length === 0 ? (
              <div className="empty">
                <div className="empty-title">No peers connected</div>
                <p className="empty-body">Devices that join this network will appear here, ready to receive files.</p>
              </div>
            ) : (
              <ul className="peer-list">
                {status.peers.map((p) => (
                  <li
                    key={p.virtualIP}
                    id={`peer-${p.virtualIP}`}
                    className="peer"
                    data-file-drop-target=""
                    data-peer-ip={p.virtualIP}
                    onClick={() => sendTo(p.virtualIP)}
                    title={`Send a file to ${p.virtualIP}`}
                  >
                    <span className="peer-icon"><IconMonitor /></span>
                    <span className="peer-info">
                      <span className="peer-name">{p.virtualIP}</span>
                      <span className="peer-addr">{p.publicAddr}</span>
                    </span>
                    <div className="peer-actions">
                      <span className="peer-action" title="Send a file"><IconSend /></span>
                      <button
                        className="peer-copy"
                        onClick={(e) => { e.stopPropagation(); copyPeer(p.virtualIP) }}
                        title="Copy IP address"
                        aria-label="Copy IP address"
                      >
                        {copiedPeer === p.virtualIP ? <IconCheck /> : <IconCopy />}
                      </button>
                    </div>
                    <span className="peer-drop"><IconDownload /> Drop to send</span>
                  </li>
                ))}
              </ul>
            )}
          </section>

          {status.transfer && (
            <div className="transfer">
              <span className="transfer-spinner" />
              <span className="transfer-text">{status.transfer}</span>
            </div>
          )}

          <div className="footer">
            {status.receiving ? (
              <button className="btn btn-secondary" onClick={stopReceive}>
                <span className="live-dot" /> Stop receiving
              </button>
            ) : (
              <button className="btn btn-secondary" onClick={doReceive}><IconDownload /> Receive a file</button>
            )}
            <button className="btn btn-danger" onClick={doDisconnect} disabled={status.busy}>
              <IconPower /> Disconnect
            </button>
          </div>
        </main>
      ) : (
        <main className="content">
          <section className="card connect-card">
            <h1 className="connect-title">Connect to a network</h1>
            <p className="connect-sub">Join a session or create a new encrypted network.</p>

            <label className="field-label" htmlFor="session">Network name</label>
            <input
              id="session"
              className="input"
              placeholder="e.g. blindspot-friends"
              value={session}
              onChange={(e) => setSession(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter' && session) doConnect() }}
              autoComplete="off"
              autoFocus
            />

            <label className="field-label" htmlFor="password">Password{!isNew && <span className="optional"> (optional)</span>}</label>
            <input
              id="password"
              className="input"
              type="password"
              placeholder={isNew ? 'At least 8 characters' : 'Leave blank if none'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter' && session) doConnect() }}
              autoComplete="off"
            />

            <label className="checkbox">
              <input type="checkbox" checked={isNew} onChange={(e) => setIsNew(e.target.checked)} />
              <span>Create a new encrypted network</span>
            </label>

            <label className="checkbox">
              <input
                type="checkbox"
                checked={useCustomRendezvous}
                onChange={(e) => setUseCustomRendezvous(e.target.checked)}
              />
              <span>Use a custom rendezvous server</span>
            </label>

            {useCustomRendezvous && (
              <input
                id="hostname"
                className="input"
                placeholder="e.g. rendezvous.trycloudflare.com"
                value={hostname}
                onChange={(e) => setHostname(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter' && session) doConnect() }}
                autoComplete="off"
              />
            )}

            <button className="btn btn-primary btn-full" onClick={doConnect} disabled={status.busy || !session}>
              {status.busy ? 'Connecting…' : 'Connect'}
            </button>
            <p className="connect-note">Connecting requires administrator access to set up the VPN adapter.</p>
          </section>

          <div className="device-line">
            <span className="device-k">Your device IP</span>
            <span className="device-v">{status.myIP || '—'}</span>
          </div>
        </main>
      )}

      {notice && <div className="notice" role="status">{notice}</div>}
    </div>
  )
}

export default App
