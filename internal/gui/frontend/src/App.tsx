import { useState, useEffect, useCallback } from 'react'
import { Events } from '@wailsio/runtime'
import { TrayService } from '../bindings/github.com/neozmmv/blindspot/internal/gui'

interface Peer {
  virtualIP: string
  publicAddr: string
}

interface Status {
  connected: boolean
  myIP: string
  peers: Peer[]
  busy: boolean
  receiving: boolean
  transfer: string
}

const emptyStatus: Status = {
  connected: false,
  myIP: '',
  peers: [],
  busy: false,
  receiving: false,
  transfer: '',
}

function App() {
  const [status, setStatus] = useState<Status>(emptyStatus)
  const [version, setVersion] = useState('')
  const [notice, setNotice] = useState('')

  // connect form
  const [session, setSession] = useState('')
  const [password, setPassword] = useState('')
  const [isNew, setIsNew] = useState(false)

  // send form
  const [peerIP, setPeerIP] = useState('')
  const [filePath, setFilePath] = useState('')
  const [saveHere, setSaveHere] = useState(false)

  const [copied, setCopied] = useState(false)

  const refresh = useCallback(async () => {
    try {
      const s = await TrayService.GetStatus()
      setStatus(s as Status)
    } catch (e) {
      console.error(e)
    }
  }, [])

  useEffect(() => {
    refresh()
    TrayService.Version().then(setVersion).catch(() => {})
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
      const msg = await TrayService.Connect(session, password, isNew)
      flash(msg || 'Connected.')
      setPassword('')
    } catch (e: any) {
      flash(String(e?.message ?? e))
    }
  }

  const doDisconnect = async () => {
    try {
      const msg = await TrayService.Disconnect()
      flash(msg)
    } catch (e: any) {
      flash(String(e?.message ?? e))
    }
  }

  const copyIP = async () => {
    if (!status.myIP) return
    try {
      await navigator.clipboard.writeText(status.myIP)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1200)
    } catch { /* clipboard blocked */ }
  }

  const chooseFile = async () => {
    try {
      const path = await TrayService.SelectFile()
      if (path) setFilePath(path)
    } catch (e: any) {
      flash(String(e?.message ?? e))
    }
  }

  const doSend = async () => {
    try {
      const msg = await TrayService.SendFile(peerIP, filePath)
      flash(msg)
    } catch (e: any) {
      flash(String(e?.message ?? e))
    }
  }

  const doReceive = async () => {
    try {
      await TrayService.StartReceive(saveHere)
    } catch (e: any) {
      flash(String(e?.message ?? e))
    }
  }

  const cancelReceive = async () => {
    try { await TrayService.CancelReceive() } catch { /* ignore */ }
  }

  const fileName = filePath ? filePath.replace(/^.*[\\/]/, '') : ''

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="dot-logo" aria-hidden="true" />
          <span className="brand-name">blindspot</span>
        </div>
        <span className={`pill ${status.connected ? 'pill-on' : 'pill-off'}`}>
          <span className="pill-dot" />
          {status.connected ? 'Connected' : 'Offline'}
        </span>
      </header>

      <main className="body">
        {status.connected ? (
          <section className="card session-card">
            <div className="row-between">
              <div>
                <div className="label">Your virtual IP</div>
                <div className="myip">{status.myIP || '—'}</div>
              </div>
              <button className="btn ghost" onClick={copyIP} disabled={!status.myIP}>
                {copied ? 'Copied' : 'Copy'}
              </button>
            </div>

            <div className="peers">
              <div className="label">
                Peers <span className="count">{status.peers.length}</span>
              </div>
              {status.peers.length === 0 ? (
                <div className="empty">No peers connected yet.</div>
              ) : (
                <ul className="peer-list">
                  {status.peers.map((p) => (
                    <li key={p.virtualIP} className="peer">
                      <span className="peer-ip">{p.virtualIP}</span>
                      <span className="peer-addr">{p.publicAddr}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <button className="btn danger full" onClick={doDisconnect} disabled={status.busy}>
              Disconnect
            </button>
          </section>
        ) : (
          <section className="card">
            <div className="label">Join or create a session</div>
            <input
              className="input"
              placeholder="Session name"
              value={session}
              onChange={(e) => setSession(e.target.value)}
              autoComplete="off"
            />
            <input
              className="input"
              type="password"
              placeholder={isNew ? 'Password (min 8 chars)' : 'Password (if any)'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="off"
            />
            <label className="check">
              <input type="checkbox" checked={isNew} onChange={(e) => setIsNew(e.target.checked)} />
              Create a new password-protected session
            </label>
            <button className="btn primary full" onClick={doConnect} disabled={status.busy || !session}>
              {status.busy ? 'Connecting…' : 'Connect'}
            </button>
            <p className="hint">Connecting prompts for administrator access to set up the VPN adapter.</p>
          </section>
        )}

        <section className="card">
          <div className="label">File transfer</div>

          <div className="subgroup">
            <div className="sublabel">Send</div>
            <input
              className="input"
              placeholder="Peer virtual IP (10.x.x.x)"
              value={peerIP}
              onChange={(e) => setPeerIP(e.target.value)}
              autoComplete="off"
            />
            <div className="file-row">
              <button className="btn ghost" onClick={chooseFile}>Choose file</button>
              <span className="file-name" title={filePath}>{fileName || 'No file selected'}</span>
            </div>
            <button
              className="btn primary full"
              onClick={doSend}
              disabled={status.busy || !peerIP || !filePath}
            >
              {status.busy ? 'Sending…' : 'Send file'}
            </button>
          </div>

          <div className="subgroup">
            <div className="sublabel">Receive</div>
            <label className="check">
              <input type="checkbox" checked={saveHere} onChange={(e) => setSaveHere(e.target.checked)} />
              Save to current directory (default: Downloads)
            </label>
            {status.receiving ? (
              <button className="btn danger full" onClick={cancelReceive}>Stop receiving</button>
            ) : (
              <button className="btn full" onClick={doReceive}>Wait for a file</button>
            )}
          </div>

          {status.transfer && <div className="transfer">{status.transfer}</div>}
        </section>
      </main>

      {notice && <div className="notice">{notice}</div>}

      <footer className="footer">
        <span>{version || 'blindspot'}</span>
      </footer>
    </div>
  )
}

export default App
