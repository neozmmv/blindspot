package network

import (
	"fmt"
	"sync"
	"time"
)

var (
	lastSeen time.Time
	mu       sync.Mutex
)

const (
	// keepaliveInterval is how often each established peer is pinged.
	keepaliveInterval = 10 * time.Second
	// keepaliveMissLimit is how many consecutive unanswered pings (~30s) it takes
	// to declare a peer unresponsive and hand it to TimeoutPeer for re-handshake.
	keepaliveMissLimit = 3
	// watchdogSilence is the last-resort all-peers-silent threshold. It is well
	// above keepaliveMissLimit*keepaliveInterval on purpose: individual dead peers
	// are detected and healed per-peer by KeepAliveAll first, so this only fires
	// when peers still look established yet nothing has been heard from anyone.
	watchdogSilence = 90 * time.Second
)

// WatchConnection monitors for activity. hasPeers returns true when there are
// currently connected peers — the timeout only fires when peers exist but are silent.
func WatchConnection(hasPeers func() bool) error {
	for {
		time.Sleep(30 * time.Second)
		if !hasPeers() {
			continue
		}
		mu.Lock()
		since := time.Since(lastSeen)
		mu.Unlock()
		if since > watchdogSilence {
			return fmt.Errorf("connection lost")
		}
	}
}

func UpdateLastSeen() {
	mu.Lock()
	lastSeen = time.Now()
	mu.Unlock()
}

// KeepAliveAll pings every established peer on a fixed cadence and hands peers
// that stop answering to TimeoutPeer, which tears down their mappings (Dead
// event) and re-arms the handshake so a transient outage heals automatically.
// The loop exits on Shutdown.
func KeepAliveAll(p *PeerConn) {
	for {
		select {
		case <-p.stop:
			return
		case <-time.After(keepaliveInterval):
		}
		for _, addr := range p.establishedPeers() {
			// Any authenticated packet proves the peer is alive. Under a heavy
			// transfer the pong replies can be lost to congestion for long
			// stretches; without this, a peer whose data is streaming in
			// perfectly would be torn down mid-transfer.
			if p.RecentActivity(addr, keepaliveInterval) {
				p.mu.Lock()
				p.missedPings[addr.String()] = 0
				p.mu.Unlock()
			}
			p.mu.Lock()
			missed := p.missedPings[addr.String()]
			p.mu.Unlock()
			if missed >= keepaliveMissLimit {
				fmt.Printf("Peer %v unresponsive (no pong after %d pings), reconnecting...\n", addr, missed)
				p.TimeoutPeer(addr)
				continue
			}
			// Encrypted, authenticated keepalive; the reply resets missedPings.
			p.sendControl(addr, CtrlPing)
			p.mu.Lock()
			p.missedPings[addr.String()]++
			p.mu.Unlock()
		}
	}
}
