package network

import (
	"fmt"
	"net"
	"sync"
	"time"
)

var (
	lastSeen time.Time
	mu       sync.Mutex
)

// sends a versioned ping every 10 seconds to keep the connection alive
func KeepAlive(conn *net.UDPConn, peerAddr *net.UDPAddr) {
	for {
		time.Sleep(10 * time.Second)
		conn.WriteToUDP(buildPacket(PacketPing, nil), peerAddr)
	}
}

// WatchConnection monitors for activity. hasPeers returns true when there are
// currently connected peers — the timeout only fires when peers exist but are silent.
func WatchConnection(conn *net.UDPConn, hasPeers func() bool) error {
	for {
		time.Sleep(30 * time.Second)
		if !hasPeers() {
			continue
		}
		mu.Lock()
		since := time.Since(lastSeen)
		mu.Unlock()
		if since > 30*time.Second {
			return fmt.Errorf("connection lost")
		}
	}
}

func UpdateLastSeen() {
	mu.Lock()
	lastSeen = time.Now()
	mu.Unlock()
}

func KeepAliveAll(p *PeerConn) {
	ping := buildPacket(PacketPing, nil)
	for {
		time.Sleep(10 * time.Second)
		for _, addr := range p.establishedPeers() {
			p.mu.Lock()
			missed := p.missedPings[addr.String()]
			p.mu.Unlock()
			if missed >= 9 {
				fmt.Printf("Peer %v declared dead (no pong after %d pings)\n", addr, missed)
				p.RemovePeer(addr)
				continue
			}
			p.conn.WriteToUDP(ping, addr)
			p.mu.Lock()
			p.missedPings[addr.String()]++
			p.mu.Unlock()
		}
	}
}
