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

// sends 0x02 every 10 seconds to keep the connection alive
func KeepAlive(conn *net.UDPConn, peerAddr *net.UDPAddr) {
	for {
		time.Sleep(10 * time.Second)
		conn.WriteToUDP([]byte{PacketPing}, peerAddr)
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
	for {
		time.Sleep(10 * time.Second)
		p.mu.Lock()
		peers := make([]*net.UDPAddr, len(p.peers))
		copy(peers, p.peers)
		p.mu.Unlock()
		for _, addr := range peers {
			p.conn.WriteToUDP([]byte{PacketPing}, addr)
		}
	}
}
