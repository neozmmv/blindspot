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

func WatchConnection(conn *net.UDPConn) error {
	for {
		time.Sleep(30 * time.Second)
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
