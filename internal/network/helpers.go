package network

import (
	"fmt"
	"net"
	"time"
)

var lastSeen time.Time

// goroutine to keep the connection alive
// sends 0x1 byte every 10s to the peer
func KeepAlive(conn *net.UDPConn, peerAddr *net.UDPAddr) {
	for {
		time.Sleep(10 * time.Second)
		conn.WriteToUDP([]byte{PacketPing}, peerAddr)
	}
}

func WatchConnection(conn *net.UDPConn) {
	for {
		time.Sleep(30 * time.Second)
		if time.Since(lastSeen) > 30*time.Second {
			fmt.Println("Connection lost...")
			conn.Close()
			return
		}
	}
}

func UpdateLastSeen() {
	lastSeen = time.Now()
}
