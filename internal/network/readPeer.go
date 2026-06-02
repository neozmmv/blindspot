package network

import (
	"fmt"
	"net"
	"strings"
)

func ReadFromPeer(conn *net.UDPConn) ([]byte, *net.UDPAddr, error) {
	buf := make([]byte, 1024)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil, nil, fmt.Errorf("error reading from peer: %w", err)
		}
		// BLINDSPOT PROTOCOL KEYWORDS

		if strings.HasPrefix(string(buf[:n]), "HELLO") {
			// HELLO should be responded in the handshake.go file, so we just ignore it here
			continue
		}

		if string(buf[:n]) == "PING" {
			/* conn.WriteToUDP([]byte("PONG"), addr) */ //  respond somewhere else
			continue
		}

		return buf[:n], addr, nil
	}
}
