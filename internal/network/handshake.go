package network

import (
	"fmt"
	"net"

	"github.com/pion/stun"
)

// OpenUDPConn opens a UDP socket on an ephemeral port and discovers this host's
// public address via a STUN binding request to Google's STUN server.
func OpenUDPConn() (*net.UDPConn, string, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		fmt.Printf("Error listening on UDP: %v\n", err)
		return nil, "", err
	}

	// Large kernel socket buffers (same 7 MB wireguard-go uses). The OS default
	// (~64 KB on Windows) holds only ~45 tunnel packets, so a burst from a fast
	// TCP sender overflows it while the reader goroutine is busy decrypting;
	// every drop looks like congestion to the tunnelled TCP stream and collapses
	// throughput. Best effort: the OS may clamp the value (e.g. Linux rmem_max).
	conn.SetReadBuffer(7 << 20)
	conn.SetWriteBuffer(7 << 20)

	// stun
	serverAddr, err := net.ResolveUDPAddr("udp", "stun.l.google.com:19302")
	if err != nil {
		fmt.Printf("Error resolving STUN server address: %v\n", err)
		return nil, "", err
	}

	// send bind request to google stun
	msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	conn.WriteToUDP(msg.Raw, serverAddr)

	buf := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		fmt.Printf("Error reading from STUN server: %v\n", err)
		return nil, "", err
	}

	// decode stun response to get public IP and port
	m := &stun.Message{Raw: buf[:n]}
	m.Decode()

	var xorAddr stun.XORMappedAddress
	xorAddr.GetFrom(m)

	publicAddr := fmt.Sprintf("%s:%d", xorAddr.IP, xorAddr.Port)
	return conn, publicAddr, nil
}
