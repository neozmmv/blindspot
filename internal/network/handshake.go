package network

import (
	"fmt"
	"net"

	"github.com/pion/stun"
)

func OpenUDPConn() (*net.UDPConn, string, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		fmt.Printf("Error listening on UDP: %v\n", err)
		return nil, "", err
	}

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

// BLINDSPOT PROTOCOL
// HELLO <public key> - sent by initiator to responder to start handshake
// HELLO <public key> - sent by responder to initiator in response to HELLO
func PunchHole(conn *net.UDPConn, peerAddr *net.UDPAddr) {
	// public key will be added later, but it should be exchanged here
	for i := 0; i < 50; i++ {
		conn.WriteToUDP([]byte("HELLO"), peerAddr)
	}
}
