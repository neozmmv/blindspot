package network

import (
	"fmt"
	"net"
	"time"

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
// HELLO PACKET is 0x01 followed by 32 bytes of public key (as defined in protocol.go)
func PunchHole(conn *net.UDPConn, peerAddr *net.UDPAddr, publicKey []byte) {
	for i := 0; i < 50; i++ {
		conn.WriteToUDP(append([]byte{PacketHello}, publicKey...), peerAddr)
		time.Sleep(100 * time.Millisecond)
	}
}

func WaitForHello(conn *net.UDPConn) ([]byte, error) {
	// waits for HELLO and closes the connected channel when it receives a HELLO
	buf := make([]byte, 1024)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil, fmt.Errorf("error reading from peer: %w", err)
		}
		if n > 0 && buf[0] == PacketHello {
			if n != 33 { // 1 byte for PacketHello + 32 bytes for public key
				fmt.Println("Invalid HELLO packet received")
				continue
			}
			return buf[1:n], nil // return the public key
		}
	}
}
