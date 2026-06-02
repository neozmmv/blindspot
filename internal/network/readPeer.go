package network

import (
	"fmt"
	"net"

	"github.com/neozmmv/blindspot/internal/crypto"
)

func ReadFromPeer(conn *net.UDPConn, sharedKey []byte) ([]byte, *net.UDPAddr, error) {
	// all bytes after the first are encrypted
	// decrypt with the shared key and return the plaintext
	buf := make([]byte, 1024)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil, nil, fmt.Errorf("error reading from peer: %w", err)
		}
		// BLINDSPOT PROTOCOL KEYWORDS

		if buf[0] == PacketHello {
			// HELLO should be responded in the handshake.go file, so we just ignore it here
			continue
		}

		if buf[0] == PacketPing {
			/* conn.WriteToUDP([]byte("PONG"), addr) */ //  respond somewhere else
			UpdateLastSeen()
			conn.WriteToUDP([]byte{PacketPong}, addr)
			continue
		}

		if buf[0] == PacketDead {
			// peer is dead, close connection
			return nil, nil, fmt.Errorf("peer is dead")
		}

		if buf[0] != PacketData {
			continue
		}

		plaintext, err := crypto.DecryptBytes(sharedKey, buf[1:n])
		if err != nil {
			return nil, nil, fmt.Errorf("error decrypting message: %w", err)
		}

		return plaintext, addr, nil
	}
}
