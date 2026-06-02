package network

import (
	"fmt"
	"net"

	"github.com/neozmmv/blindspot/internal/crypto"
)

func SendToPeer(conn *net.UDPConn, peerAddr *net.UDPAddr, sharedKey []byte, data []byte) error {
	// encrypt data with shared key and send to peer
	encrypted, err := crypto.EncryptBytes(sharedKey, data)
	if err != nil {
		return fmt.Errorf("Error encrypting data: %v\n", err)
	}

	packet := append([]byte{PacketData}, encrypted...)
	_, err = conn.WriteToUDP(packet, peerAddr)
	if err != nil {
		return fmt.Errorf("Error sending data to peer: %v\n", err)
	}
	return nil
}
