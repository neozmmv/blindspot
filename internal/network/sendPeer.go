package network

import (
	"net"
)

func SendToPeer(conn *net.UDPConn, peerAddr *net.UDPAddr, sharedKey []byte) error {}
