package network

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/neozmmv/blindspot/internal/crypto"
)

type PeerConn struct {
	conn       *net.UDPConn
	privateKey []byte
	publicKey  []byte
	sharedKeys map[string][]byte // addr → sharedKey
	mu         sync.Mutex
	Connected  chan *net.UDPAddr // signals when a new peer connects
}

func NewPeerConn(conn *net.UDPConn, privateKey, publicKey []byte) *PeerConn {
	return &PeerConn{
		conn:       conn,
		privateKey: privateKey,
		publicKey:  publicKey,
		sharedKeys: map[string][]byte{},
		Connected:  make(chan *net.UDPAddr, 10),
	}
}

func (p *PeerConn) AddPeer(addr *net.UDPAddr, peerPublicKey []byte) error {
	sharedKey, err := crypto.DeriveSharedKey(p.privateKey, peerPublicKey)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.sharedKeys[addr.String()] = sharedKey
	p.mu.Unlock()
	p.Connected <- addr
	return nil
}

func (p *PeerConn) Send(addr *net.UDPAddr, data []byte) error {
	p.mu.Lock()
	sharedKey, ok := p.sharedKeys[addr.String()]
	p.mu.Unlock()
	if !ok {
		return fmt.Errorf("unknown peer: %s", addr)
	}
	return SendToPeer(p.conn, addr, sharedKey, data)
}

func (p *PeerConn) Read() ([]byte, *net.UDPAddr, error) {
	buf := make([]byte, 1024)
	for {
		n, addr, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			return nil, nil, fmt.Errorf("error reading from peer: %w", err)
		}
		switch buf[0] {
		case PacketHello:
			// peer wants to connect, add to peer list and respond with HELLO + pubkey
			peerPublicKey := buf[1:n]
			p.conn.WriteToUDP(append([]byte{PacketHello}, p.publicKey...), addr)
			p.AddPeer(addr, peerPublicKey)
			continue
		case PacketPing:
			UpdateLastSeen()
			p.conn.WriteToUDP([]byte{PacketPong}, addr)
			continue
		case PacketDead:
			p.mu.Lock()
			delete(p.sharedKeys, addr.String())
			p.mu.Unlock()
			return nil, addr, fmt.Errorf("peer is dead")
		case PacketData:
			p.mu.Lock()
			sharedKey, ok := p.sharedKeys[addr.String()]
			p.mu.Unlock()
			if !ok {
				continue // packet from unknown peer
			}
			plaintext, err := crypto.DecryptBytes(sharedKey, buf[1:n])
			if err != nil {
				continue
			}
			return plaintext, addr, nil
		}
	}
}

func (p *PeerConn) PunchHole(peerAddr *net.UDPAddr) {
	packet := make([]byte, 1+len(p.publicKey))
	packet[0] = PacketHello
	copy(packet[1:], p.publicKey)
	for i := 0; i < 50; i++ {
		p.conn.WriteToUDP(packet, peerAddr)
		time.Sleep(100 * time.Millisecond)
	}
}
