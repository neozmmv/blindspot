package network

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/neozmmv/blindspot/internal/crypto"
)

type PeerConn struct {
	conn           *net.UDPConn
	privateKey     []byte
	publicKey      []byte
	sharedKeys     map[string][]byte // addr → sharedKey
	peerPublicKeys map[string][]byte // addr → peerPublicKey
	peers          []*net.UDPAddr
	mu             sync.Mutex
	Connected      chan *net.UDPAddr // signals when a new peer connects
}

func NewPeerConn(conn *net.UDPConn, privateKey, publicKey []byte) *PeerConn {
	return &PeerConn{
		conn:           conn,
		privateKey:     privateKey,
		publicKey:      publicKey,
		sharedKeys:     map[string][]byte{},
		peerPublicKeys: map[string][]byte{},
		Connected:      make(chan *net.UDPAddr, 10),
	}
}

func (p *PeerConn) AddPeer(addr *net.UDPAddr, peerPublicKey []byte) error {
	sharedKey, err := crypto.DeriveSharedKey(p.privateKey, peerPublicKey)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.sharedKeys[addr.String()] = sharedKey
	p.peerPublicKeys[addr.String()] = peerPublicKey
	p.peers = append(p.peers, addr)
	p.mu.Unlock()
	p.Connected <- addr
	return nil
}

// PeerPublicKey returns the public key of the peer at the given address.
func (p *PeerConn) PeerPublicKey(addr *net.UDPAddr) ([]byte, bool) {
	p.mu.Lock()
	key, ok := p.peerPublicKeys[addr.String()]
	p.mu.Unlock()
	return key, ok
}

func (p *PeerConn) send(addr *net.UDPAddr, data []byte, pktType byte) error {
	p.mu.Lock()
	sharedKey, ok := p.sharedKeys[addr.String()]
	p.mu.Unlock()
	if !ok {
		return fmt.Errorf("unknown peer: %s", addr)
	}
	return SendToPeer(p.conn, addr, sharedKey, data, pktType)
}

func (p *PeerConn) Send(addr *net.UDPAddr, data []byte) error {
	return p.send(addr, data, PacketData)
}

func (p *PeerConn) SendTun(addr *net.UDPAddr, data []byte) error {
	return p.send(addr, data, PacketTun)
}

// Read returns the packet type, decrypted payload, sender address, and any error.
// Callers should filter on PacketData (chat) or PacketTun (VPN) as appropriate.
func (p *PeerConn) Read() (byte, []byte, *net.UDPAddr, error) {
	buf := make([]byte, 65536)
	for {
		n, addr, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			return 0, nil, nil, fmt.Errorf("error reading from peer: %w", err)
		}
		switch buf[0] {
		case PacketHello:
			peerPublicKey := buf[1:n]
			p.mu.Lock()
			_, alreadyConnected := p.sharedKeys[addr.String()]
			p.mu.Unlock()
			if !alreadyConnected {
				p.conn.WriteToUDP(append([]byte{PacketHello}, p.publicKey...), addr)
				p.AddPeer(addr, peerPublicKey)
				go p.PunchHole(addr)
			}
			continue
		case PacketPing:
			UpdateLastSeen()
			p.conn.WriteToUDP([]byte{PacketPong}, addr)
			continue
		case PacketDead:
			p.mu.Lock()
			delete(p.sharedKeys, addr.String())
			p.mu.Unlock()
			return PacketDead, nil, addr, fmt.Errorf("peer is dead")
		case PacketData, PacketTun:
			p.mu.Lock()
			sharedKey, ok := p.sharedKeys[addr.String()]
			p.mu.Unlock()
			if !ok {
				continue
			}
			plaintext, err := crypto.DecryptBytes(sharedKey, buf[1:n])
			if err != nil {
				continue
			}
			return buf[0], plaintext, addr, nil
		}
	}
}

func (p *PeerConn) PunchHole(peerAddr *net.UDPAddr) {
	packet := make([]byte, 1+len(p.publicKey))
	packet[0] = PacketHello
	copy(packet[1:], p.publicKey)
	for {
		p.mu.Lock()
		_, connected := p.sharedKeys[peerAddr.String()]
		p.mu.Unlock()
		if connected {
			return
		}
		p.conn.WriteToUDP(packet, peerAddr)
		time.Sleep(10 * time.Millisecond)
	}
}

func (p *PeerConn) Broadcast(data []byte) {
	p.mu.Lock()
	peers := make([]*net.UDPAddr, len(p.peers))
	copy(peers, p.peers)
	p.mu.Unlock()
	for _, addr := range peers {
		p.Send(addr, data)
	}
}

// BroadcastRaw sends raw data without encrypting or adding packet type
// for sending bytes that are already formatted with packet type, like PacketDead
// NOT ENCRYPTED!
func (p *PeerConn) BroadcastRaw(data []byte) {
	p.mu.Lock()
	peers := make([]*net.UDPAddr, len(p.peers))
	copy(peers, p.peers)
	p.mu.Unlock()
	for _, addr := range peers {
		p.conn.WriteToUDP(data, addr)
	}
}
