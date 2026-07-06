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
	missedPings    map[string]int // addr → consecutive unanswered pings
	mu             sync.Mutex
	Connected      chan *net.UDPAddr // signals when a new peer connects
	Dead           chan *net.UDPAddr // signals when a peer is declared dead
	stop           chan struct{}     // closed by Shutdown to stop background loops (e.g. PunchHole)
	stopOnce       sync.Once
}

func NewPeerConn(conn *net.UDPConn, privateKey, publicKey []byte) *PeerConn {
	return &PeerConn{
		conn:           conn,
		privateKey:     privateKey,
		publicKey:      publicKey,
		sharedKeys:     map[string][]byte{},
		peerPublicKeys: map[string][]byte{},
		missedPings:    map[string]int{},
		Connected:      make(chan *net.UDPAddr, 10),
		Dead:           make(chan *net.UDPAddr, 10),
		stop:           make(chan struct{}),
	}
}

// Shutdown signals background loops (such as PunchHole) to stop. It is safe to
// call multiple times and does not close the underlying UDP connection.
func (p *PeerConn) Shutdown() {
	p.stopOnce.Do(func() { close(p.stop) })
}

func (p *PeerConn) AddPeer(addr *net.UDPAddr, peerPublicKey []byte) error {
	if len(peerPublicKey) != 32 {
		return fmt.Errorf("invalid peer public key length: %d", len(peerPublicKey))
	}
	// Copy the key before storing it: the caller's slice may alias a reused read
	// buffer that the next ReadFromUDP will overwrite, corrupting the stored key.
	keyCopy := make([]byte, len(peerPublicKey))
	copy(keyCopy, peerPublicKey)
	sharedKey, err := crypto.DeriveSharedKey(p.privateKey, keyCopy)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.sharedKeys[addr.String()] = sharedKey
	p.peerPublicKeys[addr.String()] = keyCopy
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
		// Guard against empty datagrams before indexing buf[0]. A zero-length UDP
		// packet is legal; without this, buf[0] reads stale data and buf[1:n] with
		// n==0 (buf[1:0]) panics with a slice-bounds-out-of-range.
		if n < 1 {
			continue
		}
		switch buf[0] {
		case PacketHello:
			// A HELLO is exactly 1 type byte + 32-byte public key. Reject any other
			// length instead of slicing with an attacker-controlled n.
			if n != 33 {
				continue
			}
			peerPublicKey := buf[1:n]
			p.mu.Lock()
			_, alreadyConnected := p.sharedKeys[addr.String()]
			p.mu.Unlock()
			if !alreadyConnected {
				p.conn.WriteToUDP(append([]byte{PacketHello}, p.publicKey...), addr)
				// AddPeer copies the key internally; check its error so a bad key
				// doesn't silently start a punch loop against a half-open peer.
				if err := p.AddPeer(addr, peerPublicKey); err != nil {
					continue
				}
				go p.PunchHole(addr)
			}
			continue
		case PacketPing:
			UpdateLastSeen()
			p.conn.WriteToUDP([]byte{PacketPong}, addr)
			continue
		case PacketPong:
			UpdateLastSeen()
			p.mu.Lock()
			p.missedPings[addr.String()] = 0
			p.mu.Unlock()
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

func (p *PeerConn) RemovePeer(addr *net.UDPAddr) {
	p.mu.Lock()
	delete(p.sharedKeys, addr.String())
	delete(p.peerPublicKeys, addr.String())
	delete(p.missedPings, addr.String())
	for i, a := range p.peers {
		if a.String() == addr.String() {
			p.peers = append(p.peers[:i], p.peers[i+1:]...)
			break
		}
	}
	p.mu.Unlock()
	select {
	case p.Dead <- addr:
	default:
	}
}

const (
	punchInterval     = 100 * time.Millisecond
	punchMaxAttempts  = 200              // upper bound on packets sent per peer
	punchTotalTimeout = 20 * time.Second // give up hole-punching after this window
)

func (p *PeerConn) PunchHole(peerAddr *net.UDPAddr) {
	packet := make([]byte, 1+len(p.publicKey))
	packet[0] = PacketHello
	copy(packet[1:], p.publicKey)
	deadline := time.Now().Add(punchTotalTimeout)
	// Bounded loop: stop once connected, after a fixed number of attempts, past the
	// total deadline, or when Shutdown is called. This prevents a leaked goroutine
	// that punches forever at a peer that never answers.
	for range punchMaxAttempts {
		p.mu.Lock()
		_, connected := p.sharedKeys[peerAddr.String()]
		p.mu.Unlock()
		if connected || time.Now().After(deadline) {
			return
		}
		p.conn.WriteToUDP(packet, peerAddr)
		select {
		case <-p.stop:
			return
		case <-time.After(punchInterval):
		}
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
func (p *PeerConn) HasPeers() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.sharedKeys) > 0
}

func (p *PeerConn) BroadcastRaw(data []byte) {
	p.mu.Lock()
	peers := make([]*net.UDPAddr, len(p.peers))
	copy(peers, p.peers)
	p.mu.Unlock()
	for _, addr := range peers {
		p.conn.WriteToUDP(data, addr)
	}
}
