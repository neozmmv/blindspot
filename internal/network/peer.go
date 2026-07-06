package network

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/flynn/noise"
)

const (
	// handshake retransmit cadence and overall deadline.
	handshakeInterval = 150 * time.Millisecond
	handshakeMaxWait  = 20 * time.Second
	// counterLen is the width of the explicit per-packet counter carried in every
	// transport packet. The counter is used as the AEAD nonce so packets can be
	// decrypted out of order and after loss (UDP reorders and drops freely), unlike
	// Noise's implicit in-order nonce.
	counterLen = 8
)

// peerSession holds the per-peer handshake and transport state. All mutable
// fields are guarded by mu; a CipherState is not safe for concurrent use.
type peerSession struct {
	mu           sync.Mutex
	addr         *net.UDPAddr
	expected     []byte // static key the rendezvous published for this peer (nil until known)
	remoteStatic []byte // authenticated static key after the handshake completes
	initiator    bool
	hs           *noise.HandshakeState
	tx           *noise.CipherState // our send cipher (per-direction, from Noise split)
	rx           *noise.CipherState // our receive cipher
	established  bool
	initMsg      []byte // initiator: cached msg1 packet, retransmitted until established
	respMsg      []byte // responder: cached msg2 packet, retransmitted on duplicate msg1
}

type PeerConn struct {
	conn     *net.UDPConn
	static   noise.DHKey
	psk      []byte
	prologue []byte

	mu           sync.Mutex
	sessions     map[string]*peerSession // addr → session
	knownStatics map[string]bool         // hex(static) → allowed; the session allowlist from the rendezvous
	missedPings  map[string]int          // addr → consecutive unanswered pings

	Connected chan *net.UDPAddr // signals when a new peer completes the handshake
	Dead      chan *net.UDPAddr // signals when a peer is declared dead
	stop      chan struct{}     // closed by Shutdown to stop background loops
	stopOnce  sync.Once
}

// NewPeerConn creates a PeerConn. privateKey/publicKey are this peer's static
// X25519 keypair; psk is the Argon2id-derived pre-shared key (second factor);
// prologue binds the handshake to the protocol version and session id.
func NewPeerConn(conn *net.UDPConn, privateKey, publicKey, psk, prologue []byte) *PeerConn {
	return &PeerConn{
		conn:         conn,
		static:       noise.DHKey{Private: privateKey, Public: publicKey},
		psk:          psk,
		prologue:     prologue,
		sessions:     map[string]*peerSession{},
		knownStatics: map[string]bool{},
		missedPings:  map[string]int{},
		Connected:    make(chan *net.UDPAddr, 32),
		Dead:         make(chan *net.UDPAddr, 10),
		stop:         make(chan struct{}),
	}
}

// Shutdown signals background loops (handshake drivers) to stop. Safe to call
// multiple times; it does not close the underlying UDP connection.
func (p *PeerConn) Shutdown() {
	p.stopOnce.Do(func() { close(p.stop) })
}

func staticKeyHex(pub []byte) string { return hex.EncodeToString(pub) }

func (p *PeerConn) isKnownStatic(pub []byte) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.knownStatics[staticKeyHex(pub)]
}

// buildPacket frames body as [Version][pktType][body].
func buildPacket(pktType byte, body []byte) []byte {
	pkt := make([]byte, 2+len(body))
	pkt[0] = ProtocolVersion
	pkt[1] = pktType
	copy(pkt[2:], body)
	return pkt
}

// AddKnownPeer registers a peer learned from the trusted rendezvous: its UDP
// address and its static public key (the pubkey the rendezvous published). The
// key is added to the session allowlist, the local peer's handshake role is
// derived deterministically from the two static keys, and the handshake driver is
// started. Calling it again for the same peer is a no-op once a handshake is in
// flight.
func (p *PeerConn) AddKnownPeer(addr *net.UDPAddr, remoteStatic []byte) error {
	if len(remoteStatic) != 32 {
		return fmt.Errorf("invalid peer public key length: %d", len(remoteStatic))
	}
	// Copy the key: the caller's slice may alias a buffer that gets reused.
	key := make([]byte, 32)
	copy(key, remoteStatic)

	p.mu.Lock()
	p.knownStatics[staticKeyHex(key)] = true
	s, ok := p.sessions[addr.String()]
	if !ok {
		s = &peerSession{addr: addr}
		p.sessions[addr.String()] = s
	}
	p.mu.Unlock()

	s.mu.Lock()
	if s.established || s.hs != nil {
		// A handshake already exists (e.g. a responder session created on inbound
		// msg1). Just record the expected key for later validation.
		if s.expected == nil {
			s.expected = key
		}
		s.mu.Unlock()
		return nil
	}
	s.expected = key
	// Deterministic role assignment with no negotiation: the peer with the smaller
	// static public key is the Noise initiator. Distinct keys guarantee no tie.
	s.initiator = bytes.Compare(p.static.Public, key) < 0
	if s.initiator {
		hs, err := newInitiatorHandshake(p.static, key, p.psk, p.prologue)
		if err != nil {
			s.mu.Unlock()
			return err
		}
		msg1, _, _, err := hs.WriteMessage(nil, nil)
		if err != nil {
			s.mu.Unlock()
			return err
		}
		s.hs = hs
		s.initMsg = buildPacket(PacketHandshakeInit, msg1)
	}
	s.mu.Unlock()

	go p.driveHandshake(s)
	return nil
}

// driveHandshake retransmits handshake traffic until the session is established,
// the deadline passes, or Shutdown is called. The initiator resends msg1 (which
// doubles as a NAT hole-punch); the responder sends empty punch packets to open
// its NAT mapping while it waits for msg1.
func (p *PeerConn) driveHandshake(s *peerSession) {
	deadline := time.Now().Add(handshakeMaxWait)
	punch := buildPacket(PacketPunch, nil)
	for {
		s.mu.Lock()
		established := s.established
		initiator := s.initiator
		initMsg := s.initMsg
		s.mu.Unlock()
		if established || time.Now().After(deadline) {
			return
		}
		if initiator && initMsg != nil {
			p.conn.WriteToUDP(initMsg, s.addr)
		} else {
			p.conn.WriteToUDP(punch, s.addr)
		}
		select {
		case <-p.stop:
			return
		case <-time.After(handshakeInterval):
		}
	}
}

// Read returns the packet type, decrypted payload, sender address, and any error.
// Callers filter on PacketData (chat) or PacketTun (VPN). Handshake, punch, and
// keepalive packets are handled internally and never returned.
func (p *PeerConn) Read() (byte, []byte, *net.UDPAddr, error) {
	buf := make([]byte, 65536)
	for {
		n, addr, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			return 0, nil, nil, fmt.Errorf("error reading from peer: %w", err)
		}
		// Every packet is [version][type][body...]. Drop anything too short or with a
		// mismatched protocol version — no silent downgrade to an older protocol.
		if n < 2 || buf[0] != ProtocolVersion {
			continue
		}
		pktType := buf[1]
		body := buf[2:n]
		switch pktType {
		case PacketPunch:
			continue
		case PacketHandshakeInit:
			p.handleHandshakeInit(addr, body)
			continue
		case PacketHandshakeResp:
			p.handleHandshakeResp(addr, body)
			continue
		case PacketPing:
			UpdateLastSeen()
			p.conn.WriteToUDP(buildPacket(PacketPong, nil), addr)
			continue
		case PacketPong:
			UpdateLastSeen()
			p.mu.Lock()
			p.missedPings[addr.String()] = 0
			p.mu.Unlock()
			continue
		case PacketDead:
			p.dropSession(addr)
			return PacketDead, nil, addr, fmt.Errorf("peer is dead")
		case PacketData, PacketTun:
			plaintext, err := p.decrypt(addr, body)
			if err != nil {
				continue
			}
			return pktType, plaintext, addr, nil
		}
	}
}

// handleHandshakeInit processes an inbound Noise msg1 (we are the responder).
func (p *PeerConn) handleHandshakeInit(addr *net.UDPAddr, msg1 []byte) {
	p.mu.Lock()
	s, ok := p.sessions[addr.String()]
	if !ok {
		// A msg1 may arrive before the rendezvous stream told us about this peer.
		// Create a provisional session; the initiator's static is still validated
		// against the session allowlist below.
		s = &peerSession{addr: addr}
		p.sessions[addr.String()] = s
	}
	p.mu.Unlock()

	s.mu.Lock()
	if s.established {
		// Retransmit our cached msg2 in case the initiator's copy was lost.
		resp := s.respMsg
		s.mu.Unlock()
		if resp != nil {
			p.conn.WriteToUDP(resp, addr)
		}
		return
	}
	// If we already took the initiator role for this addr, ignore inbound msg1.
	if s.initiator && s.hs != nil {
		s.mu.Unlock()
		return
	}
	if s.hs == nil {
		hs, err := newResponderHandshake(p.static, p.psk, p.prologue)
		if err != nil {
			s.mu.Unlock()
			return
		}
		s.hs = hs
		s.initiator = false
	}
	if _, _, _, err := s.hs.ReadMessage(nil, msg1); err != nil {
		// Bad msg1 (corrupt, wrong prologue, replay): reset so a fresh msg1 retries.
		s.hs = nil
		s.mu.Unlock()
		return
	}
	remote := s.hs.PeerStatic()
	// The initiator's static must be a key the trusted rendezvous published for
	// this session, and must match what we expected for this addr if we knew it.
	// This is what stops a malicious member (or on-path attacker) from completing a
	// handshake with an unknown key.
	if !p.isKnownStatic(remote) || (s.expected != nil && !bytes.Equal(remote, s.expected)) {
		s.hs = nil
		s.mu.Unlock()
		return
	}
	msg2, cs0, cs1, err := s.hs.WriteMessage(nil, nil)
	if err != nil {
		s.hs = nil
		s.mu.Unlock()
		return
	}
	// Responder: send with cs1 (responder→initiator), receive with cs0 (initiator→responder).
	s.tx, s.rx = cs1, cs0
	s.remoteStatic = append([]byte(nil), remote...)
	s.respMsg = buildPacket(PacketHandshakeResp, msg2)
	s.established = true
	resp := s.respMsg
	s.mu.Unlock()

	p.conn.WriteToUDP(resp, addr)
	p.fireConnected(addr)
}

// handleHandshakeResp processes an inbound Noise msg2 (we are the initiator).
func (p *PeerConn) handleHandshakeResp(addr *net.UDPAddr, msg2 []byte) {
	p.mu.Lock()
	s, ok := p.sessions[addr.String()]
	p.mu.Unlock()
	if !ok {
		return
	}
	s.mu.Lock()
	if s.established || !s.initiator || s.hs == nil {
		s.mu.Unlock()
		return
	}
	_, cs0, cs1, err := s.hs.ReadMessage(nil, msg2)
	if err != nil {
		// Wrong PSK or tampered msg2: stay unestablished and keep retransmitting
		// msg1. This is exactly what bars a forged responder key when the PSK is the
		// only thing the attacker lacks.
		s.mu.Unlock()
		return
	}
	// Defense in depth: the responder static was pinned in the config, so this is
	// always the rendezvous-published key, but confirm it anyway.
	remote := s.hs.PeerStatic()
	if s.expected != nil && !bytes.Equal(remote, s.expected) {
		s.mu.Unlock()
		return
	}
	// Initiator: send with cs0 (initiator→responder), receive with cs1 (responder→initiator).
	s.tx, s.rx = cs0, cs1
	s.remoteStatic = append([]byte(nil), remote...)
	s.established = true
	s.mu.Unlock()

	p.fireConnected(addr)
}

// decrypt authenticates and decrypts a transport packet body ([counter][ct]).
func (p *PeerConn) decrypt(addr *net.UDPAddr, body []byte) ([]byte, error) {
	p.mu.Lock()
	s, ok := p.sessions[addr.String()]
	p.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("unknown peer: %s", addr)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.established || s.rx == nil {
		return nil, fmt.Errorf("peer %s not established", addr)
	}
	if len(body) < counterLen {
		return nil, fmt.Errorf("transport packet too short")
	}
	counter := binary.BigEndian.Uint64(body[:counterLen])
	// The counter is the AEAD nonce; using it directly lets us decrypt out of order.
	// Tampering with the counter changes the nonce and fails the tag, so it is
	// implicitly authenticated. (The sliding-window replay check is added later.)
	s.rx.SetNonce(counter)
	return s.rx.Decrypt(nil, nil, body[counterLen:])
}

func (p *PeerConn) send(addr *net.UDPAddr, data []byte, pktType byte) error {
	p.mu.Lock()
	s, ok := p.sessions[addr.String()]
	p.mu.Unlock()
	if !ok {
		return fmt.Errorf("unknown peer: %s", addr)
	}
	s.mu.Lock()
	if !s.established || s.tx == nil {
		s.mu.Unlock()
		return fmt.Errorf("peer %s not established", addr)
	}
	counter := s.tx.Nonce()
	ct, err := s.tx.Encrypt(nil, nil, data)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	pkt := make([]byte, 2+counterLen+len(ct))
	pkt[0] = ProtocolVersion
	pkt[1] = pktType
	binary.BigEndian.PutUint64(pkt[2:], counter)
	copy(pkt[2+counterLen:], ct)
	_, err = p.conn.WriteToUDP(pkt, addr)
	return err
}

func (p *PeerConn) Send(addr *net.UDPAddr, data []byte) error {
	return p.send(addr, data, PacketData)
}

func (p *PeerConn) SendTun(addr *net.UDPAddr, data []byte) error {
	return p.send(addr, data, PacketTun)
}

// PeerPublicKey returns the authenticated static public key of the established
// peer at addr. The key is authenticated because it came from the trusted
// rendezvous and was verified by the Noise handshake.
func (p *PeerConn) PeerPublicKey(addr *net.UDPAddr) ([]byte, bool) {
	p.mu.Lock()
	s, ok := p.sessions[addr.String()]
	p.mu.Unlock()
	if !ok {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.established || s.remoteStatic == nil {
		return nil, false
	}
	return s.remoteStatic, true
}

func (p *PeerConn) fireConnected(addr *net.UDPAddr) {
	p.mu.Lock()
	p.missedPings[addr.String()] = 0
	p.mu.Unlock()
	select {
	case p.Connected <- addr:
	default:
	}
}

func (p *PeerConn) dropSession(addr *net.UDPAddr) {
	p.mu.Lock()
	delete(p.sessions, addr.String())
	delete(p.missedPings, addr.String())
	p.mu.Unlock()
}

func (p *PeerConn) RemovePeer(addr *net.UDPAddr) {
	p.dropSession(addr)
	select {
	case p.Dead <- addr:
	default:
	}
}

// establishedPeers returns the addresses of all currently established peers.
func (p *PeerConn) establishedPeers() []*net.UDPAddr {
	p.mu.Lock()
	all := make([]*peerSession, 0, len(p.sessions))
	for _, s := range p.sessions {
		all = append(all, s)
	}
	p.mu.Unlock()
	var out []*net.UDPAddr
	for _, s := range all {
		s.mu.Lock()
		est := s.established
		addr := s.addr
		s.mu.Unlock()
		if est {
			out = append(out, addr)
		}
	}
	return out
}

func (p *PeerConn) HasPeers() bool {
	return len(p.establishedPeers()) > 0
}

func (p *PeerConn) Broadcast(data []byte) {
	for _, addr := range p.establishedPeers() {
		p.Send(addr, data)
	}
}

// BroadcastRaw sends already-framed bytes to every established peer without
// encrypting. Used for the cleartext PacketDead shutdown notice.
func (p *PeerConn) BroadcastRaw(data []byte) {
	for _, addr := range p.establishedPeers() {
		p.conn.WriteToUDP(data, addr)
	}
}
