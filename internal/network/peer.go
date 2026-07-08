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
	// handshake retransmit cadence.
	handshakeInterval = 150 * time.Millisecond
	// handshakeAggressiveAttempts is how many retransmits stay at the aggressive
	// cadence (≈6s of hole punching) before the interval backs off, so a peer that
	// is gone for good is not flooded at 150ms forever.
	handshakeAggressiveAttempts = 40
	// handshakeMaxInterval caps the backed-off retransmit interval. It stays well
	// under typical NAT UDP mapping timeouts (~30s) so the punch keeps the mapping
	// open while we wait for the peer to come back.
	handshakeMaxInterval = 5 * time.Second
	// retryWindow bounds how long a re-armed handshake (after a keepalive timeout)
	// keeps retrying before the session is parked. A parked session is revived by
	// an inbound msg1 or a fresh rendezvous announcement.
	retryWindow = 5 * time.Minute
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
	established bool
	// driving is true while a handshake is in flight (armed and not yet
	// established). It is cleared the moment the session establishes — not when
	// the retransmit goroutine notices and exits — so a re-arm cannot be blocked
	// by a driver that is merely sleeping between retransmits.
	driving bool
	// driverGen identifies the current driveHandshake goroutine. Re-arming bumps
	// it, so a superseded driver exits without touching the new driver's state.
	driverGen uint64
	initMsg   []byte // initiator: cached msg1 packet, retransmitted until established
	respMsg   []byte // responder: cached msg2 packet, retransmitted on duplicate msg1

	// Anti-replay window for the receive direction (WireGuard/IPsec style).
	// replayMax is the highest counter accepted so far; replayBits is a bitmap of
	// the replayWindow counters ending at replayMax (bit i ⇒ counter replayMax-i seen).
	replayMax  uint64
	replayBits uint64
}

// replayWindow is the width of the anti-replay sliding window, in packets.
const replayWindow = 64

// checkReplayLocked reports whether counter is fresh (neither already seen nor
// older than the window) and records it. It must be called with s.mu held, only
// after the packet has been successfully authenticated, so that a forged packet
// can never advance or poke holes in the window.
func (s *peerSession) checkReplayLocked(counter uint64) bool {
	if counter > s.replayMax {
		shift := counter - s.replayMax
		if shift >= replayWindow {
			s.replayBits = 0
		} else {
			s.replayBits <<= shift
		}
		s.replayBits |= 1 // bit 0 marks the new replayMax
		s.replayMax = counter
		return true
	}
	// counter <= replayMax: it must fall within the window and not be seen yet.
	diff := s.replayMax - counter
	if diff >= replayWindow {
		return false // too old
	}
	mask := uint64(1) << diff
	if s.replayBits&mask != 0 {
		return false // replay
	}
	s.replayBits |= mask
	return true
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
	if s.established || s.driving {
		// A handshake is already established or in flight (e.g. a responder session
		// created on inbound msg1). Just record the expected key for later validation.
		if s.expected == nil {
			s.expected = key
		}
		s.mu.Unlock()
		return nil
	}
	gen, err := p.armHandshakeLocked(s, key)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()

	go p.driveHandshake(s, gen, time.Time{})
	return nil
}

// armHandshakeLocked (re)builds the handshake state for a session toward the peer
// with static key `key`, replacing any stale in-flight state, and returns the
// generation the caller must pass to the driveHandshake goroutine it starts. It
// must be called with s.mu held and only when the session is neither established
// nor driving (driving is set here so a concurrent arm cannot double-start).
func (p *PeerConn) armHandshakeLocked(s *peerSession, key []byte) (uint64, error) {
	s.expected = key
	s.hs = nil
	s.initMsg, s.respMsg = nil, nil
	// Deterministic role assignment with no negotiation: the peer with the smaller
	// static public key is the Noise initiator. Distinct keys guarantee no tie.
	s.initiator = bytes.Compare(p.static.Public, key) < 0
	if s.initiator {
		hs, err := newInitiatorHandshake(p.static, key, p.psk, p.prologue)
		if err != nil {
			return 0, err
		}
		msg1, _, _, err := hs.WriteMessage(nil, nil)
		if err != nil {
			return 0, err
		}
		s.hs = hs
		s.initMsg = buildPacket(PacketHandshakeInit, msg1)
	}
	s.driving = true
	s.driverGen++
	return s.driverGen, nil
}

// driveHandshake retransmits handshake traffic until the session is established,
// the deadline (if any) passes, or Shutdown is called. The initiator resends msg1
// (which doubles as a NAT hole-punch); the responder sends empty punch packets to
// open its NAT mapping while it waits for msg1.
//
// A zero deadline (rendezvous-driven handshakes) retries for as long as the
// connection lives rather than giving up after a fixed window: a peer that misses
// the initial hole-punch (transient NAT churn or packet loss) must still be able
// to connect. Re-armed handshakes after a keepalive timeout pass a bounded
// deadline; when it expires the session is parked (driving=false), from where an
// inbound msg1 or a fresh AddKnownPeer can revive it. The retransmit cadence backs
// off after the aggressive hole-punch phase so an absent peer is not flooded. The
// loop is bounded by p.stop, so it stops promptly on shutdown and is not a
// goroutine leak.
func (p *PeerConn) driveHandshake(s *peerSession, gen uint64, deadline time.Time) {
	defer func() {
		s.mu.Lock()
		// Only clear driving if this driver is still the current one: a re-arm may
		// have superseded us (bumping driverGen) while we slept.
		if s.driverGen == gen {
			s.driving = false
		}
		s.mu.Unlock()
	}()
	punch := buildPacket(PacketPunch, nil)
	interval := handshakeInterval
	attempts := 0
	for {
		s.mu.Lock()
		superseded := s.driverGen != gen
		established := s.established
		initiator := s.initiator
		initMsg := s.initMsg
		s.mu.Unlock()
		if superseded || established {
			return
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			return
		}
		if initiator && initMsg != nil {
			p.conn.WriteToUDP(initMsg, s.addr)
		} else {
			p.conn.WriteToUDP(punch, s.addr)
		}
		attempts++
		if attempts >= handshakeAggressiveAttempts && interval < handshakeMaxInterval {
			interval *= 2
			if interval > handshakeMaxInterval {
				interval = handshakeMaxInterval
			}
		}
		select {
		case <-p.stop:
			return
		case <-time.After(interval):
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
		case PacketControl:
			plaintext, err := p.openTransport(addr, buf[:n])
			if err != nil || len(plaintext) < 1 {
				continue
			}
			switch plaintext[0] {
			case CtrlPing:
				UpdateLastSeen()
				p.sendControl(addr, CtrlPong)
			case CtrlPong:
				UpdateLastSeen()
				p.mu.Lock()
				p.missedPings[addr.String()] = 0
				p.mu.Unlock()
			case CtrlDead:
				// Authenticated "I'm leaving" from the peer: drop its session, surface
				// a Dead event, and keep reading — other peers are unaffected.
				p.RemovePeer(addr)
			}
			continue
		case PacketData, PacketTun:
			plaintext, err := p.openTransport(addr, buf[:n])
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
	s.driving = false // the retransmit driver will notice and exit; the session may be re-armed before then
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
	s.driving = false // the retransmit driver will notice and exit; the session may be re-armed before then
	s.mu.Unlock()

	p.fireConnected(addr)
}

// transportHeaderLen is the cleartext prefix [version][type][counter] that also
// serves as the AEAD additional data.
const transportHeaderLen = 2 + counterLen

// openTransport authenticates and decrypts a transport packet
// [version][type][counter][ct], enforcing the anti-replay window. The 10-byte
// header is used as AAD, so the type and counter are authenticated.
func (p *PeerConn) openTransport(addr *net.UDPAddr, pkt []byte) ([]byte, error) {
	if len(pkt) < transportHeaderLen {
		return nil, fmt.Errorf("transport packet too short")
	}
	header := pkt[:transportHeaderLen]
	counter := binary.BigEndian.Uint64(pkt[2:transportHeaderLen])
	ct := pkt[transportHeaderLen:]

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
	// The counter is the AEAD nonce; using it directly lets us decrypt out of order.
	s.rx.SetNonce(counter)
	plaintext, err := s.rx.Decrypt(nil, header, ct)
	if err != nil {
		return nil, err
	}
	// Only after authentication do we consult the replay window, so a forged packet
	// can never advance it or punch a hole in it.
	if !s.checkReplayLocked(counter) {
		return nil, fmt.Errorf("replayed or out-of-window packet from %s", addr)
	}
	return plaintext, nil
}

func (p *PeerConn) send(addr *net.UDPAddr, data []byte, pktType byte) error {
	p.mu.Lock()
	s, ok := p.sessions[addr.String()]
	p.mu.Unlock()
	if !ok {
		return fmt.Errorf("unknown peer: %s", addr)
	}
	header := make([]byte, transportHeaderLen)
	header[0] = ProtocolVersion
	header[1] = pktType

	s.mu.Lock()
	if !s.established || s.tx == nil {
		s.mu.Unlock()
		return fmt.Errorf("peer %s not established", addr)
	}
	counter := s.tx.Nonce()
	binary.BigEndian.PutUint64(header[2:], counter)
	// AAD is the cleartext header (version, type, counter). Append the ciphertext
	// after the header in a single buffer so the returned slice is the whole packet.
	pkt, err := s.tx.Encrypt(header, header, data)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	_, err = p.conn.WriteToUDP(pkt, addr)
	return err
}

// sendControl sends an encrypted control message (ping/pong/dead) over the same
// authenticated, anti-replay-protected transport as data.
func (p *PeerConn) sendControl(addr *net.UDPAddr, opcode byte) error {
	return p.send(addr, []byte{opcode}, PacketControl)
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
	// Deliver reliably: block until the consumer takes the event, or until shutdown.
	// Dropping it would leave the peer without a virtual-IP mapping, so all of its
	// tunnel traffic would be silently discarded for the rest of the session. This
	// runs after s.mu is released, so blocking here cannot deadlock a session.
	select {
	case p.Connected <- addr:
	case <-p.stop:
	}
}

func (p *PeerConn) dropSession(addr *net.UDPAddr) {
	p.mu.Lock()
	delete(p.sessions, addr.String())
	delete(p.missedPings, addr.String())
	p.mu.Unlock()
}

// fireDead delivers a Dead event reliably (mirror of fireConnected): dropping it
// would leave consumers with stale virtual-IP mappings for the rest of the
// session, so block until the consumer takes it or shutdown. Consumers of a
// PeerConn must therefore drain Dead just like Connected.
func (p *PeerConn) fireDead(addr *net.UDPAddr) {
	select {
	case p.Dead <- addr:
	case <-p.stop:
	}
}

// RemovePeer drops a peer's session entirely and notifies the Dead channel. Used
// for graceful departures (the peer said it is leaving); if the peer comes back it
// will be re-announced by the rendezvous and re-added via AddKnownPeer.
func (p *PeerConn) RemovePeer(addr *net.UDPAddr) {
	p.dropSession(addr)
	p.fireDead(addr)
}

// TimeoutPeer declares a peer dead after missed keepalives: consumers get a Dead
// event so they drop mappings, and the handshake is re-armed for a bounded window
// so the session heals on its own if the outage was transient (the peer never
// told the rendezvous it left, so nothing else would ever reconnect the two).
func (p *PeerConn) TimeoutPeer(addr *net.UDPAddr) {
	p.mu.Lock()
	delete(p.missedPings, addr.String())
	p.mu.Unlock()
	p.retryHandshake(addr)
	p.fireDead(addr)
}

// retryHandshake resets an established-but-unresponsive session back to the
// handshake phase, reusing the static key authenticated by the previous handshake
// as the pinned key for the next one. The retry is bounded by retryWindow; after
// that the session is parked until an inbound msg1 or AddKnownPeer revives it.
func (p *PeerConn) retryHandshake(addr *net.UDPAddr) {
	p.mu.Lock()
	s, ok := p.sessions[addr.String()]
	p.mu.Unlock()
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.established || s.driving {
		return
	}
	remote := s.remoteStatic
	if remote == nil {
		remote = s.expected
	}
	if remote == nil {
		return
	}
	s.established = false
	s.tx, s.rx = nil, nil
	s.remoteStatic = nil
	s.replayMax, s.replayBits = 0, 0
	gen, err := p.armHandshakeLocked(s, remote)
	if err != nil {
		return
	}
	go p.driveHandshake(s, gen, time.Now().Add(retryWindow))
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

// BroadcastDead sends an encrypted, authenticated "peer is dead" control message
// to every established peer. Used on shutdown so peers tear down promptly; because
// it rides the encrypted channel, an attacker cannot forge it to disconnect a peer.
func (p *PeerConn) BroadcastDead() {
	for _, addr := range p.establishedPeers() {
		p.sendControl(addr, CtrlDead)
	}
}
