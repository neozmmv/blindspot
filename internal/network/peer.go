package network

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flynn/noise"
	wgconn "golang.zx2c4.com/wireguard/conn"
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

// Adaptive upload shaping. A TCP flow inside the tunnel cannot sense the real
// bottleneck (the tunnel emits UDP at local line rate), so without shaping its
// growing window is fired as salvos that overflow the bottleneck queue in one
// go — burst loss TCP reads as a timeout, collapsing throughput. The shaper
// stays fully uncapped until CtrlAck feedback shows real path loss, then
// engages at the observed send rate and AIMD-tracks the path: multiplicative
// cut on loss, multiplicative probe upward while clean and utilized.
const (
	// ackInterval is how often the receive side reports delivery per session.
	ackInterval = 200 * time.Millisecond
	// ackMinPkts is the minimum packets per interval to treat the measured
	// loss as signal rather than noise.
	ackMinPkts = 50
	// paceChunk bounds packets per paced send so sleep slices stay in the
	// low-millisecond range where OS timers are accurate.
	paceChunk = 32
	// paceBurstCredit is how far the virtual clock may lag wall time: a small
	// burst allowance after idle without unbounded credit.
	paceBurstCredit = 5 * time.Millisecond
	// paceMinRate floors the shaper (2 Mbit/s) so a loss storm cannot choke
	// the tunnel to nothing; paceMaxRate is where shaping stops mattering and
	// the session returns to uncapped.
	paceMinRate = 250e3
	paceMaxRate = 1.5e9
	// Loss thresholds and AIMD gains per ack interval.
	lossEngage = 0.03 // engage/cut mildly above this
	lossSevere = 0.10 // cut hard above this
	paceGrow   = 1.25
	paceCut    = 0.85
	paceCutBig = 0.6
	// paceCutGuard spaces rate cuts so one loss event (reported across
	// consecutive acks) is not punished twice.
	paceCutGuard = 300 * time.Millisecond
)

// peerSession holds the per-peer handshake and transport state. All mutable
// fields are guarded by mu.
type peerSession struct {
	mu           sync.Mutex
	addr         *net.UDPAddr    // canonical remote address, for events and the public API
	key          string          // canonical addr string; the sessions-map key
	ep           wgconn.Endpoint // bind endpoint used for all sends to this peer
	expected     []byte          // static key the rendezvous published for this peer (nil until known)
	remoteStatic []byte          // authenticated static key after the handshake completes
	initiator    bool
	hs           *noise.HandshakeState
	established  bool
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

	// Transport crypto. At establishment the AES-256-GCM keys are extracted from
	// the Noise CipherStates (UnsafeKey) and turned into stateless cipher.AEAD
	// values: unlike a *noise.CipherState (whose implicit nonce makes every call
	// order-dependent), a cipher.AEAD with an explicit nonce is safe for
	// concurrent use — this is what lets a whole batch be sealed/opened in
	// parallel across cores. The wire format is byte-identical to what the
	// CipherStates produced: nonce = 4 zero bytes ‖ big-endian counter, AAD =
	// the 10-byte cleartext header.
	txAEAD cipher.AEAD
	rxAEAD cipher.AEAD
	txCtr  uint64 // next send counter (the AEAD nonce), guarded by mu

	// lastRx is when the last packet that passed AEAD authentication and the
	// replay window arrived from this peer. Guarded by mu. Any authenticated
	// packet proves liveness, so the keepalive must not declare a peer dead
	// while this is fresh — pongs alone are unreliable under congestion.
	lastRx time.Time

	// Receive-side delivery counters for CtrlAck generation, guarded by mu
	// with the rest of the receive state. rxMaxCtr/rxAccepted are cumulative
	// for the current keys; ackSentMax is the last rxMaxCtr already reported.
	rxMaxCtr   uint64
	rxAccepted uint64
	ackSentMax uint64

	// Send-side adaptive shaper state, guarded by paceMu (its own mutex so the
	// per-chunk pacing never contends with the receive path on mu). paceRate
	// is the current cap in bytes/sec, 0 = uncapped; paceNext is the virtual
	// clock; paceSentB accumulates bytes handed to the bind since the last
	// ack, giving the utilization and engage-rate measurements.
	paceMu     sync.Mutex
	paceRate   float64
	paceNext   time.Time
	paceSentB  uint64
	lastAckAt  time.Time
	lastAckMax uint64
	lastAckAcc uint64
	lastCut    time.Time

	// rekeyNotice is a prebuilt CtrlRekey packet sealed under the previous
	// session keys. driveHandshake retransmits it until the new handshake
	// establishes, so a peer that still holds the old session tears it down
	// and re-handshakes instead of answering fresh msg1s with its stale
	// cached msg2 (which deadlocks both sides until its keepalive times out).
	rekeyNotice []byte

	// Anti-replay window for the receive direction, guarded by mu like the rest
	// of the session state and consulted only after AEAD authentication.
	replay ReplayWindow
}

// aesgcmNonce builds the Noise-spec AESGCM nonce for counter n: 32 zero bits
// followed by the 64-bit big-endian counter (matches flynn/noise exactly).
func aesgcmNonce(n uint64) [12]byte {
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], n)
	return nonce
}

// installTransportKeysLocked derives the per-direction AEADs from the Noise
// split. The initiator sends with cs0 and receives with cs1; the responder the
// reverse. Must be called with s.mu held, before established is set.
func (s *peerSession) installTransportKeysLocked(cs0, cs1 *noise.CipherState) error {
	txCS, rxCS := cs0, cs1
	if !s.initiator {
		txCS, rxCS = cs1, cs0
	}
	txKey := txCS.UnsafeKey()
	rxKey := rxCS.UnsafeKey()
	txBlock, err := aes.NewCipher(txKey[:])
	if err != nil {
		return err
	}
	txAEAD, err := cipher.NewGCM(txBlock)
	if err != nil {
		return err
	}
	rxBlock, err := aes.NewCipher(rxKey[:])
	if err != nil {
		return err
	}
	rxAEAD, err := cipher.NewGCM(rxBlock)
	if err != nil {
		return err
	}
	s.txAEAD, s.rxAEAD = txAEAD, rxAEAD
	s.txCtr = 0
	s.rekeyNotice = nil
	// Fresh keys restart the counter space: reset the delivery bookkeeping but
	// keep paceRate — what we learned about the path survives a rekey.
	s.rxMaxCtr, s.rxAccepted, s.ackSentMax = 0, 0, 0
	s.paceMu.Lock()
	s.lastAckAt, s.lastAckMax, s.lastAckAcc = time.Time{}, 0, 0
	s.paceSentB = 0
	s.paceMu.Unlock()
	return nil
}

// decrypt authenticates and decrypts a full wire packet
// [version][type][counter][ct], appending the plaintext to dst. The 10-byte
// header is the AAD, so type and counter are authenticated; the anti-replay
// window is consulted only after authentication, so a forged packet can never
// advance it or punch a hole in it.
func (s *peerSession) decrypt(dst []byte, pkt []byte) ([]byte, error) {
	if len(pkt) < transportHeaderLen {
		return nil, errors.New("transport packet too short")
	}
	header := pkt[:transportHeaderLen]
	counter := binary.BigEndian.Uint64(pkt[2:transportHeaderLen])
	s.mu.Lock()
	aead := s.rxAEAD
	established := s.established
	s.mu.Unlock()
	if !established || aead == nil {
		return nil, fmt.Errorf("peer %s not established", s.addr)
	}
	nonce := aesgcmNonce(counter)
	plaintext, err := aead.Open(dst, nonce[:], pkt[transportHeaderLen:], header)
	if err != nil {
		Stats.RxDecryptFail.Add(1)
		return nil, err
	}
	s.mu.Lock()
	fresh := s.replay.Check(counter)
	if fresh {
		s.lastRx = time.Now()
		s.rxAccepted++
		if counter > s.rxMaxCtr {
			s.rxMaxCtr = counter
		}
	}
	s.mu.Unlock()
	if !fresh {
		Stats.RxReplayDrop.Add(1)
		return nil, fmt.Errorf("replayed or out-of-window packet from %s", s.addr)
	}
	return plaintext, nil
}

// rxPacket is a still-encrypted data/tun wire packet queued between the
// receive loops and the consumer (Read / ReadTunBatch). Decryption happens on
// the consumer side so batches can be opened in parallel; buf is pooled and
// owned by the consumer once dequeued.
type rxPacket struct {
	typ byte
	s   *peerSession
	buf []byte
}

type PeerConn struct {
	bind      wgconn.Bind
	batch     int // pipeline batch: rx queue, consumer batches, send chunking
	recvBatch int // datagrams per receive-function call (the bind's own batch)

	static   noise.DHKey
	psk      []byte
	prologue []byte

	mu           sync.Mutex
	sessions     map[string]*peerSession // canonical addr string → session
	knownStatics map[string]bool         // hex(static) → allowed; the session allowlist from the rendezvous
	missedPings  map[string]int          // addr → consecutive unanswered pings

	Connected chan *net.UDPAddr // signals when a new peer completes the handshake
	Dead      chan *net.UDPAddr // signals when a peer is declared dead
	stop      chan struct{}     // closed by Shutdown to stop background loops
	stopOnce  sync.Once

	// rx carries encrypted data/tun packets from the receive loops to the
	// consumer. Sends block when it is full: backpressure ripples to the socket
	// instead of silently dropping authenticated-to-be traffic.
	rx chan rxPacket
	// recvDone is closed when every receive loop has exited (bind closed), so
	// consumers blocked in Read/ReadTunBatch wake up at teardown.
	recvDone chan struct{}
	recvWG   sync.WaitGroup

	// stunWaiter, when set, receives copies of non-protocol packets so
	// DiscoverPublicAddr can catch the STUN response on the tunnel socket.
	stunWaiter atomic.Pointer[chan []byte]

	// tunPkts/tunOK are ReadTunBatch scratch space (single consumer).
	tunPkts []rxPacket
	tunOK   []bool

	// fixedRateBits, when non-zero, is a math.Float64bits bytes/sec cap that
	// overrides the adaptive shaper for every session (the --up-mbit knob).
	fixedRateBits atomic.Uint64
}

// SetFixedUploadRate forces a fixed upload cap in bytes/sec across all
// sessions, disabling the adaptive shaper. 0 restores adaptive mode.
func (p *PeerConn) SetFixedUploadRate(bytesPerSec float64) {
	p.fixedRateBits.Store(math.Float64bits(bytesPerSec))
}

// effectiveRate returns the pacing rate for a session: the manual override if
// set, else the session's adaptive rate. 0 means uncapped.
func (p *PeerConn) effectiveRate(s *peerSession) float64 {
	if f := math.Float64frombits(p.fixedRateBits.Load()); f > 0 {
		return f
	}
	s.paceMu.Lock()
	r := s.paceRate
	s.paceMu.Unlock()
	return r
}

// paceAdmit charges nbytes against the session's virtual send clock at the
// given rate, sleeping off any deficit. It also accumulates the sent-bytes
// meter the ack handler uses for utilization. rate 0 = uncapped, no sleep.
func (s *peerSession) paceAdmit(nbytes int, rate float64) {
	s.paceMu.Lock()
	s.paceSentB += uint64(nbytes)
	if rate <= 0 {
		s.paceMu.Unlock()
		return
	}
	now := time.Now()
	if s.paceNext.Before(now.Add(-paceBurstCredit)) {
		s.paceNext = now.Add(-paceBurstCredit)
	}
	wait := s.paceNext.Sub(now)
	s.paceNext = s.paceNext.Add(time.Duration(float64(nbytes) / rate * float64(time.Second)))
	s.paceMu.Unlock()
	if wait > 0 {
		time.Sleep(wait)
	}
}

// handleAck folds one CtrlAck delivery report into the session's shaper. Loss
// is measured from counter-space deltas (Δaccepted vs Δmax-seen), which has no
// in-flight bias. The shaper engages only on real loss: until then the session
// sends uncapped, so clean paths (LAN) never pay for shaping.
func (p *PeerConn) handleAck(s *peerSession, maxCtr, accepted uint64) {
	if math.Float64frombits(p.fixedRateBits.Load()) > 0 {
		return // manual override active; adaptive state not maintained
	}
	now := time.Now()
	s.paceMu.Lock()
	defer s.paceMu.Unlock()
	if s.lastAckAt.IsZero() || maxCtr < s.lastAckMax {
		// First report of this key epoch (or a stale one after rekey): just
		// snapshot a baseline.
		s.lastAckAt, s.lastAckMax, s.lastAckAcc = now, maxCtr, accepted
		s.paceSentB = 0
		return
	}
	dMax := maxCtr - s.lastAckMax
	dAcc := accepted - s.lastAckAcc
	elapsed := now.Sub(s.lastAckAt).Seconds()
	sentB := s.paceSentB
	s.lastAckAt, s.lastAckMax, s.lastAckAcc = now, maxCtr, accepted
	s.paceSentB = 0
	if dMax < ackMinPkts || elapsed <= 0 {
		return // too little traffic to read loss from
	}
	loss := 1 - float64(dAcc)/float64(dMax)
	switch {
	case loss > lossSevere && now.Sub(s.lastCut) > paceCutGuard:
		if s.paceRate <= 0 {
			s.paceRate = float64(sentB) / elapsed
		}
		s.paceRate *= paceCutBig
		s.lastCut = now
	case loss > lossEngage && now.Sub(s.lastCut) > paceCutGuard:
		if s.paceRate <= 0 {
			s.paceRate = float64(sentB) / elapsed
		}
		s.paceRate *= paceCut
		s.lastCut = now
	case loss < 0.01 && s.paceRate > 0:
		// Clean interval: probe upward, but only when actually pushing near
		// the cap — otherwise an idle session's rate would balloon.
		if float64(sentB) > 0.5*s.paceRate*elapsed {
			s.paceRate *= paceGrow
		}
	}
	if s.paceRate > 0 {
		if s.paceRate < paceMinRate {
			s.paceRate = paceMinRate
		}
		if s.paceRate > paceMaxRate {
			s.paceRate = 0 // outgrew relevance: back to uncapped
		}
	}
	Stats.PaceBps.Store(uint64(s.paceRate))
}

// ackLoop periodically reports per-session delivery back to each peer, feeding
// the peer's shaper. ~5 tiny control packets per second per active peer.
func (p *PeerConn) ackLoop() {
	ticker := time.NewTicker(ackInterval)
	defer ticker.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-ticker.C:
		}
		p.mu.Lock()
		sessions := make([]*peerSession, 0, len(p.sessions))
		for _, s := range p.sessions {
			sessions = append(sessions, s)
		}
		p.mu.Unlock()
		for _, s := range sessions {
			s.mu.Lock()
			est := s.established
			maxc, acc := s.rxMaxCtr, s.rxAccepted
			changed := maxc != s.ackSentMax
			if est && changed {
				s.ackSentMax = maxc
			}
			s.mu.Unlock()
			if !est || !changed {
				continue
			}
			var payload [17]byte
			payload[0] = CtrlAck
			binary.BigEndian.PutUint64(payload[1:9], maxc)
			binary.BigEndian.PutUint64(payload[9:17], acc)
			p.sendBatchSession(s, [][]byte{payload[:]}, PacketControl)
		}
	}
}

// NewPeerConn creates a PeerConn on an opened Transport and starts its receive
// loops. privateKey/publicKey are this peer's static X25519 keypair; psk is the
// Argon2id-derived pre-shared key (second factor); prologue binds the handshake
// to the protocol version and session id.
func NewPeerConn(t *Transport, privateKey, publicKey, psk, prologue []byte) *PeerConn {
	p := &PeerConn{
		bind:         t.bind,
		batch:        t.batch,
		recvBatch:    t.recvBatch,
		static:       noise.DHKey{Private: privateKey, Public: publicKey},
		psk:          psk,
		prologue:     prologue,
		sessions:     map[string]*peerSession{},
		knownStatics: map[string]bool{},
		missedPings:  map[string]int{},
		Connected:    make(chan *net.UDPAddr, 32),
		Dead:         make(chan *net.UDPAddr, 10),
		stop:         make(chan struct{}),
		rx:           make(chan rxPacket, 4*t.batch),
		recvDone:     make(chan struct{}),
	}
	p.recvWG.Add(len(t.recvFns))
	for _, fn := range t.recvFns {
		go p.recvLoop(fn)
	}
	go func() {
		p.recvWG.Wait()
		close(p.recvDone)
	}()
	go p.ackLoop()
	return p
}

// BatchSize is the number of packets a caller should size ReadTunBatch /
// SendBatch batches to.
func (p *PeerConn) BatchSize() int { return p.batch }

// Shutdown signals background loops (handshake drivers, blocked consumers) to
// stop. Safe to call multiple times; it does not close the underlying bind.
func (p *PeerConn) Shutdown() {
	p.stopOnce.Do(func() { close(p.stop) })
}

// Close shuts down background loops and closes the underlying bind, waking the
// receive loops.
func (p *PeerConn) Close() error {
	p.Shutdown()
	return p.bind.Close()
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

// recvLoop services one of the bind's receive functions: batches of datagrams
// come in, handshake/punch/control packets are handled inline (rare, small),
// and data/tun packets are queued — still encrypted — for the consumer, which
// decrypts them in parallel.
func (p *PeerConn) recvLoop(fn wgconn.ReceiveFunc) {
	defer p.recvWG.Done()
	bufs := make([][]byte, p.recvBatch)
	sizes := make([]int, p.recvBatch)
	eps := make([]wgconn.Endpoint, p.recvBatch)
	for i := range bufs {
		bufs[i] = make([]byte, maxUDPPacket)
	}
	for {
		n, err := fn(bufs, sizes, eps)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-p.stop:
				return
			default:
				continue // transient receive error (e.g. ICMP-triggered reset)
			}
		}
		for i := 0; i < n; i++ {
			if sizes[i] == 0 {
				continue
			}
			p.handlePacket(bufs[i][:sizes[i]], eps[i])
		}
	}
}

// handlePacket classifies one received datagram. pkt aliases the receive
// buffer and is only valid for the duration of the call; anything that
// outlives it (queued data/tun packets) is copied into a pooled buffer.
func (p *PeerConn) handlePacket(pkt []byte, ep wgconn.Endpoint) {
	// Every packet is [version][type][body...]. Drop anything too short or with a
	// mismatched protocol version — no silent downgrade to an older protocol.
	if len(pkt) < 2 || pkt[0] != ProtocolVersion {
		// Not a blindspot packet. During public-address discovery the STUN
		// response arrives on this same socket — hand it to the waiter.
		if w := p.stunWaiter.Load(); w != nil {
			cp := append([]byte(nil), pkt...)
			select {
			case *w <- cp:
			default:
			}
		}
		return
	}
	pktType := pkt[1]
	body := pkt[2:]
	switch pktType {
	case PacketPunch:
		return
	case PacketHandshakeInit:
		p.handleHandshakeInit(ep, body)
	case PacketHandshakeResp:
		p.handleHandshakeResp(ep, body)
	case PacketControl:
		s := p.sessionForEndpoint(ep)
		if s == nil {
			return
		}
		plaintext, err := s.decrypt(nil, pkt)
		if err != nil || len(plaintext) < 1 {
			return
		}
		switch plaintext[0] {
		case CtrlPing:
			UpdateLastSeen()
			p.sendControl(s.addr, CtrlPong)
		case CtrlPong:
			UpdateLastSeen()
			p.mu.Lock()
			p.missedPings[s.key] = 0
			p.mu.Unlock()
		case CtrlDead:
			// Authenticated "I'm leaving" from the peer: drop its session and
			// surface a Dead event — other peers are unaffected.
			p.RemovePeer(s.addr)
		case CtrlRekey:
			// The peer lost this session (keepalive timeout on its side) and is
			// re-handshaking. Drop our copy too — answering its fresh msg1 with
			// the stale cached msg2 would deadlock both sides until our own
			// keepalive timed out (~30s of blackout mid-transfer). No Dead event:
			// mappings stay valid and the tunnel heals in one handshake round
			// trip; watchRearm surfaces Dead only if the re-handshake never lands.
			if gen, ok := p.rearmSession(s, false); ok {
				go p.watchRearm(s, gen)
			}
		case CtrlAck:
			if len(plaintext) == 17 {
				p.handleAck(s,
					binary.BigEndian.Uint64(plaintext[1:9]),
					binary.BigEndian.Uint64(plaintext[9:17]))
			}
		}
	case PacketData, PacketTun:
		s := p.sessionForEndpoint(ep)
		if s == nil {
			return
		}
		Stats.RxPkts.Add(1)
		Stats.RxBytes.Add(uint64(len(pkt)))
		buf := getPacketBuf(len(pkt))
		copy(buf, pkt)
		select {
		case p.rx <- rxPacket{typ: pktType, s: s, buf: buf}:
		case <-p.stop:
			putPacketBuf(buf)
		}
	}
}

// sessionForEndpoint resolves the session for a received packet's source.
func (p *PeerConn) sessionForEndpoint(ep wgconn.Endpoint) *peerSession {
	key, _, ok := canonEndpointKey(ep)
	if !ok {
		return nil
	}
	p.mu.Lock()
	s := p.sessions[key]
	p.mu.Unlock()
	return s
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

	ap := canonAddrPort(addr.AddrPort())
	sessKey := ap.String()
	ep, err := p.bind.ParseEndpoint(sessKey)
	if err != nil {
		return fmt.Errorf("parsing peer endpoint %s: %w", sessKey, err)
	}

	p.mu.Lock()
	p.knownStatics[staticKeyHex(key)] = true
	s, ok := p.sessions[sessKey]
	if !ok {
		s = &peerSession{addr: net.UDPAddrFromAddrPort(ap), key: sessKey, ep: ep}
		p.sessions[sessKey] = s
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
		notice := s.rekeyNotice
		ep := s.ep
		s.mu.Unlock()
		if superseded || established {
			return
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			return
		}
		if notice != nil {
			// Rekey notice first, so a peer still holding the old session tears
			// it down before our msg1 arrives. Retransmitting the same sealed
			// packet is safe: once one copy is delivered, later copies fail the
			// peer's replay window (or, after its rekey, the AEAD) and are dropped.
			p.bind.Send([][]byte{notice}, ep)
		}
		if initiator && initMsg != nil {
			p.bind.Send([][]byte{initMsg}, ep)
		} else {
			p.bind.Send([][]byte{punch}, ep)
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

// Read returns one decrypted packet: its type, payload, and sender address.
// Callers filter on PacketData (chat) or PacketTun (VPN). Handshake, punch, and
// keepalive packets are handled internally and never returned. High-throughput
// consumers should use ReadTunBatch instead.
func (p *PeerConn) Read() (byte, []byte, *net.UDPAddr, error) {
	for {
		select {
		case pkt := <-p.rx:
			plaintext, err := pkt.s.decrypt(nil, pkt.buf)
			addr := pkt.s.addr
			typ := pkt.typ
			putPacketBuf(pkt.buf)
			if err != nil {
				continue
			}
			return typ, plaintext, addr, nil
		case <-p.stop:
			return 0, nil, nil, fmt.Errorf("error reading from peer: %w", net.ErrClosed)
		case <-p.recvDone:
			return 0, nil, nil, fmt.Errorf("error reading from peer: %w", net.ErrClosed)
		}
	}
}

// ReadTunBatch blocks for at least one tunnel packet, then drains whatever else
// is immediately available (up to len(bufs)) and decrypts the whole batch in
// parallel. Plaintexts land in bufs[:n] (slices are swapped/replaced as
// needed); senders[:n] receives each packet's canonical remote address string,
// suitable for keying reverse-path maps. Non-tun packets and packets that fail
// authentication or replay checks are dropped. Not safe for concurrent use.
func (p *PeerConn) ReadTunBatch(bufs [][]byte, senders []string) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}
	pkts := p.tunPkts[:0]

	// Block for the first packet.
	select {
	case pkt := <-p.rx:
		pkts = append(pkts, pkt)
	case <-p.stop:
		return 0, net.ErrClosed
	case <-p.recvDone:
		return 0, net.ErrClosed
	}
	// Opportunistically drain the rest of the burst.
drain:
	for len(pkts) < len(bufs) {
		select {
		case pkt := <-p.rx:
			pkts = append(pkts, pkt)
		default:
			break drain
		}
	}

	ok := p.tunOK[:0]
	for range pkts {
		ok = append(ok, false)
	}
	p.tunPkts, p.tunOK = pkts, ok // keep scratch capacity for the next call

	parallelFor(len(pkts), func(i int) {
		if pkts[i].typ != PacketTun {
			return
		}
		plaintext, err := pkts[i].s.decrypt(bufs[i][:0], pkts[i].buf)
		if err != nil {
			return
		}
		bufs[i] = plaintext // may have been reallocated by Open; keep the header
		ok[i] = true
	})

	n := 0
	for i := range pkts {
		putPacketBuf(pkts[i].buf)
		if !ok[i] {
			continue
		}
		if n != i {
			bufs[n], bufs[i] = bufs[i], bufs[n]
		}
		senders[n] = pkts[i].s.key
		n++
	}
	return n, nil
}

// parallelFor runs fn(0..n-1) across up to GOMAXPROCS goroutines, falling back
// to a plain loop for small n where fork-join overhead would dominate.
func parallelFor(n int, fn func(i int)) {
	const minPerWorker = 8
	workers := runtime.GOMAXPROCS(0)
	if w := (n + minPerWorker - 1) / minPerWorker; w < workers {
		workers = w
	}
	if workers <= 1 {
		for i := 0; i < n; i++ {
			fn(i)
		}
		return
	}
	chunk := (n + workers - 1) / workers
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		lo := w * chunk
		hi := lo + chunk
		if hi > n {
			hi = n
		}
		if lo >= hi {
			break
		}
		wg.Add(1)
		go func(lo, hi int) {
			defer wg.Done()
			for i := lo; i < hi; i++ {
				fn(i)
			}
		}(lo, hi)
	}
	wg.Wait()
}

// handleHandshakeInit processes an inbound Noise msg1 (we are the responder).
func (p *PeerConn) handleHandshakeInit(ep wgconn.Endpoint, msg1 []byte) {
	sessKey, ap, okKey := canonEndpointKey(ep)
	if !okKey {
		return
	}
	p.mu.Lock()
	s, ok := p.sessions[sessKey]
	if !ok {
		// A msg1 may arrive before the rendezvous stream told us about this peer.
		// Create a provisional session; the initiator's static is still validated
		// against the session allowlist below. The endpoint is re-parsed rather
		// than retained: received endpoints may alias bind-internal state.
		pep, err := p.bind.ParseEndpoint(sessKey)
		if err != nil {
			p.mu.Unlock()
			return
		}
		s = &peerSession{addr: net.UDPAddrFromAddrPort(ap), key: sessKey, ep: pep}
		p.sessions[sessKey] = s
	}
	p.mu.Unlock()

	s.mu.Lock()
	if s.established {
		// Retransmit our cached msg2 in case the initiator's copy was lost.
		resp := s.respMsg
		sendEp := s.ep
		s.mu.Unlock()
		if resp != nil {
			p.bind.Send([][]byte{resp}, sendEp)
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
	if err := s.installTransportKeysLocked(cs0, cs1); err != nil {
		s.hs = nil
		s.mu.Unlock()
		return
	}
	s.remoteStatic = append([]byte(nil), remote...)
	s.respMsg = buildPacket(PacketHandshakeResp, msg2)
	s.established = true
	s.driving = false // the retransmit driver will notice and exit; the session may be re-armed before then
	resp := s.respMsg
	sendEp := s.ep
	s.mu.Unlock()

	p.bind.Send([][]byte{resp}, sendEp)
	p.fireConnected(s)
}

// handleHandshakeResp processes an inbound Noise msg2 (we are the initiator).
func (p *PeerConn) handleHandshakeResp(ep wgconn.Endpoint, msg2 []byte) {
	s := p.sessionForEndpoint(ep)
	if s == nil {
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
	if err := s.installTransportKeysLocked(cs0, cs1); err != nil {
		s.mu.Unlock()
		return
	}
	s.remoteStatic = append([]byte(nil), remote...)
	s.established = true
	s.driving = false // the retransmit driver will notice and exit; the session may be re-armed before then
	s.mu.Unlock()

	p.fireConnected(s)
}

// transportHeaderLen is the cleartext prefix [version][type][counter] that also
// serves as the AEAD additional data.
const transportHeaderLen = 2 + counterLen

// sealPacket encrypts one payload into a pooled wire packet
// [version][type][counter][ct]. The AEAD appends in place: the pooled buffer
// is sized so Seal never reallocates.
func sealPacket(aead cipher.AEAD, pktType byte, counter uint64, payload []byte) []byte {
	buf := getPacketBuf(transportHeaderLen + len(payload) + 16)
	buf[0] = ProtocolVersion
	buf[1] = pktType
	binary.BigEndian.PutUint64(buf[2:transportHeaderLen], counter)
	nonce := aesgcmNonce(counter)
	return aead.Seal(buf[:transportHeaderLen], nonce[:], payload, buf[:transportHeaderLen])
}

func (p *PeerConn) sessionByAddr(addr *net.UDPAddr) *peerSession {
	key := canonAddrPort(addr.AddrPort()).String()
	p.mu.Lock()
	s := p.sessions[key]
	p.mu.Unlock()
	return s
}

// SendBatch encrypts payloads in parallel and hands them to the bind as
// batches, which coalesces them into far fewer syscalls (UDP GSO/sendmmsg on
// Linux, RIO on Windows). Counters are reserved contiguously up front, so one
// lock acquisition covers the whole batch.
func (p *PeerConn) SendBatch(addr *net.UDPAddr, payloads [][]byte, pktType byte) error {
	s := p.sessionByAddr(addr)
	if s == nil {
		return fmt.Errorf("unknown peer: %s", addr)
	}
	return p.sendBatchSession(s, payloads, pktType)
}

func (p *PeerConn) sendBatchSession(s *peerSession, payloads [][]byte, pktType byte) error {
	m := len(payloads)
	if m == 0 {
		return nil
	}
	s.mu.Lock()
	if !s.established || s.txAEAD == nil {
		s.mu.Unlock()
		return fmt.Errorf("peer %s not established", s.addr)
	}
	aead := s.txAEAD
	ep := s.ep
	base := s.txCtr
	s.txCtr += uint64(m)
	s.mu.Unlock()

	wire := make([][]byte, m)
	parallelFor(m, func(i int) {
		wire[i] = sealPacket(aead, pktType, base+uint64(i), payloads[i])
	})

	// When the shaper is engaged, hand the batch to the bind in small paced
	// chunks; uncapped sessions keep full-width batches.
	rate := p.effectiveRate(s)
	step := p.batch
	if rate > 0 && step > paceChunk {
		step = paceChunk
	}
	var err error
	for off := 0; off < m; off += step {
		end := off + step
		if end > m {
			end = m
		}
		nbytes := 0
		for _, w := range wire[off:end] {
			nbytes += len(w) + 28 // + IPv4/UDP header overhead on the wire
		}
		s.paceAdmit(nbytes, rate)
		if e := p.bind.Send(wire[off:end], ep); e != nil && err == nil {
			err = e
		}
	}
	var payloadBytes uint64
	for _, w := range wire {
		payloadBytes += uint64(len(w))
		putPacketBuf(w)
	}
	Stats.TxPkts.Add(uint64(m))
	Stats.TxBytes.Add(payloadBytes)
	if err != nil {
		Stats.TxErrs.Add(1)
	}
	return err
}

// sendControl sends an encrypted control message (ping/pong/dead) over the same
// authenticated, anti-replay-protected transport as data.
func (p *PeerConn) sendControl(addr *net.UDPAddr, opcode byte) error {
	return p.SendBatch(addr, [][]byte{{opcode}}, PacketControl)
}

func (p *PeerConn) Send(addr *net.UDPAddr, data []byte) error {
	return p.SendBatch(addr, [][]byte{data}, PacketData)
}

func (p *PeerConn) SendTun(addr *net.UDPAddr, data []byte) error {
	return p.SendBatch(addr, [][]byte{data}, PacketTun)
}

// SendTunBatch sends a batch of tunnelled IP packets to one peer.
func (p *PeerConn) SendTunBatch(addr *net.UDPAddr, packets [][]byte) error {
	return p.SendBatch(addr, packets, PacketTun)
}

// PeerPublicKey returns the authenticated static public key of the established
// peer at addr. The key is authenticated because it came from the trusted
// rendezvous and was verified by the Noise handshake.
func (p *PeerConn) PeerPublicKey(addr *net.UDPAddr) ([]byte, bool) {
	s := p.sessionByAddr(addr)
	if s == nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.established || s.remoteStatic == nil {
		return nil, false
	}
	return s.remoteStatic, true
}

func (p *PeerConn) fireConnected(s *peerSession) {
	p.mu.Lock()
	p.missedPings[s.key] = 0
	p.mu.Unlock()
	// Deliver reliably: block until the consumer takes the event, or until shutdown.
	// Dropping it would leave the peer without a virtual-IP mapping, so all of its
	// tunnel traffic would be silently discarded for the rest of the session. This
	// runs after s.mu is released, so blocking here cannot deadlock a session.
	select {
	case p.Connected <- s.addr:
	case <-p.stop:
	}
}

func (p *PeerConn) dropSession(addr *net.UDPAddr) {
	key := canonAddrPort(addr.AddrPort()).String()
	p.mu.Lock()
	delete(p.sessions, key)
	delete(p.missedPings, key)
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
	Stats.Timeouts.Add(1)
	key := canonAddrPort(addr.AddrPort()).String()
	p.mu.Lock()
	delete(p.missedPings, key)
	p.mu.Unlock()
	p.retryHandshake(addr)
	p.fireDead(addr)
}

// retryHandshake resets an established-but-unresponsive session back to the
// handshake phase, reusing the static key authenticated by the previous handshake
// as the pinned key for the next one. The retry is bounded by retryWindow; after
// that the session is parked until an inbound msg1 or AddKnownPeer revives it.
func (p *PeerConn) retryHandshake(addr *net.UDPAddr) {
	if s := p.sessionByAddr(addr); s != nil {
		p.rearmSession(s, true)
	}
}

// rearmSession resets an established session back to the handshake phase and
// starts a bounded driver, returning the driver generation. With notify set, a
// CtrlRekey notice sealed under the outgoing keys is prepared before they are
// wiped; the driver retransmits it so the peer — which may still hold the old
// session and would otherwise answer our fresh msg1 only with its stale cached
// msg2 — tears its copy down and re-handshakes immediately.
func (p *PeerConn) rearmSession(s *peerSession, notify bool) (uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.established || s.driving {
		return 0, false
	}
	remote := s.remoteStatic
	if remote == nil {
		remote = s.expected
	}
	if remote == nil {
		return 0, false
	}
	var notice []byte
	if notify && s.txAEAD != nil {
		pkt := sealPacket(s.txAEAD, PacketControl, s.txCtr, []byte{CtrlRekey})
		s.txCtr++
		notice = append([]byte(nil), pkt...)
		putPacketBuf(pkt)
	}
	s.established = false
	s.txAEAD, s.rxAEAD = nil, nil
	s.txCtr = 0
	s.remoteStatic = nil
	s.replay = ReplayWindow{}
	gen, err := p.armHandshakeLocked(s, remote)
	if err != nil {
		return 0, false
	}
	s.rekeyNotice = notice
	Stats.Rekeys.Add(1)
	go p.driveHandshake(s, gen, time.Now().Add(retryWindow))
	return gen, true
}

// watchRearm fires Dead if a rekey-triggered re-handshake never completes
// within the retry window. A CtrlRekey rearm deliberately emits no Dead event
// (mappings stay valid for a fast heal), so a session that parks anyway must
// still be surfaced to consumers or they would route into it forever.
func (p *PeerConn) watchRearm(s *peerSession, gen uint64) {
	select {
	case <-p.stop:
	case <-time.After(retryWindow + time.Second):
		s.mu.Lock()
		parked := !s.established && s.driverGen == gen
		s.mu.Unlock()
		if parked {
			p.fireDead(s.addr)
		}
	}
}

// RecentActivity reports whether a packet that passed authentication and the
// replay window arrived from addr within d. The keepalive uses it so a peer
// whose data is flowing is never declared dead just because its pongs are
// being lost to congestion.
func (p *PeerConn) RecentActivity(addr *net.UDPAddr, d time.Duration) bool {
	s := p.sessionByAddr(addr)
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.lastRx.IsZero() && time.Since(s.lastRx) < d
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
