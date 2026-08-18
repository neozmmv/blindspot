package main

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/neozmmv/blindspot/internal/crypto"
	"github.com/neozmmv/blindspot/internal/network"
)

// staleAddr is an address in TEST-NET-1 (RFC 5737) standing in for a NAT mapping
// that has gone stale. Nothing answers there and nothing routes to it, which is
// exactly the situation being reproduced: a peer publishes an address, its
// mapping lapses or the carrier rotates the port, and every packet aimed at the
// published address is discarded upstream.
const staleAddr = "192.0.2.1:51820"

// keyPairsOrdered returns two keypairs, the first holding the smaller static
// public key. Handshake roles are not negotiated — the smaller static key is the
// Noise initiator — so a test that needs a particular side to be the responder
// has to choose its keys rather than hope for them.
func keyPairsOrdered(t *testing.T) (smaller, larger *crypto.KeyPair) {
	t.Helper()
	a, b := mustKeyPair(t), mustKeyPair(t)
	if bytes.Compare(a.PublicKey, b.PublicKey) > 0 {
		a, b = b, a
	}
	return a, b
}

// sendRawPunch writes a punch packet naming staticKey directly onto the wire,
// bypassing PeerConn — the only way to forge one from an address the receiver
// has never been told about.
func sendRawPunch(t *testing.T, from *net.UDPConn, to string, staticKey []byte) {
	t.Helper()
	pkt := append([]byte{network.ProtocolVersion, network.PacketPunch}, staticKey...)
	if _, err := from.WriteToUDP(pkt, mustResolve(t, to)); err != nil {
		t.Fatalf("sending raw punch: %v", err)
	}
}

// TestPunchRebindsStaleAddress covers the case that used to deadlock forever.
//
// One peer's published address is wrong, and that peer draws the *responder*
// role. It therefore never sends msg1 — only punches — while its partner
// retransmits msg1 at an address nothing is listening on. Before punches named
// their sender there was nothing in the protocol that could correct this: the
// responder had no way to say "I am over here", and msg2 from an unexpected
// address is dropped by design. Since roles come from a fixed comparison of the
// two static keys, it also failed the same way on every retry for a given pair
// of identities rather than being a race that sometimes came good.
func TestPunchRebindsStaleAddress(t *testing.T) {
	const sessionID, password = "punch-rebind", "punchpass1"

	// The peer with the stale address must be the responder, so it sends
	// nothing but punches.
	seekerKey, staleKey := keyPairsOrdered(t)

	seeker := newTestPeerWithKey(t, sessionID, password, seekerKey)
	defer seeker.conn.Close()
	defer seeker.pc.Shutdown()

	stale := newTestPeerWithKey(t, sessionID, password, staleKey)
	defer stale.conn.Close()
	defer stale.pc.Shutdown()

	seeker.startReadLoop()
	stale.startReadLoop()

	// The seeker was handed a dead address for its peer, as the room would have
	// after that peer's mapping lapsed. The peer itself knows where the seeker
	// really is, so its punches arrive.
	seeker.pc.AddKnownPeer(mustResolve(t, staleAddr), stale.kp.PublicKey)
	stale.pc.AddKnownPeer(mustResolve(t, seeker.addr), seeker.kp.PublicKey)

	connAddr := seeker.waitConnected(t, 10*time.Second)
	stale.waitConnected(t, 10*time.Second)

	// The session must have moved to where the punches actually came from, not
	// merely completed somehow at the address discovery supplied.
	if connAddr.String() != mustResolve(t, stale.addr).String() {
		t.Fatalf("connected to %v, want the address the punch arrived from (%v)", connAddr, stale.addr)
	}

	// And the rebound session has to carry traffic, not just report itself up.
	msg := []byte("rebound")
	if err := seeker.pc.Send(connAddr, msg); err != nil {
		t.Fatalf("send over rebound session: %v", err)
	}
	select {
	case got := <-stale.recv:
		if string(got.data) != string(msg) {
			t.Fatalf("received %q, want %q", got.data, msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for data over the rebound session")
	}
}

// TestPunchDoesNotMoveEstablishedSession pins the security limit on the rebind.
//
// A punch body is cleartext and unauthenticated, so anyone who has seen a
// member's published static key can send one claiming to be that member. Moving
// an unestablished session on that basis is harmless — the Noise handshake still
// has to complete against the pinned key and the PSK before anything flows — but
// moving an *established* one would let the same forgery redirect a live,
// authenticated tunnel.
func TestPunchDoesNotMoveEstablishedSession(t *testing.T) {
	const sessionID, password = "punch-established", "punchpass2"

	peerA := newTestPeer(t, sessionID, password)
	defer peerA.conn.Close()
	defer peerA.pc.Shutdown()

	peerB := newTestPeer(t, sessionID, password)
	defer peerB.conn.Close()
	defer peerB.pc.Shutdown()

	peerA.startReadLoop()
	peerB.startReadLoop()

	aAddr := mustResolve(t, peerA.addr)
	bAddr := mustResolve(t, peerB.addr)
	peerA.pc.AddKnownPeer(bAddr, peerB.kp.PublicKey)
	peerB.pc.AddKnownPeer(aAddr, peerA.kp.PublicKey)

	peerA.waitConnected(t, 5*time.Second)
	peerB.waitConnected(t, 5*time.Second)

	// A third party claims, in cleartext, to be peer B at a new address.
	attacker, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer attacker.Close()
	sendRawPunch(t, attacker, peerA.addr, peerB.kp.PublicKey)
	time.Sleep(500 * time.Millisecond)

	// If A had taken the bait, its session would now be filed under the
	// attacker's address and this send would fail outright as an unknown peer.
	msg := []byte("still yours")
	if err := peerA.pc.Send(bAddr, msg); err != nil {
		t.Fatalf("established session no longer addressable at %v: %v", bAddr, err)
	}
	select {
	case got := <-peerB.recv:
		if string(got.data) != string(msg) {
			t.Fatalf("peer B received %q, want %q", got.data, msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out; traffic no longer reaches the real peer")
	}
}

// TestEmptyPunchIgnored keeps the change compatible in both directions: a peer
// running the older build sends a punch with no body, which carries no
// information and must therefore leave every session exactly where it was.
func TestEmptyPunchIgnored(t *testing.T) {
	const sessionID, password = "punch-empty", "punchpass3"

	peerA := newTestPeer(t, sessionID, password)
	defer peerA.conn.Close()
	defer peerA.pc.Shutdown()

	peerB := newTestPeer(t, sessionID, password)
	defer peerB.conn.Close()
	defer peerB.pc.Shutdown()

	peerA.startReadLoop()
	peerB.startReadLoop()

	bAddr := mustResolve(t, peerB.addr)
	peerA.pc.AddKnownPeer(bAddr, peerB.kp.PublicKey)

	// An old-style empty punch from somewhere A has never heard of.
	legacy, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer legacy.Close()
	sendRawPunch(t, legacy, peerA.addr, nil)
	time.Sleep(300 * time.Millisecond)

	// A's pending session is untouched, so the handshake still completes with
	// the real peer once it answers.
	peerB.pc.AddKnownPeer(mustResolve(t, peerA.addr), peerA.kp.PublicKey)
	connAddr := peerA.waitConnected(t, 10*time.Second)
	if connAddr.String() != bAddr.String() {
		t.Fatalf("connected to %v, want %v", connAddr, bAddr)
	}
}
