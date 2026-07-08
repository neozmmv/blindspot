package main

import (
	"net"
	"testing"
	"time"
)

// waitDead expects a Dead event within the timeout and returns the dead address.
func waitDead(t *testing.T, tp *testPeer, timeout time.Duration) *net.UDPAddr {
	t.Helper()
	select {
	case addr := <-tp.pc.Dead:
		return addr
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for Dead event after %v", timeout)
		return nil
	}
}

// TestTimeoutPeerReconnects proves a session that died from missed keepalives
// heals on its own: TimeoutPeer surfaces a Dead event (so consumers drop their
// mappings) and re-arms the Noise handshake, so the peers re-establish and can
// exchange traffic again without any rendezvous involvement.
func TestTimeoutPeerReconnects(t *testing.T) {
	const sessionID, password = "reconnect-session", "reconnpass1"

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

	// Simulate what KeepAliveAll does when both sides stop hearing each other
	// (e.g. a transient network outage): each declares the other dead.
	go peerA.pc.TimeoutPeer(bAddr)
	go peerB.pc.TimeoutPeer(aAddr)
	if got := waitDead(t, peerA, 3*time.Second); got.String() != bAddr.String() {
		t.Fatalf("peer A got Dead event for %v, want %v", got, bAddr)
	}
	if got := waitDead(t, peerB, 3*time.Second); got.String() != aAddr.String() {
		t.Fatalf("peer B got Dead event for %v, want %v", got, aAddr)
	}

	// The re-armed handshake must complete again on both sides...
	connA := peerA.waitConnected(t, 5*time.Second)
	peerB.waitConnected(t, 5*time.Second)

	// ...and the fresh session must carry traffic.
	msg := []byte("hello again")
	if err := peerA.pc.Send(connA, msg); err != nil {
		t.Fatalf("send after reconnect: %v", err)
	}
	select {
	case got := <-peerB.recv:
		if string(got.data) != string(msg) {
			t.Fatalf("peer B received %q, want %q", got.data, msg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("peer B did not receive traffic after reconnect")
	}
}

// TestGracefulDeadAndRejoin proves a graceful departure is surfaced as a Dead
// event on the surviving peer, and that the departed peer can rejoin later (new
// socket, same identity — the crash/restart case) once it is announced again.
func TestGracefulDeadAndRejoin(t *testing.T) {
	const sessionID, password = "rejoin-session", "rejoinpass1"

	peerA := newTestPeer(t, sessionID, password)
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

	// A leaves gracefully, exactly like the CLI teardown does.
	peerA.pc.BroadcastDead()
	if got := waitDead(t, peerB, 3*time.Second); got.String() != aAddr.String() {
		t.Fatalf("peer B got Dead event for %v, want %v", got, aAddr)
	}
	peerA.pc.Shutdown()
	peerA.conn.Close()

	// A restarts with the same identity but a new socket, and both sides learn of
	// each other again (as they would via the rendezvous announcement).
	peerA2 := newTestPeerWithKey(t, sessionID, password, peerA.kp)
	defer peerA2.conn.Close()
	defer peerA2.pc.Shutdown()
	peerA2.startReadLoop()

	peerA2.pc.AddKnownPeer(bAddr, peerB.kp.PublicKey)
	peerB.pc.AddKnownPeer(mustResolve(t, peerA2.addr), peerA.kp.PublicKey)

	connA2 := peerA2.waitConnected(t, 5*time.Second)
	peerB.waitConnected(t, 5*time.Second)

	msg := []byte("back online")
	if err := peerA2.pc.Send(connA2, msg); err != nil {
		t.Fatalf("send after rejoin: %v", err)
	}
	select {
	case got := <-peerB.recv:
		if string(got.data) != string(msg) {
			t.Fatalf("peer B received %q, want %q", got.data, msg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("peer B did not receive traffic after rejoin")
	}
}
