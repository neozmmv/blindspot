package main

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/neozmmv/blindspot/internal/network"
)

// TestForgedControlCannotDisconnectPeer proves control messages now ride inside
// the authenticated channel: an attacker who can inject packets from the peer's
// address (on-path) cannot forge a "dead" notice to tear down the session, nor a
// bogus PacketControl, because both fail authentication.
func TestForgedControlCannotDisconnectPeer(t *testing.T) {
	const sessionID, password = "forged-control-session", "controlpass1"

	peerA := newTestPeer(t, sessionID, password)
	defer peerA.conn.Close()
	defer peerA.pc.Shutdown()

	peerB := newTestPeer(t, sessionID, password)
	defer peerB.conn.Close()
	defer peerB.pc.Shutdown()

	// MITM proxy so we can inject packets toward B that appear to come from A.
	proxy, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	defer proxy.Close()
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxy.LocalAddr().(*net.UDPAddr).Port)

	aUDP := mustResolve(t, peerA.addr)
	bUDP := mustResolve(t, peerB.addr)

	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := proxy.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pkt := append([]byte(nil), buf[:n]...)
			if from.String() == aUDP.String() {
				proxy.WriteToUDP(pkt, bUDP)
			} else {
				proxy.WriteToUDP(pkt, aUDP)
			}
		}
	}()

	peerA.startReadLoop()
	peerB.startReadLoop()

	pAddr := mustResolve(t, proxyAddr)
	peerA.pc.AddKnownPeer(pAddr, peerB.kp.PublicKey)
	peerB.pc.AddKnownPeer(pAddr, peerA.kp.PublicKey)

	connA := peerA.waitConnected(t, 5*time.Second)
	peerB.waitConnected(t, 5*time.Second)

	// Attacker injects, from A's apparent address (the proxy), forged control:
	//  1. an old-style cleartext "dead" (version + a now-unknown 0x05 type byte)
	//  2. a PacketControl with a bogus counter and garbage ciphertext
	forgedCleartextDead := []byte{network.ProtocolVersion, 0x05}
	forgedControl := make([]byte, 2+8+16) // version, type, counter, garbage "ciphertext"
	forgedControl[0] = network.ProtocolVersion
	forgedControl[1] = network.PacketControl
	for i := 2; i < len(forgedControl); i++ {
		forgedControl[i] = 0xAB
	}
	proxy.WriteToUDP(forgedCleartextDead, bUDP)
	proxy.WriteToUDP(forgedControl, bUDP)

	// The forged packets must not have torn down B's session: a real data message
	// from A still arrives. (If B had accepted a forged "dead", its session would be
	// gone and this message would never decrypt.)
	time.Sleep(200 * time.Millisecond)
	msg := []byte("still connected")
	if err := peerA.pc.Send(connA, msg); err != nil {
		t.Fatalf("send: %v", err)
	}
	select {
	case got := <-peerB.recv:
		if string(got.data) != string(msg) {
			t.Fatalf("B received %q, want %q", got.data, msg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("B's session was torn down by a forged control packet")
	}

	// And B never surfaced a Dead event.
	select {
	case addr := <-peerB.pc.Dead:
		t.Fatalf("B wrongly declared peer %v dead from a forged packet", addr)
	default:
	}
}
