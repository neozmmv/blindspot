package main

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/neozmmv/blindspot/internal/network"
)

// TestAntiReplayRejectsReinjectedPacket proves the sliding-window anti-replay
// protection: a valid, already-delivered transport packet that is captured and
// reinjected is rejected by the receiver and never delivered twice.
//
// A and B talk through a MITM UDP proxy that records the A→B data packet. After
// B receives it once, the proxy reinjects the identical bytes; B must drop it.
func TestAntiReplayRejectsReinjectedPacket(t *testing.T) {
	const sessionID, password = "replay-session", "replaypass1"

	peerA := newTestPeer(t, sessionID, password)
	defer peerA.conn.Close()
	defer peerA.pc.Shutdown()

	peerB := newTestPeer(t, sessionID, password)
	defer peerB.conn.Close()
	defer peerB.pc.Shutdown()

	// MITM proxy: both peers address the proxy; it forwards A↔B and records the
	// A→B data packet so we can replay it verbatim.
	proxy, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	defer proxy.Close()
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxy.LocalAddr().(*net.UDPAddr).Port)

	aUDP := mustResolve(t, peerA.addr)
	bUDP := mustResolve(t, peerB.addr)

	var mu sync.Mutex
	var lastData []byte // most recent A→B PacketData packet, captured verbatim

	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := proxy.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pkt := append([]byte(nil), buf[:n]...)
			if from.String() == aUDP.String() {
				if len(pkt) >= 2 && pkt[1] == network.PacketData {
					mu.Lock()
					lastData = pkt
					mu.Unlock()
				}
				proxy.WriteToUDP(pkt, bUDP)
			} else {
				proxy.WriteToUDP(pkt, aUDP)
			}
		}
	}()

	peerA.startReadLoop()
	peerB.startReadLoop()

	// Both peers pin each other's key and run the handshake through the proxy addr.
	pAddr := mustResolve(t, proxyAddr)
	peerA.pc.AddKnownPeer(pAddr, peerB.kp.PublicKey)
	peerB.pc.AddKnownPeer(pAddr, peerA.kp.PublicKey)

	connA := peerA.waitConnected(t, 5*time.Second)
	peerB.waitConnected(t, 5*time.Second)

	// A sends a data message; B must receive it exactly once.
	msg := []byte("replay me")
	if err := peerA.pc.Send(connA, msg); err != nil {
		t.Fatalf("send: %v", err)
	}
	select {
	case got := <-peerB.recv:
		if string(got.data) != string(msg) {
			t.Fatalf("B received %q, want %q", got.data, msg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("B did not receive the original message")
	}

	// Reinject the captured packet.
	mu.Lock()
	rec := lastData
	mu.Unlock()
	if rec == nil {
		t.Fatal("no A→B data packet was captured")
	}
	if _, err := proxy.WriteToUDP(rec, bUDP); err != nil {
		t.Fatalf("replay write: %v", err)
	}

	// B must NOT deliver the replayed packet again.
	select {
	case got := <-peerB.recv:
		t.Fatalf("anti-replay failed: B re-delivered %q", got.data)
	case <-time.After(1500 * time.Millisecond):
	}

	// Sanity check: a fresh packet (higher counter) still gets through, proving the
	// window rejects only the replay, not all subsequent traffic.
	fresh := []byte("fresh packet")
	if err := peerA.pc.Send(connA, fresh); err != nil {
		t.Fatalf("send fresh: %v", err)
	}
	select {
	case got := <-peerB.recv:
		if string(got.data) != string(fresh) {
			t.Fatalf("B received %q, want %q", got.data, fresh)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("B did not receive the fresh message after the replay")
	}
}
