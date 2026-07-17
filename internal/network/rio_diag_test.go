package network

// Diagnostic benchmarks over the REAL platform bind (WinRingBind on Windows),
// not the WrapUDPConn test adapter. Temporary: used to chase the 0–2 MB/s
// oscillation seen in real transfers.

import (
	"net"
	"testing"
	"time"

	"github.com/neozmmv/blindspot/internal/crypto"
)

type rioSide struct {
	pc   *PeerConn
	addr *net.UDPAddr
	kp   *crypto.KeyPair
}

func newRIOSide(t *testing.B, psk []byte) *rioSide {
	t.Helper()
	tr, err := OpenTransport()
	if err != nil {
		t.Fatalf("OpenTransport: %v", err)
	}
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pc := NewPeerConn(tr, kp.PrivateKey, kp.PublicKey, psk, Prologue("bench-session"))
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: tr.Port()}
	return &rioSide{pc: pc, addr: addr, kp: kp}
}

func rioPair(b *testing.B) (*rioSide, *rioSide) {
	b.Helper()
	psk := crypto.DerivePSK("bench-pass-123", "bench-session")
	sa := newRIOSide(b, psk)
	sb := newRIOSide(b, psk)
	if err := sa.pc.AddKnownPeer(sb.addr, sb.kp.PublicKey); err != nil {
		b.Fatalf("AddKnownPeer: %v", err)
	}
	if err := sb.pc.AddKnownPeer(sa.addr, sa.kp.PublicKey); err != nil {
		b.Fatalf("AddKnownPeer: %v", err)
	}
	for _, s := range []*rioSide{sa, sb} {
		select {
		case <-s.pc.Connected:
		case <-time.After(5 * time.Second):
			b.Fatal("handshake did not complete")
		}
	}
	b.Cleanup(func() {
		sa.pc.Close()
		sb.pc.Close()
	})
	return sa, sb
}

// BenchmarkRIOTunnelDelivered measures delivered throughput through the real
// bind with a windowed sender, and reports the loss rate.
func BenchmarkRIOTunnelDelivered(b *testing.B) {
	sa, sb := rioPair(b)

	const payloadSize = 1420
	received := make(chan int, 4096)
	go func() {
		bufs := make([][]byte, sb.pc.BatchSize())
		for i := range bufs {
			bufs[i] = make([]byte, 1600)
		}
		senders := make([]string, sb.pc.BatchSize())
		for {
			n, err := sb.pc.ReadTunBatch(bufs, senders)
			if err != nil {
				return
			}
			received <- n
		}
	}()

	const sendGroup = 64 // what the connect.go sender typically aggregates
	payloads := make([][]byte, sendGroup)
	for i := range payloads {
		pkt := make([]byte, payloadSize)
		pkt[0] = 0x45
		payloads[i] = pkt
	}

	b.SetBytes(payloadSize)
	b.ResetTimer()
	sent, got, timeouts := 0, 0, 0
	deadline := time.Now().Add(60 * time.Second)
	for got < b.N {
		for sent-got < 8*sendGroup && sent < b.N+16*sendGroup {
			if err := sa.pc.SendTunBatch(sb.addr, payloads); err != nil {
				b.Fatalf("SendTunBatch: %v", err)
			}
			sent += sendGroup
		}
		select {
		case n := <-received:
			got += n
		case <-time.After(100 * time.Millisecond):
			timeouts++
			if time.Now().After(deadline) {
				b.Fatalf("stalled: sent %d, received %d of %d", sent, got, b.N)
			}
			sent = got // window resync after loss
		}
	}
	b.ReportMetric(float64(timeouts), "loss-stalls")
	b.ReportMetric(float64(sb.pc.BatchSize()), "bind-batch")
}

// BenchmarkRIOTunnelBlast sends as fast as the tx path allows with no window
// and reports what fraction survives to the receiver — measures raw rx-side
// drop behavior of the real bind under burst load.
func BenchmarkRIOTunnelBlast(b *testing.B) {
	sa, sb := rioPair(b)

	const payloadSize = 1420
	var got int64
	done := make(chan struct{})
	go func() {
		bufs := make([][]byte, sb.pc.BatchSize())
		for i := range bufs {
			bufs[i] = make([]byte, 1600)
		}
		senders := make([]string, sb.pc.BatchSize())
		for {
			n, err := sb.pc.ReadTunBatch(bufs, senders)
			if err != nil {
				close(done)
				return
			}
			got += int64(n)
		}
	}()

	const sendGroup = 64
	payloads := make([][]byte, sendGroup)
	for i := range payloads {
		pkt := make([]byte, payloadSize)
		pkt[0] = 0x45
		payloads[i] = pkt
	}

	b.SetBytes(payloadSize)
	b.ResetTimer()
	for sent := 0; sent < b.N; sent += sendGroup {
		if err := sa.pc.SendTunBatch(sb.addr, payloads); err != nil {
			b.Fatalf("SendTunBatch: %v", err)
		}
	}
	elapsedDrain := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(elapsedDrain) {
		time.Sleep(50 * time.Millisecond)
	}
	b.StopTimer()
	b.ReportMetric(float64(got)/float64(b.N)*100, "delivered-%")
}
