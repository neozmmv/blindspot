package network

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/neozmmv/blindspot/internal/crypto"
)

// benchSide is one loopback peer: a real PeerConn over a WrapUDPConn transport.
type benchSide struct {
	pc   *PeerConn
	addr *net.UDPAddr
	kp   *crypto.KeyPair
}

func newBenchSide(b *testing.B, psk []byte) *benchSide {
	b.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		b.Fatalf("ListenUDP: %v", err)
	}
	// Large socket buffers so the loopback path measures the pipeline, not the
	// default 64 KB kernel queue.
	conn.SetReadBuffer(7 << 20)
	conn.SetWriteBuffer(7 << 20)
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		b.Fatalf("GenerateKeyPair: %v", err)
	}
	pc := NewPeerConn(WrapUDPConn(conn), kp.PrivateKey, kp.PublicKey, psk, Prologue("bench-session"))
	return &benchSide{pc: pc, addr: conn.LocalAddr().(*net.UDPAddr), kp: kp}
}

// benchPair returns two handshaked peers on loopback.
func benchPair(b *testing.B) (*benchSide, *benchSide) {
	b.Helper()
	psk := crypto.DerivePSK("bench-pass-123", "bench-session")
	sa := newBenchSide(b, psk)
	sb := newBenchSide(b, psk)
	if err := sa.pc.AddKnownPeer(sb.addr, sb.kp.PublicKey); err != nil {
		b.Fatalf("AddKnownPeer: %v", err)
	}
	if err := sb.pc.AddKnownPeer(sa.addr, sa.kp.PublicKey); err != nil {
		b.Fatalf("AddKnownPeer: %v", err)
	}
	for _, s := range []*benchSide{sa, sb} {
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

// BenchmarkTunnelSend measures the transmit pipeline — batched counter
// reservation, parallel AES-GCM seal, batched socket writes — through a real
// loopback UDP socket while a receiver actively drains (drops don't stall the
// sender; UDP semantics). Reported MB/s is tunnel payload throughput.
func BenchmarkTunnelSend(b *testing.B) {
	sa, sb := benchPair(b)

	// Active receiver: drain and decrypt whatever survives the loopback queue.
	go func() {
		bufs := make([][]byte, sb.pc.BatchSize())
		for i := range bufs {
			bufs[i] = make([]byte, 1600)
		}
		senders := make([]string, sb.pc.BatchSize())
		for {
			if _, err := sb.pc.ReadTunBatch(bufs, senders); err != nil {
				return
			}
		}
	}()

	const payloadSize = 1420
	batch := sa.pc.BatchSize()
	payloads := make([][]byte, batch)
	for i := range payloads {
		pkt := make([]byte, payloadSize)
		pkt[0] = 0x45 // minimal IPv4-looking header so nothing chokes downstream
		payloads[i] = pkt
	}

	b.SetBytes(payloadSize)
	b.ResetTimer()
	for sent := 0; sent < b.N; {
		m := batch
		if rem := b.N - sent; rem < m {
			m = rem
		}
		if err := sa.pc.SendTunBatch(sb.addr, payloads[:m]); err != nil {
			b.Fatalf("SendTunBatch: %v", err)
		}
		sent += m
	}
}

// BenchmarkTunnelRoundtrip measures delivered end-to-end throughput: the
// receiver must actually authenticate, decrypt, and pass the replay window for
// every counted packet. Loopback UDP can drop under pressure, so the sender
// paces itself with a crude in-flight window driven by the receiver's count.
func BenchmarkTunnelRoundtrip(b *testing.B) {
	sa, sb := benchPair(b)

	const payloadSize = 1420
	received := make(chan int, 1024)
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

	batch := sa.pc.BatchSize()
	payloads := make([][]byte, batch)
	for i := range payloads {
		pkt := make([]byte, payloadSize)
		pkt[0] = 0x45
		payloads[i] = pkt
	}

	b.SetBytes(payloadSize)
	b.ResetTimer()
	sent, got := 0, 0
	deadline := time.Now().Add(60 * time.Second)
	for got < b.N {
		// Keep at most 4 batches in flight to stay under the loopback queue.
		for sent-got < 4*batch && sent < b.N+8*batch {
			m := batch
			if err := sa.pc.SendTunBatch(sb.addr, payloads[:m]); err != nil {
				b.Fatalf("SendTunBatch: %v", err)
			}
			sent += m
		}
		select {
		case n := <-received:
			got += n
		case <-time.After(100 * time.Millisecond):
			// Loss on loopback: top the window back up.
			if time.Now().After(deadline) {
				b.Fatalf("stalled: sent %d, received %d of %d", sent, got, b.N)
			}
			sent = got
		}
	}
}

var benchSink error

// BenchmarkSealBatch isolates the parallel encrypt stage (no socket): how fast
// can a batch of tunnel packets be sealed across cores.
func BenchmarkSealBatch(b *testing.B) {
	sa, sb := benchPair(b)
	_ = sb
	s := sa.pc.sessionByAddr(sb.addr)
	if s == nil {
		b.Fatal("no session")
	}
	const payloadSize = 1420
	batch := 128
	payloads := make([][]byte, batch)
	for i := range payloads {
		payloads[i] = make([]byte, payloadSize)
	}
	s.mu.Lock()
	aead := s.txAEAD
	s.mu.Unlock()
	if aead == nil {
		b.Fatal("no tx AEAD")
	}
	b.SetBytes(payloadSize)
	b.ResetTimer()
	for done := 0; done < b.N; done += batch {
		wire := make([][]byte, batch)
		parallelFor(batch, func(i int) {
			wire[i] = sealPacket(aead, PacketTun, uint64(done+i), payloads[i])
		})
		for _, w := range wire {
			putPacketBuf(w)
		}
	}
	benchSink = fmt.Errorf("%d", b.N) // defeat dead-code elimination
}
