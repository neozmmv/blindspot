package main

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/neozmmv/blindspot/internal/crypto"
	"github.com/neozmmv/blindspot/internal/network"
)

// deliverAndRead spins up a real PeerConn, delivers `payload` as a single UDP
// datagram, then shuts the socket down so the read loop unblocks. It returns the
// value recovered from any panic inside PeerConn.Read (nil if none).
//
// This exercises the live, remotely reachable parse path with attacker-controlled
// bytes and asserts it never panics (Etapa 0, #3/#11/#12).
func deliverAndRead(t *testing.T, payload []byte) (panicVal any) {
	t.Helper()

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pc := network.NewPeerConn(conn, kp.PrivateKey, kp.PublicKey)

	var (
		mu   sync.Mutex
		pv   any
		done = make(chan struct{})
	)
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				mu.Lock()
				pv = r
				mu.Unlock()
			}
		}()
		for {
			if _, _, _, err := pc.Read(); err != nil {
				return // socket closed → clean exit
			}
		}
	}()

	sender, err := net.DialUDP("udp4", nil, conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	sender.Write(payload) // deliberately unchecked: a send error is fine for the test
	sender.Close()

	// Give the read loop time to process the datagram, then tear everything down.
	time.Sleep(50 * time.Millisecond)
	pc.Shutdown() // stop any PunchHole goroutine a valid-looking HELLO may have started
	conn.Close()  // unblock ReadFromUDP so the goroutine returns

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("read loop did not exit after socket close")
	}

	mu.Lock()
	defer mu.Unlock()
	return pv
}

// TestReadDoesNotPanicOnMalformedPackets feeds a table of malformed datagrams
// through the real read loop and asserts none of them panic.
func TestReadDoesNotPanicOnMalformedPackets(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
	}{
		{"empty", []byte{}},
		{"single-data-type-byte", []byte{network.PacketData}},
		{"single-tun-type-byte", []byte{network.PacketTun}},
		{"single-hello-type-byte", []byte{network.PacketHello}},
		{"short-hello", []byte{network.PacketHello, 0x01, 0x02}},
		{"hello-31-byte-key", append([]byte{network.PacketHello}, make([]byte, 31)...)},
		{"hello-33-byte-key-too-long", append([]byte{network.PacketHello}, make([]byte, 33)...)},
		{"data-too-short-for-nonce", []byte{network.PacketData, 0x00, 0x01}},
		{"unknown-type", []byte{0xFF, 0xAA, 0xBB}},
		{"tun-truncated", append([]byte{network.PacketTun}, make([]byte, 5)...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if pv := deliverAndRead(t, tc.payload); pv != nil {
				t.Fatalf("Read panicked on %q payload: %v", tc.name, pv)
			}
		})
	}
}

// FuzzReadPacket drives arbitrary bytes through the read loop and asserts the
// parser never panics regardless of input.
func FuzzReadPacket(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{network.PacketHello})
	f.Add([]byte{network.PacketData, 0x00})
	f.Add(append([]byte{network.PacketHello}, make([]byte, 32)...))
	f.Add([]byte{0x07, 0x45, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		if pv := deliverAndRead(t, data); pv != nil {
			t.Fatalf("Read panicked on fuzz payload %x: %v", data, pv)
		}
	})
}

// TestIsValidPeerAddr covers the rendezvous-address filter (Etapa 0, #7): reject
// broadcast/multicast/unspecified IPs and privileged ports, but keep loopback and
// private addresses that legitimate same-NAT peers use.
func TestIsValidPeerAddr(t *testing.T) {
	mk := func(ip string, port int) *net.UDPAddr {
		return &net.UDPAddr{IP: net.ParseIP(ip), Port: port}
	}
	cases := []struct {
		name string
		addr *net.UDPAddr
		want bool
	}{
		{"public-high-port", mk("203.0.113.7", 51820), true},
		{"loopback-high-port", mk("127.0.0.1", 40000), true},
		{"private-high-port", mk("192.168.1.5", 40000), true},
		{"limited-broadcast", mk("255.255.255.255", 40000), false},
		{"multicast", mk("224.0.0.1", 40000), false},
		{"unspecified", mk("0.0.0.0", 40000), false},
		{"privileged-port-dns", mk("203.0.113.7", 53), false},
		{"port-zero", mk("203.0.113.7", 0), false},
		{"port-1023", mk("203.0.113.7", 1023), false},
		{"port-1024-boundary", mk("203.0.113.7", 1024), true},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := network.IsValidPeerAddr(tc.addr); got != tc.want {
				t.Fatalf("IsValidPeerAddr(%v) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
}
