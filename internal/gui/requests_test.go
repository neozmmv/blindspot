package gui

import (
	"io"
	"net"
	"testing"
)

// TestRequestHeaderRoundTrip locks the :28126 control-channel framing so it can't drift
// between tray versions (both ends must agree for the consent handshake to interoperate).
func TestRequestHeaderRoundTrip(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	const name = "quarterly report.pdf"
	const size uint64 = 9_400_123

	errc := make(chan error, 1)
	go func() { errc <- writeRequestHeader(c1, name, size) }()

	gotName, gotSize, err := readRequestHeader(c2)
	if err != nil {
		t.Fatalf("readRequestHeader: %v", err)
	}
	if werr := <-errc; werr != nil {
		t.Fatalf("writeRequestHeader: %v", werr)
	}
	if gotName != name || gotSize != size {
		t.Fatalf("round-trip = (%q, %d), want (%q, %d)", gotName, gotSize, name, size)
	}
}

// TestDecisionByte confirms the accept/decline response is a single 1/0 byte.
func TestDecisionByte(t *testing.T) {
	for _, accept := range []bool{true, false} {
		c1, c2 := net.Pipe()
		go func() {
			writeDecision(c1, accept)
			c1.Close()
		}()
		buf := make([]byte, 1)
		if _, err := io.ReadFull(c2, buf); err != nil {
			t.Fatalf("accept=%v: read: %v", accept, err)
		}
		want := byte(0)
		if accept {
			want = 1
		}
		if buf[0] != want {
			t.Fatalf("accept=%v: got byte %d, want %d", accept, buf[0], want)
		}
		c2.Close()
	}
}

// TestIPOnly checks the virtual-IP extraction used to attribute a request to a peer.
func TestIPOnly(t *testing.T) {
	addr, err := net.ResolveTCPAddr("tcp", "10.5.6.7:53000")
	if err != nil {
		t.Fatal(err)
	}
	if got := ipOnly(addr); got != "10.5.6.7" {
		t.Fatalf("ipOnly = %q, want 10.5.6.7", got)
	}
}
