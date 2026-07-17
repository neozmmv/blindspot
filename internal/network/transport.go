package network

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/pion/stun"
	wgconn "golang.zx2c4.com/wireguard/conn"
)

// The tunnel transport rides on wireguard-go's conn.Bind instead of a raw
// *net.UDPConn. The Bind batches datagrams through the kernel — UDP GSO/GRO and
// sendmmsg/recvmmsg on Linux, registered I/O (RIO) rings on Windows — so the
// per-packet syscall cost that capped throughput is amortized across batches of
// up to conn.IdealBatchSize packets. The Bind is protocol-agnostic: everything
// above it (Noise handshake, framing, AEAD, replay protection) is unchanged.

// maxUDPPacket is the receive buffer size per batch slot. It must hold the
// largest possible datagram: with GRO the kernel can hand back a coalesced
// super-packet of up to 64 KB in a single slot before the bind splits it.
const maxUDPPacket = 65536

// packetBufSize is the pooled buffer size for individual wire packets. It
// covers the transport header + a full tunnel MTU payload + AEAD tag with room
// to spare; larger (rare, e.g. long chat lines) packets fall back to plain
// allocation.
const packetBufSize = 2048

var packetPool = sync.Pool{
	New: func() any {
		b := make([]byte, packetBufSize)
		return &b
	},
}

// getPacketBuf returns a buffer of length n, pooled when n fits the standard
// packet size.
func getPacketBuf(n int) []byte {
	if n <= packetBufSize {
		return (*packetPool.Get().(*[]byte))[:n]
	}
	return make([]byte, n)
}

// putPacketBuf recycles a buffer obtained from getPacketBuf. Buffers that were
// reallocated (or oversized ones) are simply dropped for the GC.
func putPacketBuf(b []byte) {
	if cap(b) == packetBufSize {
		b = b[:packetBufSize]
		packetPool.Put(&b)
	}
}

// canonAddrPort normalizes an address to its unmapped form so that
// "::ffff:1.2.3.4" and "1.2.3.4" produce the same session key regardless of
// which socket (v4/v6) or code path (ParseEndpoint vs. receive) produced it.
func canonAddrPort(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// canonEndpointKey derives the canonical session key ("ip:port") and AddrPort
// for a bind endpoint.
func canonEndpointKey(ep wgconn.Endpoint) (string, netip.AddrPort, bool) {
	ap, err := netip.ParseAddrPort(ep.DstToString())
	if err != nil {
		return "", netip.AddrPort{}, false
	}
	ap = canonAddrPort(ap)
	return ap.String(), ap, true
}

// Transport is an opened UDP transport: a bind in the listening state plus its
// receive functions, ready to be handed to NewPeerConn.
type Transport struct {
	bind    wgconn.Bind
	recvFns []wgconn.ReceiveFunc
	port    uint16
	batch   int
}

// OpenTransport opens the platform's default batched bind (RIO on Windows,
// GSO/sendmmsg-capable StdNetBind elsewhere) on an ephemeral port. The bind's
// own control functions already request large (7 MB) kernel socket buffers.
func OpenTransport() (*Transport, error) {
	bind := wgconn.NewDefaultBind()
	fns, port, err := bind.Open(0)
	if err != nil {
		return nil, fmt.Errorf("opening UDP bind: %w", err)
	}
	return &Transport{bind: bind, recvFns: fns, port: port, batch: bind.BatchSize()}, nil
}

// Port returns the local UDP port the transport is bound to.
func (t *Transport) Port() int { return int(t.port) }

// WrapUDPConn adapts an existing, already-bound *net.UDPConn into a Transport.
// It performs no batched I/O on receive (one datagram per call) and is meant
// for tests, which bind explicitly to loopback; production code uses
// OpenTransport.
func WrapUDPConn(c *net.UDPConn) *Transport {
	b := &udpBind{conn: c}
	return &Transport{
		bind:    b,
		recvFns: []wgconn.ReceiveFunc{b.receive},
		port:    uint16(c.LocalAddr().(*net.UDPAddr).Port),
		batch:   b.BatchSize(),
	}
}

// udpBind is a minimal conn.Bind over a pre-bound *net.UDPConn. Send accepts
// full batches (looping over WriteToUDPAddrPort) so the batched send path is
// exercised; receive returns one datagram per call.
type udpBind struct{ conn *net.UDPConn }

type udpEndpoint netip.AddrPort

func (e udpEndpoint) ClearSrc()           {}
func (e udpEndpoint) SrcToString() string { return "" }
func (e udpEndpoint) DstToString() string { return netip.AddrPort(e).String() }
func (e udpEndpoint) DstToBytes() []byte {
	b, _ := netip.AddrPort(e).MarshalBinary()
	return b
}
func (e udpEndpoint) DstIP() netip.Addr { return netip.AddrPort(e).Addr() }
func (e udpEndpoint) SrcIP() netip.Addr { return netip.Addr{} }

func (b *udpBind) Open(_ uint16) ([]wgconn.ReceiveFunc, uint16, error) {
	return []wgconn.ReceiveFunc{b.receive}, uint16(b.conn.LocalAddr().(*net.UDPAddr).Port), nil
}

func (b *udpBind) receive(packets [][]byte, sizes []int, eps []wgconn.Endpoint) (int, error) {
	n, addr, err := b.conn.ReadFromUDPAddrPort(packets[0])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	eps[0] = udpEndpoint(canonAddrPort(addr))
	return 1, nil
}

func (b *udpBind) Send(bufs [][]byte, ep wgconn.Endpoint) error {
	ue, ok := ep.(udpEndpoint)
	if !ok {
		return wgconn.ErrWrongEndpointType
	}
	for _, buf := range bufs {
		if _, err := b.conn.WriteToUDPAddrPort(buf, netip.AddrPort(ue)); err != nil {
			return err
		}
	}
	return nil
}

func (b *udpBind) ParseEndpoint(s string) (wgconn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return udpEndpoint(canonAddrPort(ap)), nil
}

func (b *udpBind) Close() error             { return b.conn.Close() }
func (b *udpBind) SetMark(_ uint32) error   { return nil }
func (b *udpBind) BatchSize() int           { return wgconn.IdealBatchSize }

// stunServer is the public STUN server used to discover this host's public
// address for NAT traversal.
const stunServer = "stun.l.google.com:19302"

// DiscoverPublicAddr sends a STUN binding request through the tunnel's own
// bind (so the discovered mapping is the one peers will punch to) and returns
// the public "ip:port". Unlike the old one-shot version it retransmits, since
// a single lost STUN datagram used to hang connection setup forever.
func (p *PeerConn) DiscoverPublicAddr() (string, error) {
	raddr, err := net.ResolveUDPAddr("udp4", stunServer)
	if err != nil {
		return "", fmt.Errorf("resolving STUN server address: %w", err)
	}
	ep, err := p.bind.ParseEndpoint(canonAddrPort(raddr.AddrPort()).String())
	if err != nil {
		return "", fmt.Errorf("parsing STUN endpoint: %w", err)
	}

	ch := make(chan []byte, 4)
	p.stunWaiter.Store(&ch)
	defer p.stunWaiter.Store(nil)

	req := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	for attempt := 0; attempt < 4; attempt++ {
		if err := p.bind.Send([][]byte{req.Raw}, ep); err != nil {
			return "", fmt.Errorf("sending STUN request: %w", err)
		}
		timer := time.NewTimer(2 * time.Second)
	wait:
		for {
			select {
			case pkt := <-ch:
				m := &stun.Message{Raw: pkt}
				if err := m.Decode(); err != nil {
					continue // unrelated non-protocol packet
				}
				var xorAddr stun.XORMappedAddress
				if err := xorAddr.GetFrom(m); err != nil {
					continue
				}
				timer.Stop()
				return fmt.Sprintf("%s:%d", xorAddr.IP, xorAddr.Port), nil
			case <-timer.C:
				break wait
			case <-p.stop:
				timer.Stop()
				return "", net.ErrClosed
			}
		}
	}
	return "", fmt.Errorf("no response from STUN server %s", stunServer)
}
