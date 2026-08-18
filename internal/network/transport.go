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
	// recvBatch is the number of datagrams one call to a receive function can
	// return — the bind's own batch size.
	recvBatch int
	// batch is the pipeline batch size: rx queue sizing, consumer batches
	// (ReadTunBatch), and send chunking. It is deliberately NOT tied to the
	// bind's BatchSize: WinRingBind reports 1 (batching in and out of the RIO
	// ring is an upstream TODO), which would otherwise disable the parallel
	// seal/open and batched TUN writes entirely on Windows. Every bind's Send
	// accepts arbitrarily long bufs slices, so sending IdealBatchSize-sized
	// batches is always safe.
	batch int
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
	recvBatch := bind.BatchSize()
	batch := wgconn.IdealBatchSize
	if recvBatch > batch {
		batch = recvBatch
	}
	return &Transport{bind: bind, recvFns: fns, port: port, recvBatch: recvBatch, batch: batch}, nil
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
		bind:      b,
		recvFns:   []wgconn.ReceiveFunc{b.receive},
		port:      uint16(c.LocalAddr().(*net.UDPAddr).Port),
		recvBatch: 1, // receive fills exactly one datagram per call
		batch:     b.BatchSize(),
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

func (b *udpBind) Close() error           { return b.conn.Close() }
func (b *udpBind) SetMark(_ uint32) error { return nil }
func (b *udpBind) BatchSize() int         { return wgconn.IdealBatchSize }

// stunServer is the public STUN server used to discover this host's public
// address for NAT traversal.
const stunServer = "stun.l.google.com:19302"

// stunProbeServers are the servers ProbeNATMapping queries. Detecting
// endpoint-dependent ("symmetric") mapping requires two servers at *different*
// IP addresses: the whole test is whether the NAT hands out the same external
// port for two different destinations. They are deliberately run by different
// operators, so one being down or anycast-collapsed does not silently turn the
// test into a comparison of one server with itself.
var stunProbeServers = []string{
	"stun.l.google.com:19302",
	"stun.cloudflare.com:3478",
	"stun.nextcloud.com:443",
}

// parseSTUNMapped extracts the XOR-MAPPED-ADDRESS from a datagram, reporting
// false for anything that is not a decodable STUN binding response.
func parseSTUNMapped(pkt []byte) (string, bool) {
	m := &stun.Message{Raw: pkt}
	if err := m.Decode(); err != nil {
		return "", false
	}
	var xorAddr stun.XORMappedAddress
	if err := xorAddr.GetFrom(m); err != nil {
		return "", false
	}
	return fmt.Sprintf("%s:%d", xorAddr.IP, xorAddr.Port), true
}

// DiscoverPublicAddr sends a STUN binding request through the tunnel's own
// bind (so the discovered mapping is the one peers will punch to) and returns
// the public "ip:port". Unlike the old one-shot version it retransmits, since
// a single lost STUN datagram used to hang connection setup forever.
//
// Sending the request is also what creates (or refreshes) the NAT mapping peers
// punch to, which is why RefreshPublicAddr calls this on a timer while no peer
// is established — see the comment there.
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
				addr, ok := parseSTUNMapped(pkt)
				if !ok {
					continue // unrelated non-protocol packet
				}
				timer.Stop()
				return addr, nil
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

// NATMapping is what ProbeNATMapping learned about the local NAT.
type NATMapping struct {
	// Servers and Addrs are the two STUN servers that answered and the public
	// address each one saw, in the same order.
	Servers [2]string
	Addrs   [2]string
	// EndpointIndependent is true when both servers saw the same public
	// address. That is the property hole punching needs: the address one peer
	// discovers via STUN is the address every other peer can send to.
	EndpointIndependent bool
}

// ProbeNATMapping reports whether this host's NAT assigns one external port per
// socket (endpoint-independent) or a different one per destination
// ("symmetric"). It queries two STUN servers from a single socket and compares
// what they saw.
//
// It uses its own UDP socket rather than the tunnel's bind: mapping behaviour is
// a property of the NAT, not of one particular socket, and keeping it standalone
// lets `blindspot ip --nat` answer the question without starting a session.
//
// Endpoint-dependent mapping means the address published to the room is only
// ever valid for the STUN server that reported it, so peers punch at a port
// nothing is listening on. That is the one failure this diagnostic exists to
// name, because it is otherwise indistinguishable from an ordinary timeout.
func ProbeNATMapping() (NATMapping, error) {
	var out NATMapping

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return out, fmt.Errorf("opening probe socket: %w", err)
	}
	defer conn.Close()

	var (
		servers []string
		addrs   []string
		lastErr error
	)
	for _, srv := range stunProbeServers {
		addr, err := stunProbe(conn, srv)
		if err != nil {
			lastErr = err
			continue
		}
		// A second server that resolved to the same IP as the first proves
		// nothing: the comparison has to be across two distinct destinations.
		servers = append(servers, srv)
		addrs = append(addrs, addr)
		if len(servers) == 2 {
			break
		}
	}
	if len(servers) < 2 {
		if lastErr == nil {
			lastErr = fmt.Errorf("not enough STUN servers answered")
		}
		return out, fmt.Errorf("need two STUN servers to compare, got %d: %w", len(servers), lastErr)
	}

	out.Servers = [2]string{servers[0], servers[1]}
	out.Addrs = [2]string{addrs[0], addrs[1]}
	out.EndpointIndependent = addrs[0] == addrs[1]
	return out, nil
}

// stunProbe sends a binding request to one server on conn and returns the public
// address it reported. Retransmits, like DiscoverPublicAddr, because a single
// lost datagram must not be read as "this server is down".
func stunProbe(conn *net.UDPConn, server string) (string, error) {
	raddr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", server, err)
	}
	req := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	buf := make([]byte, 1500)
	for attempt := 0; attempt < 3; attempt++ {
		if _, err := conn.WriteToUDP(req.Raw, raddr); err != nil {
			return "", fmt.Errorf("sending to %s: %w", server, err)
		}
		deadline := time.Now().Add(2 * time.Second)
		conn.SetReadDeadline(deadline)
		for time.Now().Before(deadline) {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				break // timed out; retransmit
			}
			// Only the server we are currently asking can answer this question:
			// a late reply from the previous server carries the previous
			// server's view and would compare the socket with itself.
			if !from.IP.Equal(raddr.IP) || from.Port != raddr.Port {
				continue
			}
			if addr, ok := parseSTUNMapped(buf[:n]); ok {
				return addr, nil
			}
		}
	}
	return "", fmt.Errorf("no response from %s", server)
}
