package cmd

import (
	"encoding/base64"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/neozmmv/blindspot/internal/network"
	"github.com/neozmmv/blindspot/internal/session"
)

// registerInterval is how often a peer re-announces itself so the discovery
// endpoint's TTL never expires under it. Comfortably inside roomserver.PeerTTL
// (10 minutes), which is the shorter of the two TTLs this has to satisfy.
const registerInterval = 5 * time.Minute

// mappingRefreshInterval is how often a peer with no established connection
// re-runs STUN, which both refreshes the NAT mapping peers punch to and
// re-reads what that mapping currently is.
//
// It has to beat the shortest NAT UDP idle timeout in play. Home routers sit
// around 300s, but mobile carriers commonly expire an idle UDP mapping in
// 30-60s, so this leaves a 2-4x margin against the worst case.
//
// Nothing else keeps the socket warm before a peer connects: the handshake
// driver only starts once discovery names a peer, and KeepAliveAll only walks
// sessions that are already established. That gap is the whole problem — a
// peer that publishes its address and then waits (a room host waiting out the
// joiner's Tor bootstrap waits minutes) goes silent long enough for the mapping
// to lapse, and the address left sitting in the room points at nothing.
const mappingRefreshInterval = 15 * time.Second

// peerRoster turns discovery announcements into live peer connections.
//
// It owns the bookkeeping every command needs around discovery: which announced
// peers already have a connection, keeping this peer's own registration alive,
// and following the peer stream across a change of discovery endpoint (an onion
// room moving to a new host). What differs per command — VPN routing versus
// printing chat lines — is left to the caller, which is why add reports the
// address it used rather than doing anything with it.
type peerRoster struct {
	ref       *discoveryRef
	conn      *network.PeerConn
	pubKeyB64 string

	// mu guards known, which is touched by the initial join, the SSE stream,
	// the periodic re-register, and the peer-death handler — and the address
	// fields below, which the mapping refresh rewrites when the NAT moves us.
	mu    sync.Mutex
	known map[string]bool

	publicAddr string
	myPublicIP string
	// streamReset is closed and replaced when publicAddr changes, so the SSE
	// stream reconnects under the new address. The room filters our own
	// announcements out of our stream by the udp_addr the stream was opened
	// with, so a stream still naming the old one would hand us our own
	// registration as though it were a peer.
	streamReset chan struct{}
}

func newPeerRoster(ref *discoveryRef, conn *network.PeerConn, publicAddr, pubKeyB64 string) *peerRoster {
	return &peerRoster{
		ref:         ref,
		conn:        conn,
		pubKeyB64:   pubKeyB64,
		publicAddr:  publicAddr,
		myPublicIP:  strings.Split(publicAddr, ":")[0],
		known:       map[string]bool{},
		streamReset: make(chan struct{}),
	}
}

// self returns the address this peer is currently published under and its
// public IP. They move together when the NAT mapping changes, so they are read
// together rather than field by field.
func (r *peerRoster) self() (addr, ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.publicAddr, r.myPublicIP
}

// resetCh fires when the published address changed and the stream must be
// reopened against it.
func (r *peerRoster) resetCh() <-chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.streamReset
}

// join announces this peer to the current discovery endpoint and returns
// everyone already present, for the caller to feed through add. create maps to
// the rendezvous server's "create a password session" step; onion rooms have no
// such concept and always pass false.
func (r *peerRoster) join(create bool) ([]session.PeerAddr, error) {
	cur, _ := r.ref.current()
	myAddr, _ := r.self()
	peers, selfIndex, err := cur.Register(myAddr, r.pubKeyB64, create)
	if err != nil {
		return nil, err
	}
	r.ref.setSelfIndex(selfIndex)
	return peers, nil
}

// add validates an announced peer and, if it is new, pins its static key and
// kicks off the Noise handshake. It reports the address chosen — a peer behind
// the same public IP is reached on its local address instead, with no internet
// round-trip — and whether the peer was newly added.
func (r *peerRoster) add(peer session.PeerAddr) (string, bool) {
	// Our own registration comes back to us: the room excludes the caller from
	// what it returns and streams, but a re-registration is announced to every
	// open stream including our own. Without this guard a peer adds itself as a
	// peer on its first keepalive and drives a handshake against itself — which
	// cannot complete, since the role split needs two distinct static keys.
	myAddr, myIP := r.self()
	if peer.Public == myAddr {
		return peer.Public, false
	}

	addrStr := peer.Public
	if strings.Split(peer.Public, ":")[0] == myIP && peer.Local != "" {
		addrStr = peer.Local
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addrStr)
	if err != nil {
		return addrStr, false
	}
	if !network.IsValidPeerAddr(udpAddr) {
		return addrStr, false // reject broadcast/multicast/unspecified IPs and privileged ports
	}
	pub, err := base64.StdEncoding.DecodeString(peer.PubKey)
	if err != nil || len(pub) != 32 {
		return addrStr, false // no valid pubkey from discovery → cannot handshake
	}

	r.mu.Lock()
	if r.known[udpAddr.String()] {
		r.mu.Unlock()
		return addrStr, false
	}
	r.known[udpAddr.String()] = true
	r.mu.Unlock()

	r.conn.AddKnownPeer(udpAddr, pub)
	return addrStr, true
}

// forget drops a dead peer so a later announcement — after a crash and rejoin —
// starts a fresh handshake instead of being ignored as already known.
func (r *peerRoster) forget(addr *net.UDPAddr) {
	r.mu.Lock()
	delete(r.known, addr.String())
	r.mu.Unlock()
}

// keepRegistered re-announces this peer until quit: on a timer to stay inside
// the discovery TTL, and immediately when the room hands over to a new host,
// since that host's room starts empty and waiting out the interval would leave
// it without even its own peers listed. Each response also re-announces peers
// that were dropped or that the stream missed, so they are fed back through add.
//
// onAdd, when non-nil, is called for each peer that was newly added.
func (r *peerRoster) keepRegistered(quit <-chan struct{}, onAdd func(string)) {
	ticker := time.NewTicker(registerInterval)
	defer ticker.Stop()
	for {
		select {
		case <-quit:
			return
		case <-r.ref.wakeCh(): // discovery moved to a new host; register there right away
		case <-ticker.C:
		}

		peers, err := r.join(false)
		if err != nil {
			continue
		}
		for _, peer := range peers {
			if addrStr, added := r.add(peer); added && onAdd != nil {
				onAdd(addrStr)
			}
		}
	}
}

// followStream consumes announcements until quit. The stream is re-established
// whenever discovery is swapped, so a handover to a new host reconnects instead
// of silently going deaf on the old one.
func (r *peerRoster) followStream(quit <-chan struct{}, onAdd func(string)) {
	for {
		select {
		case <-quit:
			return
		default:
		}
		cur, superseded := r.ref.current()
		myAddr, _ := r.self()
		for peer := range cur.StreamPeers(myAddr, anyClosed(quit, superseded, r.resetCh())) {
			if addrStr, added := r.add(peer); added && onAdd != nil {
				onAdd(addrStr)
			}
		}
	}
}

// leave removes this peer from the current discovery endpoint so the others
// stop trying to reach it.
func (r *peerRoster) leave() {
	cur, _ := r.ref.current()
	myAddr, _ := r.self()
	cur.Leave(myAddr)
}

// keepMappingAlive re-runs STUN on a timer while no peer is connected, so the
// address this peer published stays both alive and correct.
//
// One probe does two jobs. Sending the request refreshes the NAT mapping, which
// is what stops it lapsing while this peer waits — the case that matters is a
// room host that publishes its address and then waits out the joiner's Tor
// bootstrap, minutes during which nothing else touches the socket. Reading the
// reply says what the mapping now is, so a port that moved anyway (a carrier
// rotating it, or a lapsed mapping coming back somewhere else) is republished
// rather than left in the room pointing at nothing.
//
// It idles while anything is established: a live session's keepalives already
// keep the mapping warm, and re-registering under a session's nose would be
// pure churn. A session that later times out drops back to unestablished, which
// resumes this loop — which is what we want, because a timeout is one of the
// ways an address goes stale in the first place.
func (r *peerRoster) keepMappingAlive(quit <-chan struct{}, onAdd func(string)) {
	ticker := time.NewTicker(mappingRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-quit:
			return
		case <-ticker.C:
		}
		if r.conn.HasPeers() {
			continue
		}
		addr, err := r.conn.DiscoverPublicAddr()
		if err != nil {
			// The request went out regardless, so the mapping was refreshed even
			// though the reply was lost. There is nothing to republish; the next
			// tick tries again.
			continue
		}
		r.refreshAddr(addr, onAdd)
	}
}

// refreshAddr republishes this peer under a new public address, reporting
// whether the address actually changed.
//
// The old registration is explicitly left rather than abandoned to its TTL:
// the room keys peers by the address they registered with, so for up to
// roomserver.PeerTTL it would otherwise keep being announced to everyone,
// sending every one of them to punch at the address that just stopped working.
func (r *peerRoster) refreshAddr(newAddr string, onAdd func(string)) bool {
	r.mu.Lock()
	if newAddr == r.publicAddr {
		r.mu.Unlock()
		return false
	}
	oldAddr := r.publicAddr
	r.publicAddr = newAddr
	r.myPublicIP = strings.Split(newAddr, ":")[0]
	close(r.streamReset)
	r.streamReset = make(chan struct{})
	r.mu.Unlock()

	cur, _ := r.ref.current()
	cur.Leave(oldAddr)

	// Re-announce immediately instead of waiting for the register timer: until
	// this lands nobody in the room can reach us at all.
	peers, err := r.join(false)
	if err != nil {
		return true // the periodic re-register will retry
	}
	for _, peer := range peers {
		if addrStr, added := r.add(peer); added && onAdd != nil {
			onAdd(addrStr)
		}
	}
	return true
}
