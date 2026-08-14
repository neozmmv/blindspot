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

// peerRoster turns discovery announcements into live peer connections.
//
// It owns the bookkeeping every command needs around discovery: which announced
// peers already have a connection, keeping this peer's own registration alive,
// and following the peer stream across a change of discovery endpoint (an onion
// room moving to a new host). What differs per command — VPN routing versus
// printing chat lines — is left to the caller, which is why add reports the
// address it used rather than doing anything with it.
type peerRoster struct {
	ref        *discoveryRef
	conn       *network.PeerConn
	publicAddr string
	pubKeyB64  string
	myPublicIP string

	// mu guards known, which is touched by the initial join, the SSE stream,
	// the periodic re-register, and the peer-death handler.
	mu    sync.Mutex
	known map[string]bool
}

func newPeerRoster(ref *discoveryRef, conn *network.PeerConn, publicAddr, pubKeyB64 string) *peerRoster {
	return &peerRoster{
		ref:        ref,
		conn:       conn,
		publicAddr: publicAddr,
		pubKeyB64:  pubKeyB64,
		myPublicIP: strings.Split(publicAddr, ":")[0],
		known:      map[string]bool{},
	}
}

// join announces this peer to the current discovery endpoint and returns
// everyone already present, for the caller to feed through add. create maps to
// the rendezvous server's "create a password session" step; onion rooms have no
// such concept and always pass false.
func (r *peerRoster) join(create bool) ([]session.PeerAddr, error) {
	cur, _ := r.ref.current()
	peers, selfIndex, err := cur.Register(r.publicAddr, r.pubKeyB64, create)
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
	if peer.Public == r.publicAddr {
		return peer.Public, false
	}

	addrStr := peer.Public
	if strings.Split(peer.Public, ":")[0] == r.myPublicIP && peer.Local != "" {
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
		for peer := range cur.StreamPeers(r.publicAddr, anyClosed(quit, superseded)) {
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
	cur.Leave(r.publicAddr)
}
