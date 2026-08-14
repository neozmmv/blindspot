// Package roomserver is the peer-discovery API a Blindspot peer serves while it
// is hosting a room over a Tor onion service.
//
// It is a port of the standalone clearnet rendezvous server, trimmed to the one
// shape the onion model needs. Three things are deliberately gone:
//
//   - The SecretSession family (create_session, join_session*) and its password
//     check. The onion address is derived from name+password, so anyone who can
//     reach this server already proved they know the secret.
//   - The session table. There is exactly one room per onion service instance,
//     so the map[string]Session collapses to a single room value.
//   - The per-IP rate limiter. Every request arrives through the local onion
//     listener, so c.ClientIP() is the same non-distinguishing value for every
//     peer; ported unchanged it would throttle the whole room as one bucket.
package roomserver

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// PeerTTL is how long a peer stays in the room without re-registering. Peers
// re-register well inside this window to keep themselves alive.
const PeerTTL = 10 * time.Minute

// StreamKeepAlive is how often an idle SSE stream emits a comment frame. Tor
// circuits are long-lived but an idle HTTP response through one is not, and the
// client treats a dead stream as a missing host.
const StreamKeepAlive = 30 * time.Second

// RoomSessionID is the fixed session id used in the route paths. There is one
// room per onion service, so nothing has to be agreed separately from
// name+password; it exists only to keep the URL shape the existing client in
// internal/session already speaks.
const RoomSessionID = "room"

// Peer is one participant's reachability info, as broadcast to the room.
type Peer struct {
	IP        string `json:"ip"`
	LocalAddr string `json:"local_addr"`
	PubKey    string `json:"pub_key"`
	// Index is join order, assigned by the host on first registration and held
	// stable across re-registration. Failover uses it to stagger takeover
	// attempts, so it must not churn while a peer is merely keeping alive.
	Index int `json:"index"`
}

type room struct {
	mu          sync.Mutex
	peers       []Peer
	nextIndex   int
	indexByAddr map[string]int
	notifiers   []chan Peer
	peerCancels map[string]context.CancelFunc
	ttl         time.Duration
	keepAlive   time.Duration
}

// Server is a room's HTTP API, ready to be mounted on an onion listener.
type Server struct {
	room        *room
	version     string
	hostSession string
}

// New builds a room server. hostSession is a nonce identifying this host
// process; it is echoed from /version so a host can detect that another peer's
// descriptor has overwritten its own (see the failover design).
func New(version, hostSession string) *Server {
	return &Server{
		room: &room{
			indexByAddr: map[string]int{},
			peerCancels: map[string]context.CancelFunc{},
			ttl:         PeerTTL,
			keepAlive:   StreamKeepAlive,
		},
		version:     version,
		hostSession: hostSession,
	}
}

// SetPeerTTL overrides how long a peer survives without re-registering. Tests
// use it to exercise expiry without waiting out PeerTTL.
func (s *Server) SetPeerTTL(d time.Duration) {
	s.room.mu.Lock()
	defer s.room.mu.Unlock()
	s.room.ttl = d
}

// SetStreamKeepAlive overrides the SSE keepalive interval.
func (s *Server) SetStreamKeepAlive(d time.Duration) {
	s.room.mu.Lock()
	defer s.room.mu.Unlock()
	s.room.keepAlive = d
}

// Handler wires the routes. gin.New rather than gin.Default: this runs inside
// the CLI daemon, where per-request logging to stdout is noise.
func (s *Server) Handler() http.Handler {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	r.POST("/session/:id", s.register)
	r.GET("/session/:id/stream", s.stream)
	r.POST("/session/:id/leave", s.leave)
	r.GET("/version", s.versionInfo)

	return r
}

func (s *Server) versionInfo(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"version":      s.version,
		"host_session": s.hostSession,
	})
}

func (s *Server) register(c *gin.Context) {
	var body struct {
		UdpAddr   string `json:"udp_addr"`
		LocalAddr string `json:"local_addr"`
		PubKey    string `json:"pub_key"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.UdpAddr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "udp_addr required"})
		return
	}

	rm := s.room
	rm.mu.Lock()

	// A re-registration supersedes the previous TTL watcher for this peer.
	if cancel, exists := rm.peerCancels[body.UdpAddr]; exists {
		cancel()
	}

	// Everyone except the registering peer — this is both the response body and
	// the set that already knows about each other.
	existing := make([]Peer, 0, len(rm.peers))
	for _, p := range rm.peers {
		if p.IP != body.UdpAddr {
			existing = append(existing, p)
		}
	}

	// Join order is assigned once and then held. Peers re-register on a timer to
	// stay inside PeerTTL, and reassigning here would make every index climb on
	// every keepalive, destroying the ordering failover depends on.
	index, seen := rm.indexByAddr[body.UdpAddr]
	if !seen {
		index = rm.nextIndex
		rm.nextIndex++
		rm.indexByAddr[body.UdpAddr] = index
	}

	newPeer := Peer{
		IP:        body.UdpAddr,
		LocalAddr: body.LocalAddr,
		PubKey:    body.PubKey,
		Index:     index,
	}
	rm.peers = append(existing, newPeer)

	for _, ch := range rm.notifiers {
		select {
		case ch <- newPeer:
		default: // slow consumer; it will re-register and be re-announced
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	rm.peerCancels[body.UdpAddr] = cancel
	rm.mu.Unlock()

	go rm.expirePeerAfterTTL(ctx, body.UdpAddr)

	// "index" is the caller's own join order. Peers need it to stagger failover
	// attempts, and it cannot be read off "peers", which lists everyone else.
	c.JSON(http.StatusOK, gin.H{"peers": existing, "index": index})
}

func (s *Server) stream(c *gin.Context) {
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")

	myAddr := c.Query("udp_addr")
	rm := s.room

	rm.mu.Lock()
	keepAlive := rm.keepAlive
	ch := make(chan Peer, len(rm.peers)+10)
	for _, peer := range rm.peers {
		if peer.IP != myAddr {
			ch <- peer
		}
	}
	rm.notifiers = append(rm.notifiers, ch)
	rm.mu.Unlock()

	defer func() {
		rm.mu.Lock()
		for i, n := range rm.notifiers {
			if n == ch {
				rm.notifiers = append(rm.notifiers[:i], rm.notifiers[i+1:]...)
				break
			}
		}
		rm.mu.Unlock()
	}()

	c.Stream(func(w io.Writer) bool {
		select {
		case peer, ok := <-ch:
			if !ok {
				return false
			}
			c.SSEvent("peer", peer)
			return true
		case <-time.After(keepAlive):
			fmt.Fprint(w, ": keepalive\n\n")
			return true
		case <-c.Request.Context().Done():
			return false
		}
	})
}

func (s *Server) leave(c *gin.Context) {
	var body struct {
		UdpAddr string `json:"udp_addr"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.UdpAddr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "udp_addr required"})
		return
	}

	rm := s.room
	rm.mu.Lock()
	rm.removeLocked(body.UdpAddr)
	// An explicit leave forfeits the join order; coming back is a new join.
	delete(rm.indexByAddr, body.UdpAddr)
	rm.mu.Unlock()

	c.JSON(http.StatusOK, gin.H{"message": "left session"})
}

// removeLocked drops a peer and cancels its TTL watcher. Caller holds rm.mu.
func (rm *room) removeLocked(udpAddr string) {
	for i, p := range rm.peers {
		if p.IP == udpAddr {
			rm.peers = append(rm.peers[:i], rm.peers[i+1:]...)
			break
		}
	}
	if cancel, ok := rm.peerCancels[udpAddr]; ok {
		cancel()
		delete(rm.peerCancels, udpAddr)
	}
}

func (rm *room) expirePeerAfterTTL(ctx context.Context, udpAddr string) {
	rm.mu.Lock()
	ttl := rm.ttl
	rm.mu.Unlock()

	select {
	case <-time.After(ttl):
	case <-ctx.Done():
		return // re-registered or left; a newer watcher owns this peer
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()
	for i, p := range rm.peers {
		if p.IP == udpAddr {
			rm.peers = append(rm.peers[:i], rm.peers[i+1:]...)
			break
		}
	}
	delete(rm.peerCancels, udpAddr)
	// indexByAddr is intentionally kept: a peer that times out and comes back
	// reclaims its original join order rather than jumping to the end.
}

// Peers returns a snapshot, for tests and for the host's own bookkeeping.
func (s *Server) Peers() []Peer {
	s.room.mu.Lock()
	defer s.room.mu.Unlock()
	return append([]Peer(nil), s.room.peers...)
}
