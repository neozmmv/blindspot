package cmd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/cretz/bine/tor"
	"github.com/neozmmv/blindspot/internal/roomserver"
	"github.com/neozmmv/blindspot/internal/session"
)

// Failover timings. These are starting points chosen from measured onion
// latency, not tuned against a real multi-peer deployment — see the note on
// jitterBase about what a bad choice costs.
const (
	// hostHeartbeatInterval is how often a client checks the host is still there.
	hostHeartbeatInterval = 45 * time.Second
	// hostFailuresBeforeTakeover is how many consecutive heartbeat failures are
	// needed before a client will consider taking over. Onion fetches were
	// measured from 6s to 63s with occasional far worse outliers, so a single
	// failure means very little.
	hostFailuresBeforeTakeover = 3
	// hostSelfCheckInterval is how often a host re-probes its own onion address
	// to confirm it is still the one being served. Much slower than the client
	// heartbeat because each check is a full circuit to our own service, and
	// because losing a descriptor race is rare.
	hostSelfCheckInterval = 5 * time.Minute
	// takeoverJitterBase staggers takeover by join order: peer with index N
	// waits N*base before acting. It must comfortably exceed the time for one
	// peer to publish a descriptor (~4s measured, but variable), or two peers
	// will publish over each other. Too large instead means a longer outage.
	takeoverJitterBase = 25 * time.Second
)

// roomSupervisor keeps exactly one peer hosting a room.
//
// Two things make this tractable. The room's onion address is derived, so it
// never changes: a client always talks to the same URL regardless of who is
// behind it, and clients reconnect to a new host on their own. And Tor's HSDir
// publication is last-writer-wins, so two peers publishing under the same key
// do not produce two visible hosts — they silently overwrite each other, which
// is why detection has to be after the fact (the nonce check) rather than by
// asking whether publishing "succeeded".
type roomSupervisor struct {
	tor       *tor.Tor
	priv      ed25519.PrivateKey
	onionURL  string
	torClient *http.Client
	ref       *discoveryRef
	mode      roomserver.Mode
	progress  func(string)

	mu        sync.Mutex
	hosting   bool
	hostNonce string
	closeHost func()
}

// versionInfo is the room's /version payload.
type versionInfo struct {
	Version     string `json:"version"`
	HostSession string `json:"host_session"`
	// Mode is what the host is running the room for. Empty from a host built
	// before rooms carried a mode, which could only ever have been a VPN room —
	// see roomMode.
	Mode roomserver.Mode `json:"mode"`
}

// fetchVersion asks whoever currently answers the room address who they are.
func fetchVersion(client *http.Client, baseURL string) (versionInfo, error) {
	var v versionInfo
	resp, err := client.Get(baseURL + "/version")
	if err != nil {
		return v, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return v, fmt.Errorf("room answered HTTP %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return v, fmt.Errorf("decoding /version: %w", err)
	}
	return v, nil
}

func (s *roomSupervisor) isHosting() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hosting
}

// startHosting publishes the onion service and points our own discovery at the
// local copy of the room.
func (s *roomSupervisor) startHosting(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hosting {
		return nil
	}

	local, nonce, closeHost, err := publishRoom(ctx, s.tor, s.priv, s.mode)
	if err != nil {
		return err
	}
	s.hosting, s.hostNonce, s.closeHost = true, nonce, closeHost
	s.ref.swap(session.NewClient(local, roomserver.RoomSessionID, "", http.DefaultClient))
	return nil
}

// stopHosting tears down our onion service and goes back to being a client of
// whoever else is now serving the address.
func (s *roomSupervisor) stopHosting() {
	s.mu.Lock()
	closeHost, wasHosting := s.closeHost, s.hosting
	s.hosting, s.hostNonce, s.closeHost = false, "", nil
	s.mu.Unlock()

	if !wasHosting {
		return
	}
	if closeHost != nil {
		closeHost()
	}
	s.ref.swap(session.NewClient(s.onionURL, roomserver.RoomSessionID, "", s.torClient))
}

// run supervises until quit. It alternates between two jobs depending on
// whether this peer is currently the host.
func (s *roomSupervisor) run(ctx context.Context, quit <-chan struct{}) {
	failures := 0
	// Reported once, not every heartbeat: a foreign-mode host does not resolve
	// itself, and repeating it would bury everything else the session prints.
	warnedForeign := false
	for {
		interval := hostHeartbeatInterval
		if s.isHosting() {
			interval = hostSelfCheckInterval
		}

		select {
		case <-quit:
			return
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}

		if s.isHosting() {
			s.selfCheck()
			continue
		}

		if info, err := fetchVersion(s.torClient, s.onionURL); err == nil {
			failures = 0
			// The address answers, but for the other mode — the losing side of
			// two peers publishing at once. Nothing here can fix it (the
			// descriptor is theirs now), and no peer connection can form across
			// modes, so the session is inert. Say so rather than leaving the
			// user watching a room that will never fill.
			if sameMode(s.mode, info.Mode) {
				warnedForeign = false // a host of our own mode is back; a later foreign one is worth reporting again
			} else if !warnedForeign {
				warnedForeign = true
				s.progress("this room is now hosted for " + modeName(info.Mode) +
					"; no peers will connect. Restart with " + modeCommand(info.Mode) + ", or use a different room name")
			}
			continue
		}
		if failures++; failures < hostFailuresBeforeTakeover {
			continue
		}
		failures = 0
		s.attemptTakeover(ctx, quit)
	}
}

// selfCheck confirms this host is still the one the address resolves to.
//
// A failure here is NOT evidence of losing the race: reaching our own onion
// service goes out through Tor and back, and that path breaks for its own
// reasons. Only a successful response carrying somebody else's nonce proves our
// descriptor was overwritten.
func (s *roomSupervisor) selfCheck() {
	s.mu.Lock()
	mine := s.hostNonce
	s.mu.Unlock()

	v, err := fetchVersion(s.torClient, s.onionURL)
	if err != nil {
		return
	}
	if v.HostSession != "" && v.HostSession != mine {
		if !sameMode(s.mode, v.Mode) {
			// Both sides published at once and theirs won. Stepping down is
			// still forced — our descriptor is gone — but name the reason,
			// because from here nothing will ever connect.
			s.progress("another peer took over the room for " + modeName(v.Mode) +
				"; no peers will connect. Restart with " + modeCommand(v.Mode) + ", or use a different room name")
		} else {
			s.progress("another peer took over the room; stepping down to client")
		}
		s.stopHosting()
	}
}

// attemptTakeover runs the election after the host has gone quiet.
//
// The stagger is by join order, so the lowest-index peer acts first and the
// others only act if it did not. Before publishing, the address is checked once
// more: whoever won during the wait is already serving, and publishing over
// them is exactly the split-brain this is trying to avoid.
func (s *roomSupervisor) attemptTakeover(ctx context.Context, quit <-chan struct{}) {
	delay := time.Duration(s.ref.SelfIndex()) * takeoverJitterBase
	if delay > 0 {
		select {
		case <-quit:
			return
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}

	if _, err := fetchVersion(s.torClient, s.onionURL); err == nil {
		return // somebody else got there first; stay a client
	}

	s.progress("host is gone; taking over the room")
	if err := s.startHosting(ctx); err != nil {
		s.progress("could not take over the room: " + err.Error())
	}
}

// publishRoom starts an onion service for the room and serves the room API on
// it, plus on a loopback listener whose URL is returned so the hosting peer can
// register with its own room without a pointless round trip through Tor.
func publishRoom(ctx context.Context, t *tor.Tor, priv ed25519.PrivateKey, mode roomserver.Mode) (localURL, nonce string, closeFn func(), err error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", "", nil, fmt.Errorf("generating host nonce: %w", err)
	}
	nonce = hex.EncodeToString(raw)

	srv := roomserver.New(getVersion(), nonce, mode)
	handler := srv.Handler()

	loopback, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", "", nil, fmt.Errorf("opening local room listener: %w", err)
	}

	onionSvc, err := t.Listen(ctx, &tor.ListenConf{
		Key:         priv,
		Version3:    true,
		RemotePorts: []int{80},
	})
	if err != nil {
		loopback.Close()
		return "", "", nil, fmt.Errorf("publishing onion service: %w", err)
	}

	go http.Serve(onionSvc, handler)
	go http.Serve(loopback, handler)

	return "http://" + loopback.Addr().String(), nonce, func() {
		onionSvc.Close()
		loopback.Close()
	}, nil
}
