package cmd

import (
	"context"
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/cretz/bine/tor"
	"github.com/neozmmv/blindspot/internal/roomkey"
	"github.com/neozmmv/blindspot/internal/roomserver"
	"github.com/neozmmv/blindspot/internal/session"
	"github.com/neozmmv/blindspot/internal/tornet"
)

// Timeouts here are set from measured behaviour, not guessed. Cold starts of the
// full derive → bootstrap → publish → first-fetch chain ranged from ~28s to
// ~187s across runs of identical code, so anything tuned to the fast case
// misfires badly on the slow one.
const (
	// roomProbeTimeout bounds a single "is somebody already hosting?" request.
	// A fetch of a known-good onion service was measured at 7.8s, 12.5s and
	// 62.8s; timing out early makes this peer wrongly conclude the room is empty
	// and publish a competing descriptor, which is the split-brain case, so this
	// errs long.
	roomProbeTimeout = 75 * time.Second
	// roomProbeAttempts is the ceiling on attempts before concluding nobody
	// hosts. Two consecutive definitive "host unreachable" replies short-circuit
	// this, so the count only matters for ambiguous failures worth retrying.
	roomProbeAttempts = 3
)

// roomProbeBackoff separates probe attempts. A variable rather than a constant
// so tests can exercise the retry logic without the real wait.
var roomProbeBackoff = 3 * time.Second

// roomSession is a live membership in a room: a discovery reference that always
// points at whoever is currently hosting, plus the Tor process and the
// supervisor that keeps exactly one peer in that role.
//
// `connect` and `chat` join a room identically and differ only in what they do
// with the peers they find, so the whole derive → bootstrap → probe →
// host-or-join chain lives here rather than in either command.
type roomSession struct {
	// ref is what the rest of a session talks to. It survives a change of host,
	// so nothing above the discovery layer is torn down by a handover.
	ref *discoveryRef

	onionID string

	tor  *tor.Tor
	sup  *roomSupervisor
	quit chan struct{}
}

// sameMode reports whether a host's advertised mode is the one this peer is
// running.
//
// An empty mode is a host built before rooms advertised one. Those could only
// ever have been VPN rooms — `chat` reached rooms in the same release that
// added the field — so that is what an empty value means, rather than "unknown,
// let it through".
func sameMode(want, got roomserver.Mode) bool {
	if got == "" {
		got = roomserver.ModeVPN
	}
	return want == got
}

// modeCommand names the command that joins a room of the given mode, for error
// messages that tell the user what to run instead.
func modeCommand(m roomserver.Mode) string {
	if m == roomserver.ModeChat {
		return "blindspot chat"
	}
	return "blindspot connect"
}

// modeName is how a mode is written in a message to the user.
func modeName(m roomserver.Mode) string {
	if m == roomserver.ModeChat {
		return "chat"
	}
	return "VPN"
}

// wrongMode is the error a peer gets when the room it derived is already being
// run for the other mode.
//
// The room that exists wins: this peer refuses rather than publishing a
// competing descriptor, which would split the room between two hosts and strand
// whoever is already in it.
func wrongMode(name string, got roomserver.Mode) error {
	return fmt.Errorf("room %q is already in use for %s — join it with %q, or pick a different room name",
		name, modeName(got), modeCommand(got))
}

// joinRoom derives the room's onion address from name+password, starts Tor, and
// either joins the peer already hosting the room or publishes it. Each step is
// reported through progress, because the chain routinely takes over a minute
// and silence for that long is indistinguishable from a hang.
//
// mode is what this peer intends the room for. A room already running the other
// mode is refused outright: see wrongMode.
//
// The caller owns ctx and must call close on the result.
func joinRoom(ctx context.Context, name, password string, mode roomserver.Mode, progress func(string)) (*roomSession, error) {
	priv, onionID, err := roomkey.ForRoom(name, password)
	if err != nil {
		return nil, err
	}
	// Argon2id just allocated 512 MiB and is done with it, but the process then
	// goes essentially idle — and Go's collector is driven by allocation, so
	// nothing would ever trigger it. Measured: RSS stays at 529 MiB for the life
	// of the session without this, and drops to ~18 MiB with it. Forcing the
	// scavenge costs a few milliseconds, once, at startup.
	debug.FreeOSMemory()

	onionURL := "http://" + onionID + ".onion"

	progress("starting Tor")
	t, err := tornet.Start(ctx)
	if err != nil {
		return nil, fmt.Errorf("starting tor: %w", err)
	}

	transport, err := tornet.HTTPTransport(ctx, t)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("building tor transport: %w", err)
	}
	torClient := &http.Client{Transport: transport, Timeout: roomProbeTimeout}

	// Discovery always points at the room's derived address; only a peer that
	// is itself hosting swaps to its local copy. Because the address never
	// changes, clients need no reconfiguration when hosting moves.
	ref := newDiscoveryRef(session.NewClient(onionURL, roomserver.RoomSessionID, "", torClient))
	sup := &roomSupervisor{
		tor:       t,
		priv:      priv,
		onionURL:  onionURL,
		torClient: torClient,
		ref:       ref,
		mode:      mode,
		progress:  progress,
	}

	progress("looking for an existing host at " + onionID + ".onion")
	// hostedElsewhere also reports why it concluded the room was empty; it is
	// dropped here to keep the CLI line readable. Worth routing to a debug log
	// if false negatives (publishing over a live host) ever need diagnosing.
	if hosted, info, _ := hostedElsewhere(torClient, onionURL); hosted {
		if !sameMode(mode, info.Mode) {
			t.Close()
			return nil, wrongMode(name, info.Mode)
		}
		progress("joining host at " + onionID + ".onion")
	} else {
		progress("no host found. publishing " + onionID + ".onion")
		if err := sup.startHosting(ctx); err != nil {
			t.Close()
			return nil, fmt.Errorf("publishing room: %w", err)
		}
		progress("hosting room at " + onionID + ".onion")
	}

	r := &roomSession{ref: ref, onionID: onionID, tor: t, sup: sup, quit: make(chan struct{})}
	// Watch for the host disappearing (or for losing a descriptor race while
	// hosting) for as long as the session lives.
	go sup.run(ctx, r.quit)
	return r, nil
}

// close stops supervising, gives up hosting if this peer had it, and shuts Tor
// down. Order matters: stepping down while the supervisor could still react to
// it, and before the Tor process it publishes through goes away.
func (r *roomSession) close() {
	close(r.quit)
	r.sup.stopHosting()
	r.tor.Close()
}

// hostedElsewhere reports whether the room's onion service already answers,
// what that host said about itself, and why it concluded otherwise.
//
// The reason matters for tuning and for debugging false negatives: concluding
// "empty" when a host is actually up makes this peer publish a competing
// descriptor, and since HSDir publication is last-writer-wins that shows up as
// the room's address flapping between two backends rather than as a clean error.
//
// A host counts as up only if it returns a /version payload that decodes. That
// is stricter than checking the status code, and deliberately so: the reply is
// where the room's mode comes from, and a 200 carrying something else is not a
// room this peer can join.
func hostedElsewhere(client *http.Client, onionURL string) (bool, versionInfo, string) {
	var last string
	misses := 0
	for i := 0; i < roomProbeAttempts; i++ {
		started := time.Now()
		info, err := fetchVersion(client, onionURL)
		took := time.Since(started).Round(time.Second)

		if err == nil {
			return true, info, ""
		}

		last = fmt.Sprintf("attempt %d: %v after %s", i+1, err, took)
		// Tor answers with SOCKS5 "host unreachable" when it cannot reach the
		// service at all — typically because no descriptor is published, i.e.
		// nobody is hosting. That arrives in seconds, where an ambiguous
		// failure burns the full per-attempt timeout, so treating it as
		// conclusive is the difference between hosting an empty room in ~15s
		// and in ~200s.
		//
		// It is not completely unambiguous: the same code appears when a
		// descriptor exists but its introduction points are failing. Two
		// consecutive misses are required before acting, so a host having one
		// bad moment does not get a competing descriptor published over it.
		if isOnionUnreachable(err) {
			if misses++; misses >= 2 {
				return false, versionInfo{}, last
			}
			time.Sleep(roomProbeBackoff)
			continue
		}
		misses = 0

		if i < roomProbeAttempts-1 {
			time.Sleep(roomProbeBackoff)
		}
	}
	return false, versionInfo{}, last
}

// isOnionUnreachable matches Tor's SOCKS5 "host unreachable" reply.
//
// golang.org/x/net/proxy renders reply codes as text and exposes no typed
// error, so this matches on that text. A false negative here is harmless — it
// only costs the slower timeout path.
func isOnionUnreachable(err error) bool {
	return strings.Contains(err.Error(), "host unreachable")
}
