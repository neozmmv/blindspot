package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/neozmmv/blindspot/internal/roomserver"
)

func newTestRoom(t *testing.T) *httptest.Server {
	t.Helper()
	srv := roomserver.New("test", "nonce-1", roomserver.ModeVPN)
	// Keep the SSE keepalive short so a finished test's handler returns promptly
	// instead of parking on the 30s production interval.
	srv.SetStreamKeepAlive(200 * time.Millisecond)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

type registerResp struct {
	Peers []roomserver.Peer `json:"peers"`
	Index int               `json:"index"`
	Error string            `json:"error"`
}

func register(t *testing.T, base, udpAddr, pubKey string) registerResp {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"udp_addr":   udpAddr,
		"local_addr": "192.168.1.5:1234",
		"pub_key":    pubKey,
	})
	resp, err := http.Post(base+"/session/room", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("register %s: %v", udpAddr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register %s: status %d", udpAddr, resp.StatusCode)
	}
	var out registerResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

func indexOf(t *testing.T, base, udpAddr string) int {
	t.Helper()
	// Register a throwaway probe so the response lists the peer we care about.
	for _, p := range register(t, base, "probe:1", "probe-key").Peers {
		if p.IP == udpAddr {
			return p.Index
		}
	}
	t.Fatalf("peer %s not present in room", udpAddr)
	return -1
}

// A peer that registers first should not see itself in the returned peer list,
// and should see peers that joined before it.
func TestRegisterReturnsOtherPeersOnly(t *testing.T) {
	ts := newTestRoom(t)

	first := register(t, ts.URL, "1.1.1.1:100", "key-a")
	if len(first.Peers) != 0 {
		t.Fatalf("first peer should see an empty room, got %+v", first.Peers)
	}

	second := register(t, ts.URL, "2.2.2.2:200", "key-b")
	if len(second.Peers) != 1 || second.Peers[0].IP != "1.1.1.1:100" {
		t.Fatalf("second peer should see exactly the first, got %+v", second.Peers)
	}
	if second.Peers[0].PubKey != "key-a" {
		t.Fatalf("pub_key not propagated, got %q", second.Peers[0].PubKey)
	}
}

// A peer cannot read its own index out of "peers", which lists everyone else —
// so the response has to report it directly. Failover staggers takeover by this
// number, so without it every peer would act at once.
func TestRegisterReportsCallersOwnIndex(t *testing.T) {
	ts := newTestRoom(t)

	first := register(t, ts.URL, "1.1.1.1:100", "key-a")
	if first.Index != 0 {
		t.Fatalf("first peer to join should be index 0, got %d", first.Index)
	}

	second := register(t, ts.URL, "2.2.2.2:200", "key-b")
	if second.Index != 1 {
		t.Fatalf("second peer should be index 1, got %d", second.Index)
	}

	// And it stays put across a keepalive, matching what others see.
	again := register(t, ts.URL, "1.1.1.1:100", "key-a")
	if again.Index != 0 {
		t.Fatalf("re-registering changed the caller's own index to %d", again.Index)
	}
	for _, p := range second.Peers {
		if p.IP == "1.1.1.1:100" && p.Index != first.Index {
			t.Fatalf("peer sees index %d for a peer that was told %d", p.Index, first.Index)
		}
	}
}

// Regression: peers re-register on a timer to stay inside the TTL. If that
// reassigned Index, join order would churn on every keepalive and the
// index-staggered failover election would be meaningless.
func TestIndexIsStableAcrossReRegistration(t *testing.T) {
	ts := newTestRoom(t)

	register(t, ts.URL, "1.1.1.1:100", "key-a")
	register(t, ts.URL, "2.2.2.2:200", "key-b")

	before := indexOf(t, ts.URL, "1.1.1.1:100")

	for i := 0; i < 5; i++ {
		register(t, ts.URL, "1.1.1.1:100", "key-a") // keepalive
	}

	after := indexOf(t, ts.URL, "1.1.1.1:100")
	if before != after {
		t.Fatalf("index churned across re-registration: %d -> %d", before, after)
	}
}

// Indices are assigned under the room lock, so concurrent joins must still get
// distinct values — two peers sharing an index would both take over at once.
func TestConcurrentRegistrationsGetUniqueIndices(t *testing.T) {
	ts := newTestRoom(t)

	const n = 25
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			register(t, ts.URL, fmt.Sprintf("10.0.0.%d:100", i), fmt.Sprintf("key-%d", i))
		}(i)
	}
	wg.Wait()

	seen := map[int]string{}
	for _, p := range register(t, ts.URL, "probe:1", "probe-key").Peers {
		if other, dup := seen[p.Index]; dup {
			t.Fatalf("duplicate index %d shared by %s and %s", p.Index, other, p.IP)
		}
		seen[p.Index] = p.IP
	}
	if len(seen) != n {
		t.Fatalf("expected %d distinct peers, got %d", n, len(seen))
	}
}

// A peer already streaming must be told about someone who joins afterwards —
// this is the whole point of the SSE channel.
func TestStreamBroadcastsLaterJoiner(t *testing.T) {
	ts := newTestRoom(t)

	register(t, ts.URL, "1.1.1.1:100", "key-a")

	req, _ := http.NewRequest("GET", ts.URL+"/session/room/stream?udp_addr=1.1.1.1:100", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("expected SSE content type, got %q", ct)
	}

	got := make(chan roomserver.Peer, 1)
	go func() {
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "data:") {
				continue
			}
			var p roomserver.Peer
			if json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(line, "data:"))), &p) == nil {
				got <- p
				return
			}
		}
	}()

	// Give the stream a moment to register its notifier before the join lands.
	time.Sleep(200 * time.Millisecond)
	register(t, ts.URL, "2.2.2.2:200", "key-b")

	select {
	case p := <-got:
		if p.IP != "2.2.2.2:200" {
			t.Fatalf("expected the later joiner, got %+v", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("streaming peer was never told about the later joiner")
	}
}

// A stream must not be told about itself, or a peer would try to hole-punch to
// its own address.
func TestStreamExcludesSelf(t *testing.T) {
	ts := newTestRoom(t)
	register(t, ts.URL, "1.1.1.1:100", "key-a")

	req, _ := http.NewRequest("GET", ts.URL+"/session/room/stream?udp_addr=1.1.1.1:100", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	defer resp.Body.Close()

	seen := make(chan string, 4)
	go func() {
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data:") {
				var p roomserver.Peer
				if json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(line, "data:"))), &p) == nil {
					seen <- p.IP
				}
			}
		}
	}()

	select {
	case ip := <-seen:
		t.Fatalf("stream replayed the subscriber to itself: %s", ip)
	case <-time.After(1 * time.Second): // nothing arrived, which is correct
	}
}

// An idle stream must keep emitting something. Over Tor a silent connection is
// liable to be torn down, and the client reads a dead stream as a missing host,
// which would trigger a spurious failover.
func TestStreamEmitsKeepAliveWhenIdle(t *testing.T) {
	ts := newTestRoom(t) // keepalive shortened to 200ms

	req, _ := http.NewRequest("GET", ts.URL+"/session/room/stream?udp_addr=9.9.9.9:900", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	defer resp.Body.Close()

	got := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			if strings.HasPrefix(scanner.Text(), ":") { // SSE comment frame
				got <- scanner.Text()
				return
			}
		}
	}()

	select {
	case <-got: // a keepalive arrived on an otherwise idle room
	case <-time.After(5 * time.Second):
		t.Fatal("idle stream never emitted a keepalive")
	}
}

func TestLeaveRemovesPeer(t *testing.T) {
	ts := newTestRoom(t)

	register(t, ts.URL, "1.1.1.1:100", "key-a")
	register(t, ts.URL, "2.2.2.2:200", "key-b")

	body, _ := json.Marshal(map[string]string{"udp_addr": "1.1.1.1:100"})
	resp, err := http.Post(ts.URL+"/session/room/leave", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("leave: %v", err)
	}
	resp.Body.Close()

	for _, p := range register(t, ts.URL, "probe:1", "probe-key").Peers {
		if p.IP == "1.1.1.1:100" {
			t.Fatal("peer still present after leaving")
		}
	}
}

// A peer that stops re-registering must age out, or a crashed peer would linger
// in the room forever and be handed to others as a hole-punch target.
func TestPeerExpiresAfterTTL(t *testing.T) {
	srv := roomserver.New("test", "nonce-1", roomserver.ModeVPN)
	srv.SetPeerTTL(300 * time.Millisecond)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	register(t, ts.URL, "1.1.1.1:100", "key-a")
	if len(srv.Peers()) != 1 {
		t.Fatalf("expected 1 peer right after registering, got %d", len(srv.Peers()))
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(srv.Peers()) == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("peer never expired; still %d in room", len(srv.Peers()))
}

// Re-registering inside the TTL must cancel the pending expiry, otherwise the
// original watcher would evict a peer that is actively keeping itself alive.
func TestReRegistrationCancelsPendingExpiry(t *testing.T) {
	srv := roomserver.New("test", "nonce-1", roomserver.ModeVPN)
	srv.SetPeerTTL(400 * time.Millisecond)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	register(t, ts.URL, "1.1.1.1:100", "key-a")
	for i := 0; i < 4; i++ {
		time.Sleep(200 * time.Millisecond) // keepalive well inside the TTL
		register(t, ts.URL, "1.1.1.1:100", "key-a")
	}

	if len(srv.Peers()) == 0 {
		t.Fatal("peer was evicted despite re-registering inside the TTL")
	}
}

// /version carries the host nonce that failover uses to detect that another
// peer's descriptor has replaced this host's, and the mode that tells an
// arriving peer whether this room is theirs to join at all.
func TestVersionReportsHostSessionAndMode(t *testing.T) {
	srv := roomserver.New("v1.2.3", "nonce-xyz", roomserver.ModeChat)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/version")
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	defer resp.Body.Close()

	var out struct {
		Version     string          `json:"version"`
		HostSession string          `json:"host_session"`
		Mode        roomserver.Mode `json:"mode"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Version != "v1.2.3" || out.HostSession != "nonce-xyz" || out.Mode != roomserver.ModeChat {
		t.Fatalf("unexpected /version payload: %+v", out)
	}
}

func TestRegisterRejectsMissingUdpAddr(t *testing.T) {
	ts := newTestRoom(t)

	body, _ := json.Marshal(map[string]string{"local_addr": "192.168.1.5:1234"})
	resp, err := http.Post(ts.URL+"/session/room", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing udp_addr, got %d", resp.StatusCode)
	}
}
