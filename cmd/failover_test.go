package cmd

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/neozmmv/blindspot/internal/roomserver"
	"github.com/neozmmv/blindspot/internal/session"
)

func newRef(t *testing.T, url string) *discoveryRef {
	t.Helper()
	return newDiscoveryRef(session.NewClient(url, roomserver.RoomSessionID, "", http.DefaultClient))
}

// A supervisor whose Tor bits are nil: enough to exercise every decision that
// does not actually publish a descriptor.
func newSupervisor(t *testing.T, url string, log *[]string) *roomSupervisor {
	t.Helper()
	var mu sync.Mutex
	return &roomSupervisor{
		onionURL:  url,
		torClient: http.DefaultClient,
		ref:       newRef(t, url),
		progress: func(m string) {
			mu.Lock()
			defer mu.Unlock()
			*log = append(*log, m)
		},
	}
}

func TestFetchVersionParsesHostSession(t *testing.T) {
	ts := httptest.NewServer(roomserver.New("v9", "nonce-abc").Handler())
	defer ts.Close()

	v, err := fetchVersion(http.DefaultClient, ts.URL)
	if err != nil {
		t.Fatalf("fetchVersion: %v", err)
	}
	if v.HostSession != "nonce-abc" || v.Version != "v9" {
		t.Fatalf("unexpected payload: %+v", v)
	}
}

func TestFetchVersionErrorsOnNon200(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	if _, err := fetchVersion(http.DefaultClient, ts.URL); err == nil {
		t.Fatal("a 503 should be an error, not a healthy host")
	}
}

// The core of the split-brain defence: if the address now answers with somebody
// else's nonce, our descriptor was overwritten and we must stop serving.
func TestSelfCheckStepsDownWhenAnotherHostAnswers(t *testing.T) {
	ts := httptest.NewServer(roomserver.New("v9", "somebody-else").Handler())
	defer ts.Close()

	var log []string
	sup := newSupervisor(t, ts.URL, &log)
	sup.hosting = true
	sup.hostNonce = "mine"
	sup.closeHost = func() {}

	sup.selfCheck()

	if sup.isHosting() {
		t.Fatal("host should have stepped down after seeing another peer's nonce")
	}
}

// Our own nonce coming back means we are still the host; nothing should change.
func TestSelfCheckKeepsHostingWhenNonceMatches(t *testing.T) {
	ts := httptest.NewServer(roomserver.New("v9", "mine").Handler())
	defer ts.Close()

	var log []string
	sup := newSupervisor(t, ts.URL, &log)
	sup.hosting = true
	sup.hostNonce = "mine"
	sup.closeHost = func() { t.Fatal("must not tear down hosting when the nonce matches") }

	sup.selfCheck()

	if !sup.isHosting() {
		t.Fatal("host stepped down despite serving its own nonce")
	}
}

// Reaching our own onion goes out through Tor and back, and that path fails for
// its own reasons. An unreachable address is not proof we lost the race, so
// stepping down on it would hand the room to nobody.
func TestSelfCheckKeepsHostingWhenUnreachable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := ts.URL
	ts.Close() // nothing is listening now

	var log []string
	sup := newSupervisor(t, url, &log)
	sup.hosting = true
	sup.hostNonce = "mine"
	sup.closeHost = func() { t.Fatal("must not tear down hosting on an unreachable self-check") }

	sup.selfCheck()

	if !sup.isHosting() {
		t.Fatal("host stepped down because it could not reach itself")
	}
}

// If somebody else won the election while we were waiting out our stagger, we
// must not publish over them.
func TestAttemptTakeoverYieldsWhenRoomIsAnsweringAgain(t *testing.T) {
	ts := httptest.NewServer(roomserver.New("v9", "the-winner").Handler())
	defer ts.Close()

	var log []string
	sup := newSupervisor(t, ts.URL, &log)
	sup.ref.setSelfIndex(0) // no stagger, act immediately

	quit := make(chan struct{})
	sup.attemptTakeover(t.Context(), quit)

	if sup.isHosting() {
		t.Fatal("took over a room that was already being served")
	}
	for _, m := range log {
		if m == "host is gone; taking over the room" {
			t.Fatal("should not have announced a takeover")
		}
	}
}

// The stagger is what keeps two peers from publishing at the same instant, so
// it has to actually be honoured — and be interruptible when the session ends.
func TestAttemptTakeoverStaggersByIndexAndHonoursQuit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := ts.URL
	ts.Close()

	var log []string
	sup := newSupervisor(t, url, &log)
	sup.ref.setSelfIndex(5) // 5 * takeoverJitterBase — far longer than this test waits

	quit := make(chan struct{})
	done := make(chan struct{})
	go func() {
		sup.attemptTakeover(t.Context(), quit)
		close(done)
	}()

	// Still waiting out its stagger, so it must not have published yet.
	time.Sleep(150 * time.Millisecond)
	if sup.isHosting() {
		t.Fatal("peer with index 5 took over without waiting its turn")
	}

	close(quit)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("attemptTakeover ignored quit and kept waiting")
	}
	if sup.isHosting() {
		t.Fatal("took over after the session was told to quit")
	}
}

// Swapping endpoints must wake the long-lived stream so it reconnects to the
// new host, and nudge a re-registration so the new room is not left empty.
func TestSwapSupersedesAndWakes(t *testing.T) {
	ref := newRef(t, "http://old.onion")
	_, superseded := ref.current()

	ref.swap(session.NewClient("http://new.onion", roomserver.RoomSessionID, "", http.DefaultClient))

	select {
	case <-superseded:
	case <-time.After(time.Second):
		t.Fatal("old stream was never told its endpoint was superseded")
	}
	select {
	case <-ref.wakeCh():
	case <-time.After(time.Second):
		t.Fatal("swap did not request an immediate re-registration")
	}

	cur, _ := ref.current()
	if cur.BaseURL != "http://new.onion" {
		t.Fatalf("current endpoint is %q, want the new one", cur.BaseURL)
	}
}

// Swapping to the identical client would needlessly drop a healthy stream.
func TestSwapToSameClientIsANoOp(t *testing.T) {
	c := session.NewClient("http://same.onion", roomserver.RoomSessionID, "", http.DefaultClient)
	ref := newDiscoveryRef(c)
	_, superseded := ref.current()

	ref.swap(c)

	select {
	case <-superseded:
		t.Fatal("swapping to the same client tore down the existing stream")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestAnyClosedFiresOnFirstClose(t *testing.T) {
	a, b := make(chan struct{}), make(chan struct{})
	out := anyClosed(a, b)

	select {
	case <-out:
		t.Fatal("fired before either input closed")
	case <-time.After(50 * time.Millisecond):
	}

	close(b)
	select {
	case <-out:
	case <-time.After(time.Second):
		t.Fatal("did not fire when an input closed")
	}
}
