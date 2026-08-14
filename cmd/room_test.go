package cmd

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/neozmmv/blindspot/internal/roomserver"
)

// The probe is where a peer learns what the room it found is for, so the mode
// has to survive the whole trip: host → /version → decoded reply.
func TestRoomProbeReportsHostMode(t *testing.T) {
	ts := httptest.NewServer(roomserver.New("v9", "nonce-abc", roomserver.ModeChat).Handler())
	defer ts.Close()

	hosted, info, why := hostedElsewhere(ts.Client(), ts.URL)
	if !hosted {
		t.Fatalf("expected the live host to be detected (%s)", why)
	}
	if info.Mode != roomserver.ModeChat {
		t.Fatalf("probe reported mode %q, want %q", info.Mode, roomserver.ModeChat)
	}
	if sameMode(roomserver.ModeVPN, info.Mode) {
		t.Fatal("a VPN peer must not accept a chat room")
	}
}

// The room that exists wins: the arriving peer is refused, and told what to run
// instead rather than being left to guess.
func TestWrongModeNamesTheOtherCommand(t *testing.T) {
	err := wrongMode("my-room", roomserver.ModeChat)
	if err == nil {
		t.Fatal("joining a chat room as a VPN peer must be an error")
	}
	for _, want := range []string{"my-room", "chat", "blindspot chat"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q should mention %q", err, want)
		}
	}

	if err := wrongMode("my-room", roomserver.ModeVPN); !strings.Contains(err.Error(), "blindspot connect") {
		t.Fatalf("error %q should point a chat peer at connect", err)
	}
}

// A host built before rooms advertised a mode reports none. Rooms only existed
// for the VPN then, so that is what an empty value means — a chat peer must be
// turned away from one, not waved through on a missing field.
func TestMissingModeIsTreatedAsVPN(t *testing.T) {
	if !sameMode(roomserver.ModeVPN, "") {
		t.Fatal("a VPN peer should accept a host that predates the mode field")
	}
	if sameMode(roomserver.ModeChat, "") {
		t.Fatal("a chat peer must not join a host that predates the mode field")
	}
	if got := wrongMode("my-room", ""); !strings.Contains(got.Error(), "blindspot connect") {
		t.Fatalf("error %q should name connect for a mode-less host", got)
	}
}
