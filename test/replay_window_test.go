package main

import (
	"testing"

	"github.com/neozmmv/blindspot/internal/network"
)

// TestReplayWindow exercises the sliding-window bitmap directly: fresh counters
// are accepted once, duplicates rejected, reordering within the window
// tolerated, and counters at or beyond the enforced window edge rejected —
// including the RFC 6479 boundary word, where accepting would alias bits
// already reused by a newer epoch.
func TestReplayWindow(t *testing.T) {
	var w network.ReplayWindow

	if !w.Check(0) {
		t.Fatal("first counter 0 rejected")
	}
	if w.Check(0) {
		t.Fatal("replayed counter 0 accepted")
	}

	// In-order advance.
	for c := uint64(1); c <= 10; c++ {
		if !w.Check(c) {
			t.Fatalf("in-order counter %d rejected", c)
		}
	}
	// Duplicate of an in-window counter.
	if w.Check(5) {
		t.Fatal("replayed counter 5 accepted")
	}

	// Jump ahead, then fill in reordered counters within the window.
	if !w.Check(1000) {
		t.Fatal("counter 1000 rejected")
	}
	for _, c := range []uint64{999, 500, 11} {
		if !w.Check(c) {
			t.Fatalf("reordered in-window counter %d rejected", c)
		}
		if w.Check(c) {
			t.Fatalf("replayed counter %d accepted", c)
		}
	}

	// Advance far so old counters fall outside the enforced window
	// (ReplayWindowSize - 64 behind the highest counter).
	max := uint64(100000)
	if !w.Check(max) {
		t.Fatal("large jump rejected")
	}
	if w.Check(max - network.ReplayWindowSize) {
		t.Fatal("counter beyond the window accepted")
	}
	// Boundary word: within ReplayWindowSize of max but inside the one-word
	// guard band — must be rejected, or it would alias a newer epoch's bits.
	if w.Check(max - network.ReplayWindowSize + 63) {
		t.Fatal("counter in the guard-band word accepted")
	}
	// Just inside the enforced window: accepted once, then rejected as replay.
	edge := max - (network.ReplayWindowSize - 64)
	if !w.Check(edge) {
		t.Fatalf("counter %d at the window edge rejected", edge)
	}
	if w.Check(edge) {
		t.Fatal("replayed edge counter accepted")
	}

	// A jump larger than the whole bitmap resets it: the new counter is fresh
	// and everything before the new window is stale.
	if !w.Check(max + 10*network.ReplayWindowSize) {
		t.Fatal("post-reset counter rejected")
	}
	if w.Check(max) {
		t.Fatal("stale counter accepted after bitmap reset")
	}
}
