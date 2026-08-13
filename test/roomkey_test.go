package main

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/neozmmv/blindspot/internal/roomkey"
)

// The whole scheme rests on this: two peers who never talk to each other must
// compute byte-identical keys from the same name+password.
func TestDeriveSeedIsDeterministic(t *testing.T) {
	a := roomkey.DeriveSeed("team-room", "correct-horse-battery")
	b := roomkey.DeriveSeed("team-room", "correct-horse-battery")

	if !bytes.Equal(a, b) {
		t.Fatalf("same name+password produced different seeds:\n%x\n%x", a, b)
	}
	if len(a) != ed25519.SeedSize {
		t.Fatalf("seed is %d bytes, ed25519 needs %d", len(a), ed25519.SeedSize)
	}
}

// The room name is the salt, so it must actually separate keyspaces: reusing a
// password across two rooms must not put both rooms behind the same address.
func TestDifferentNameYieldsDifferentSeed(t *testing.T) {
	const password = "correct-horse-battery"

	a := roomkey.DeriveSeed("team-room", password)
	b := roomkey.DeriveSeed("other-room", password)

	if bytes.Equal(a, b) {
		t.Fatal("different room names produced the same seed; the name is not salting")
	}
}

func TestDifferentPasswordYieldsDifferentSeed(t *testing.T) {
	a := roomkey.DeriveSeed("team-room", "correct-horse-battery")
	b := roomkey.DeriveSeed("team-room", "correct-horse-batterz")

	if bytes.Equal(a, b) {
		t.Fatal("different passwords produced the same seed")
	}
}

// Determinism has to survive all the way to the address, not just the seed —
// that string is what one peer publishes and the other dials.
func TestOnionAddressIsDeterministicAndWellFormed(t *testing.T) {
	_, addrA, err := roomkey.ForRoom("team-room", "correct-horse-battery")
	if err != nil {
		t.Fatalf("ForRoom: %v", err)
	}
	_, addrB, err := roomkey.ForRoom("team-room", "correct-horse-battery")
	if err != nil {
		t.Fatalf("ForRoom: %v", err)
	}

	if addrA != addrB {
		t.Fatalf("onion address is not deterministic: %q != %q", addrA, addrB)
	}
	// v3 service ids are 56 base32 chars (32-byte key + 2-byte checksum + version).
	if len(addrA) != 56 {
		t.Fatalf("v3 onion id should be 56 chars, got %d: %q", len(addrA), addrA)
	}

	_, addrC, err := roomkey.ForRoom("other-room", "correct-horse-battery")
	if err != nil {
		t.Fatalf("ForRoom: %v", err)
	}
	if addrA == addrC {
		t.Fatal("different room names resolved to the same onion address")
	}
}

// The private key we publish the service with must be the one the address was
// derived from, or the host would advertise an address nobody can reach.
func TestForRoomKeyMatchesAddress(t *testing.T) {
	priv, addr, err := roomkey.ForRoom("team-room", "correct-horse-battery")
	if err != nil {
		t.Fatalf("ForRoom: %v", err)
	}

	got := roomkey.OnionAddress(priv.Public().(ed25519.PublicKey))
	if got != addr {
		t.Fatalf("address from private key %q != address from ForRoom %q", got, addr)
	}
}

// An empty password would leave the address derivable from the room name alone.
func TestForRoomRejectsEmptyInput(t *testing.T) {
	for _, tc := range []struct{ name, password string }{
		{"", "correct-horse-battery"},
		{"team-room", ""},
		{"", ""},
	} {
		if _, _, err := roomkey.ForRoom(tc.name, tc.password); err == nil {
			t.Fatalf("ForRoom(%q, %q) should have failed", tc.name, tc.password)
		}
	}
}
