package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
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

// Nothing rate-limits guessing a room: candidate addresses are derived offline
// and only checked against the network. A trivially short password would make
// the whole room enumerable, so the minimums are enforced before derivation.
func TestForRoomRejectsShortInput(t *testing.T) {
	for _, tc := range []struct {
		desc, name, password string
		want                 error
	}{
		{"empty name", "", "correct-horse-battery", roomkey.ErrNameTooShort},
		{"empty password", "team-room", "", roomkey.ErrPasswordTooShort},
		{"both empty", "", "", roomkey.ErrNameTooShort},
		{"name one under", "abc", "correct-horse-battery", roomkey.ErrNameTooShort},
		{"password one under", "team-room", "1234567", roomkey.ErrPasswordTooShort},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			_, _, err := roomkey.ForRoom(tc.name, tc.password)
			if !errors.Is(err, tc.want) {
				t.Fatalf("ForRoom(%q, %q) = %v, want %v", tc.name, tc.password, err, tc.want)
			}
		})
	}
}

// Exactly at the limit must be accepted, or the boundary is off by one.
func TestForRoomAcceptsMinimumLengths(t *testing.T) {
	name := strings.Repeat("a", roomkey.MinNameLen)
	password := strings.Repeat("b", roomkey.MinPasswordLen)

	if _, _, err := roomkey.ForRoom(name, password); err != nil {
		t.Fatalf("ForRoom at exactly the minimum lengths should succeed, got %v", err)
	}
}

// The minimums are in characters, not bytes: a two-character name that happens
// to encode to six bytes must still be rejected.
func TestForRoomCountsCharactersNotBytes(t *testing.T) {
	shortName := "日本" // 2 characters, 6 bytes
	if len(shortName) < roomkey.MinNameLen {
		t.Fatalf("test premise broken: %q is only %d bytes", shortName, len(shortName))
	}

	if _, _, err := roomkey.ForRoom(shortName, "correct-horse-battery"); !errors.Is(err, roomkey.ErrNameTooShort) {
		t.Fatalf("a 2-character name should be rejected on character count, got %v", err)
	}

	shortPassword := "パスワード¡" // 6 characters, well over 8 bytes
	if _, _, err := roomkey.ForRoom("team-room", shortPassword); !errors.Is(err, roomkey.ErrPasswordTooShort) {
		t.Fatalf("a 6-character password should be rejected on character count, got %v", err)
	}
}
