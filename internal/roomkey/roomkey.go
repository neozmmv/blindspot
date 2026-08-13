// Package roomkey derives a Tor v3 onion service identity from a room name and
// password, so peers that share those two strings can compute the same .onion
// address independently — with no DNS, no fixed server, and nothing published
// anywhere in advance.
//
// The onion address IS the shared secret. Reaching the service at all requires
// having derived it, which requires knowing name+password. That is why the
// onion-hosted room API drops the application-layer password check that the
// clearnet rendezvous server needs (see internal/roomserver).
package roomkey

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"unicode/utf8"

	"github.com/cretz/bine/torutil"
	bineed25519 "github.com/cretz/bine/torutil/ed25519"
	"golang.org/x/crypto/argon2"
)

// Argon2id parameters for deriving the onion identity seed from the room
// password.
//
// These deliberately do NOT match internal/crypto.DerivePSK's 64 MiB. That one
// guards a key exchanged through the rendezvous server, which rate-limits
// guessing and sits on the interactive path. This one guards a value an
// attacker can attack entirely offline: derive a candidate seed, compute the
// .onion, ask Tor whether a descriptor exists. Nothing throttles that, so the
// only lever is making each guess expensive.
//
// The asymmetry is what makes this worth doing. Derivation happens once per
// `blindspot connect`, inside a command whose Tor bootstrap and descriptor
// publish were measured at 36-200s — so a sub-second derivation is invisible to
// the user, while every point of memory cost is paid again by an attacker on
// every one of billions of guesses.
//
// Memory is the knob that matters: Argon2id's resistance to GPU and ASIC attack
// scales with it, where iteration count only costs time. 512 MiB is 8x the
// OWASP floor. Measured at 199ms and a 512 MiB peak allocation
// (BenchmarkDeriveSeed) — check that figure again before targeting genuinely
// small devices, since it must fit in RAM all at once.
//
// THESE VALUES ARE PART OF THE PROTOCOL. They feed the address every peer
// computes, so changing any of them moves every room to a new .onion. Two peers
// running different values do not fail to agree — they silently derive
// different addresses, never see each other, and each ends up hosting its own
// empty room. Any future change has to be a coordinated, versioned break.
const (
	seedArgonTime    = 1
	seedArgonMemory  = 512 * 1024 // KiB → 512 MiB
	seedArgonThreads = 4
	seedLen          = 32
)

// Minimum lengths for the two halves of a room identity, counted in characters
// rather than bytes so a short non-ASCII name cannot slip past on byte count.
//
// These are a floor against typos and trivially guessable rooms, not a
// substitute for a strong password. Nothing rate-limits guessing here: an
// attacker derives candidate addresses entirely offline and only touches the
// network to check whether a descriptor exists, so the room's security rests
// on password entropy alone. A passphrase is worth far more than the minimum.
const (
	MinNameLen     = 4
	MinPasswordLen = 8
)

// ErrNameTooShort and ErrPasswordTooShort report which half failed, so the CLI
// can tell the user what to fix.
var (
	ErrNameTooShort     = fmt.Errorf("room name must be at least %d characters", MinNameLen)
	ErrPasswordTooShort = fmt.Errorf("room password must be at least %d characters", MinPasswordLen)
)

// DeriveSeed derives a deterministic 32-byte Ed25519 seed from a room name and
// password. The name is hashed to a fixed-length salt so that the same password
// under a different room name yields an unrelated key.
func DeriveSeed(name, password string) []byte {
	salt := sha256.Sum256([]byte(name))
	return argon2.IDKey([]byte(password), salt[:], seedArgonTime, seedArgonMemory, seedArgonThreads, seedLen)
}

// KeyPair returns the Ed25519 keypair for the onion service.
func KeyPair(seed []byte) (ed25519.PrivateKey, ed25519.PublicKey) {
	priv := ed25519.NewKeyFromSeed(seed)
	return priv, priv.Public().(ed25519.PublicKey)
}

// OnionAddress returns the v3 service id (the .onion label, without the
// ".onion" suffix) for a public key.
//
// bine's torutil takes its own []byte-based ed25519.PublicKey rather than the
// standard library's, so the conversion here is required — it is not a drop-in.
func OnionAddress(pub ed25519.PublicKey) string {
	return torutil.OnionServiceIDFromV3PublicKey(bineed25519.PublicKey(pub))
}

// Validate checks the room identity without deriving anything. Callers that
// only need to reject bad input should use this rather than ForRoom: derivation
// costs a 512 MiB allocation, so it is not something to do twice for the sake
// of an early error message.
func Validate(name, password string) error {
	if utf8.RuneCountInString(name) < MinNameLen {
		return ErrNameTooShort
	}
	if utf8.RuneCountInString(password) < MinPasswordLen {
		return ErrPasswordTooShort
	}
	return nil
}

// ForRoom is the one call the CLI needs: it validates the inputs and returns the
// onion identity to either publish (as host) or dial (as client).
func ForRoom(name, password string) (ed25519.PrivateKey, string, error) {
	if err := Validate(name, password); err != nil {
		return nil, "", err
	}
	priv, pub := KeyPair(DeriveSeed(name, password))
	return priv, OnionAddress(pub), nil
}
