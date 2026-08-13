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
// password. These match internal/crypto.DerivePSK and follow OWASP's Argon2id
// guidance (64 MiB, 1 iteration, 4 lanes).
//
// Tuning tradeoff: raising seedArgonMemory increases the cost of brute-forcing a
// weak room password into a reachable onion address, but is paid on every
// `blindspot connect`. Measured at ~0.1s for these values, which is negligible
// next to the ~23s Tor bootstrap and onion publish that follow it.
const (
	seedArgonTime    = 1
	seedArgonMemory  = 64 * 1024 // KiB → 64 MiB
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

// ForRoom is the one call the CLI needs: it validates the inputs and returns the
// onion identity to either publish (as host) or dial (as client).
func ForRoom(name, password string) (ed25519.PrivateKey, string, error) {
	if utf8.RuneCountInString(name) < MinNameLen {
		return nil, "", ErrNameTooShort
	}
	if utf8.RuneCountInString(password) < MinPasswordLen {
		return nil, "", ErrPasswordTooShort
	}
	priv, pub := KeyPair(DeriveSeed(name, password))
	return priv, OnionAddress(pub), nil
}
