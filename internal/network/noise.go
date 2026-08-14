package network

import "github.com/flynn/noise"

// noiseSuite is the same cipher suite WireGuard uses: X25519 for DH, AES-256-GCM
// for the AEAD, and SHA-256 for hashing/HKDF.
var noiseSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)

// pskPlacementPSK2 places the pre-shared key at the end of the second handshake
// message (the "psk2" modifier of the IK pattern). By then the IK handshake has
// already authenticated the responder via its static key, so the PSK acts purely
// as a second factor gating the final key derivation.
const pskPlacementPSK2 = 2

// Prologue binds the handshake to the protocol version and session id. Both peers
// must derive an identical prologue or the handshake fails, which prevents a
// handshake from one session/version being replayed into another.
func Prologue(sessionId string) []byte {
	return append([]byte("blindspot/v2|"), []byte(sessionId)...)
}

// ChatPrologue is Prologue for chat peers.
//
// Chat and VPN peers must never establish a session with each other. They can
// meet: a room's onion address, PSK and prologue all come from the same name
// and password, so without this they would handshake successfully and then
// ignore everything the other sent — one only ever emits TUN packets, the other
// only DATA. To both users that looks like a working connection that silently
// carries nothing.
//
// Discovery already turns a peer of the wrong mode away at the door, with an
// error naming the command to use instead. This is the backstop for the case
// discovery cannot catch: two peers of different modes publishing the room at
// the same instant, one of which ends up registered in the other's room. A
// distinct prologue makes that handshake fail outright.
//
// VPN keeps the bare prologue so peers on the public rendezvous server stay
// compatible across releases.
func ChatPrologue(sessionId string) []byte {
	return append([]byte("blindspot/v2|chat|"), []byte(sessionId)...)
}

// newInitiatorHandshake builds the initiator side of a Noise IKpsk2 handshake.
// remoteStatic is the responder's static public key, pinned from the trusted
// rendezvous — this is what makes the on-path attacker unable to impersonate the
// responder.
func newInitiatorHandshake(static noise.DHKey, remoteStatic, psk, prologue []byte) (*noise.HandshakeState, error) {
	return noise.NewHandshakeState(noise.Config{
		CipherSuite:           noiseSuite,
		Pattern:               noise.HandshakeIK,
		Initiator:             true,
		Prologue:              prologue,
		StaticKeypair:         static,
		PeerStatic:            remoteStatic,
		PresharedKey:          psk,
		PresharedKeyPlacement: pskPlacementPSK2,
	})
}

// newResponderHandshake builds the responder side of a Noise IKpsk2 handshake.
// The responder learns the initiator's static key from msg1 and validates it
// against the set of keys the rendezvous published for the session.
func newResponderHandshake(static noise.DHKey, psk, prologue []byte) (*noise.HandshakeState, error) {
	return noise.NewHandshakeState(noise.Config{
		CipherSuite:           noiseSuite,
		Pattern:               noise.HandshakeIK,
		Initiator:             false,
		Prologue:              prologue,
		StaticKeypair:         static,
		PresharedKey:          psk,
		PresharedKeyPlacement: pskPlacementPSK2,
	})
}
