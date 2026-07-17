package network

// BLINDSPOT PROTOCOL (v2)
//
// Every packet on the wire is:
//
//	[Version:1][Type:1][Body...]
//
// Version is ProtocolVersion. A packet with a different version byte is dropped
// (peers NEVER silently downgrade). Body depends on Type:
//
//	PacketHandshakeInit  Noise IKpsk2 message 1 (initiator → responder)
//	PacketHandshakeResp  Noise IKpsk2 message 2 (responder → initiator)
//	PacketPunch          empty; opens the NAT mapping while a responder waits for msg1
//	PacketData/PacketTun/PacketControl  transport packets (see below)
//
// A transport packet body is:
//
//	[Counter:8][AEAD ciphertext]
//
// The AEAD's additional data (AAD) is the 10-byte cleartext header
// [Version][Type][Counter], so the type and counter are authenticated: flipping
// the type byte or the counter in transit fails the tag. The counter is also the
// AEAD nonce (a monotonic per-session-direction 64-bit value), which makes the
// nonce deterministic and lets the receiver reject replays with a sliding window.
//
// PacketControl carries an encrypted control message whose plaintext is a single
// inner opcode byte (CtrlPing/CtrlPong/CtrlDead). Control traffic therefore rides
// inside the same authenticated, anti-replay-protected channel as data — there is
// no cleartext keepalive or "peer dead" packet an attacker could forge.
//
// Migration note (packet-type mapping from v1):
//   - v1 HELLO from the initiator  → PacketHandshakeInit (Noise msg1)
//   - v1 HELLO echoed by responder → PacketHandshakeResp (Noise msg2)
//   - v1 cleartext PING/PONG/DEAD  → CtrlPing/CtrlPong/CtrlDead inside PacketControl
//
// The static public key is no longer carried on the wire (v1 sent it inside HELLO).
// It is distributed by the trusted rendezvous over TLS and pinned before the
// handshake, which is what neutralises the on-path attacker.
const ProtocolVersion byte = 0x02

// Outer packet types.
const (
	PacketHandshakeInit byte = 0x10 // Noise IKpsk2 msg1 (initiator → responder)
	PacketHandshakeResp byte = 0x11 // Noise IKpsk2 msg2 (responder → initiator)
	PacketPunch         byte = 0x12 // empty NAT hole-punch keepalive during handshake

	PacketData    byte = 0x04 // encrypted application data (chat)
	PacketTun     byte = 0x07 // encrypted tunnelled IP packet (VPN)
	PacketControl byte = 0x08 // encrypted control message; plaintext is an inner opcode
)

// Inner control opcodes, carried as the plaintext of a PacketControl transport
// packet (authenticated and anti-replay-protected like any other payload).
//
// CtrlRekey is sent (sealed under the keys being discarded) by a peer that is
// resetting an established session back to the handshake phase, so the other
// side drops its copy and re-handshakes immediately instead of answering the
// fresh msg1 with a stale cached msg2. Peers that don't know the opcode simply
// ignore it and heal via their own keepalive timeout, as before.
const (
	CtrlPing  byte = 0x01
	CtrlPong  byte = 0x02
	CtrlDead  byte = 0x03
	CtrlRekey byte = 0x04
)
