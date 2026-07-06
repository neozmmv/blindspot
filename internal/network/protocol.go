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
//	PacketData/PacketTun [Counter:8][Noise-AEAD ciphertext]
//	PacketPing/Pong/Dead/ACK  empty (still cleartext in v2; moved inside the
//	                          encrypted channel in a later stage)
//
// Migration note (packet-type mapping from v1):
//   - v1 HELLO from the initiator  → PacketHandshakeInit (Noise msg1)
//   - v1 HELLO echoed by responder → PacketHandshakeResp (Noise msg2)
//
// The static public key is no longer carried on the wire (v1 sent it inside HELLO).
// It is distributed by the trusted rendezvous over TLS and pinned before the
// handshake, which is what neutralises the on-path attacker.
const ProtocolVersion byte = 0x02

// Packet types. The byte values represent a packet type.
const (
	PacketHandshakeInit byte = 0x10 // Noise IKpsk2 msg1 (initiator → responder)
	PacketHandshakeResp byte = 0x11 // Noise IKpsk2 msg2 (responder → initiator)
	PacketPunch         byte = 0x12 // empty NAT hole-punch keepalive during handshake

	PacketPing byte = 0x02
	PacketPong byte = 0x03
	PacketData byte = 0x04
	PacketDead byte = 0x05
	PacketACK  byte = 0x06
	PacketTun  byte = 0x07
)
