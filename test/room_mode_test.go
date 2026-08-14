package main

import (
	"testing"
	"time"

	"github.com/neozmmv/blindspot/internal/network"
)

// Chat and VPN are separate modes and their peers must never reach each other.
//
// They can meet by accident: a room's onion address, PSK and handshake inputs
// all come from the same name and password, so the two modes derive identical
// key material. Discovery turns a peer of the wrong mode away with an error,
// but it cannot catch the race where two peers of different modes publish the
// room at the same instant and one ends up registered in the other's room.
//
// This is what that peer must run into. Without the mode-specific prologue the
// handshake succeeds and the two sit there "connected", each ignoring
// everything the other sends — one emits only TUN packets, the other only DATA.
func TestChatAndVPNPeersCannotConnect(t *testing.T) {
	const room, password = "shared-room", "correct horse battery staple"

	vpn := newTestPeerWithPrologue(t, room, password, mustKeyPair(t), network.Prologue(room))
	defer vpn.conn.Close()
	defer vpn.pc.Shutdown()

	chat := newTestPeerWithPrologue(t, room, password, mustKeyPair(t), network.ChatPrologue(room))
	defer chat.conn.Close()
	defer chat.pc.Shutdown()

	vpn.startReadLoop()
	chat.startReadLoop()

	// Pin each other's static keys and start handshaking, exactly as a room
	// announcement would have them do.
	vpn.pc.AddKnownPeer(mustResolve(t, chat.addr), chat.kp.PublicKey)
	chat.pc.AddKnownPeer(mustResolve(t, vpn.addr), vpn.kp.PublicKey)

	vpn.notConnected(t, 3*time.Second)
	chat.notConnected(t, 3*time.Second)
}

// The control for the test above: two peers of the same mode, built the same
// way, must still connect. Without this, a change that broke handshakes
// outright would leave TestChatAndVPNPeersCannotConnect passing.
func TestTwoChatPeersConnect(t *testing.T) {
	const room, password = "shared-room", "correct horse battery staple"

	a := newTestPeerWithPrologue(t, room, password, mustKeyPair(t), network.ChatPrologue(room))
	defer a.conn.Close()
	defer a.pc.Shutdown()

	b := newTestPeerWithPrologue(t, room, password, mustKeyPair(t), network.ChatPrologue(room))
	defer b.conn.Close()
	defer b.pc.Shutdown()

	a.startReadLoop()
	b.startReadLoop()

	a.pc.AddKnownPeer(mustResolve(t, b.addr), b.kp.PublicKey)
	b.pc.AddKnownPeer(mustResolve(t, a.addr), a.kp.PublicKey)

	connected := a.waitConnected(t, 5*time.Second)
	b.waitConnected(t, 5*time.Second)

	msg := []byte("hello from a chat peer")
	if err := a.pc.Send(connected, msg); err != nil {
		t.Fatalf("send: %v", err)
	}
	select {
	case got := <-b.recv:
		if string(got.data) != string(msg) {
			t.Fatalf("received %q, want %q", got.data, msg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the second chat peer never received the message")
	}
}
