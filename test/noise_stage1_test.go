package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/neozmmv/blindspot/internal/crypto"
	"github.com/neozmmv/blindspot/internal/session"
)

// keyPairGreaterThan returns a fresh keypair whose public key sorts strictly
// after ref. Role assignment is deterministic (smaller static key initiates), so
// this lets a test force a specific peer to be the Noise initiator.
func keyPairGreaterThan(t *testing.T, ref []byte) *crypto.KeyPair {
	t.Helper()
	for i := 0; i < 10000; i++ {
		kp := mustKeyPair(t)
		if bytes.Compare(ref, kp.PublicKey) < 0 {
			return kp
		}
	}
	t.Fatal("could not generate a greater keypair")
	return nil
}

// TestOnPathAttackerCannotImpersonatePeer proves the on-path attacker is defeated.
//
// The rendezvous is honest: it published the TARGET's real static key. The victim
// pins that key and initiates a Noise IK handshake to an endpoint the attacker
// controls. The attacker knows the correct session password (worst case) but does
// NOT hold the target's private key, so it cannot decrypt msg1 nor produce a msg2
// the victim will accept. The victim's handshake must never complete.
func TestOnPathAttackerCannotImpersonatePeer(t *testing.T) {
	const sessionID, password = "onpath-session", "correct horse battery staple"

	victim := newTestPeer(t, sessionID, password)
	defer victim.conn.Close()
	defer victim.pc.Shutdown()

	// The target's real key — this is what the honest rendezvous publishes and the
	// victim pins. It must sort after the victim's key so the victim initiates.
	targetKey := keyPairGreaterThan(t, victim.kp.PublicKey)

	// The attacker sits at some endpoint with its OWN keypair (not the target's) but
	// with the correct password/PSK, and tries to answer the victim's handshake.
	attacker := newTestPeerWithKey(t, sessionID, password, mustKeyPair(t))
	defer attacker.conn.Close()
	defer attacker.pc.Shutdown()

	victim.startReadLoop()
	attacker.startReadLoop()

	// The attacker would accept the victim's static if it could — give it every
	// advantage so the ONLY thing that can save the victim is the missing private key.
	attacker.pc.AddKnownPeer(mustResolve(t, victim.addr), victim.kp.PublicKey)

	// The victim pins the target's real key but is actually talking to the attacker's
	// address: this is exactly what an on-path attacker forces.
	victim.pc.AddKnownPeer(mustResolve(t, attacker.addr), targetKey.PublicKey)

	victim.notConnected(t, 3*time.Second)
}

// TestForgedPubkeyBarredByPSK proves the password second factor holds even when
// the rendezvous is COMPROMISED.
//
// The compromised rendezvous publishes the ATTACKER's own static key to the victim
// (so the attacker can decrypt msg1). But the attacker does not know the session
// password, so its Argon2id-derived PSK is wrong. In IKpsk2 the PSK is mixed into
// the final key, so the victim's verification of msg2 fails and its handshake never
// completes — even though the pinned key genuinely belongs to the attacker.
func TestForgedPubkeyBarredByPSK(t *testing.T) {
	const sessionID = "forged-session"
	const victimPassword = "the-real-password"
	const attackerPassword = "attacker-guess" // wrong password → wrong PSK

	victim := newTestPeer(t, sessionID, victimPassword)
	defer victim.conn.Close()
	defer victim.pc.Shutdown()

	// The attacker's key must sort after the victim's so the victim initiates.
	attackerKey := keyPairGreaterThan(t, victim.kp.PublicKey)
	attacker := newTestPeerWithKey(t, sessionID, attackerPassword, attackerKey)
	defer attacker.conn.Close()
	defer attacker.pc.Shutdown()

	victim.startReadLoop()
	attacker.startReadLoop()

	// Attacker accepts the victim's static (so only the PSK can stop the handshake).
	attacker.pc.AddKnownPeer(mustResolve(t, victim.addr), victim.kp.PublicKey)

	// The compromised rendezvous made the victim pin the attacker's real key.
	victim.pc.AddKnownPeer(mustResolve(t, attacker.addr), attackerKey.PublicKey)

	// Attacker holds the matching private key, so it can decrypt msg1 and will
	// happily "complete" on its side — but with the wrong PSK. The victim must reject.
	victim.notConnected(t, 3*time.Second)
}

// TestStreamPeersDeliversPubKey proves the rendezvous round-trip: a peer's static
// pubkey published at registration is delivered to other peers over the SSE stream.
func TestStreamPeersDeliversPubKey(t *testing.T) {
	const sessionID, password = "stream-pubkey-session", "streampass1"

	rv := newMockRendezvous()
	srv := httptest.NewServer(rv)
	defer srv.Close()

	peerA := newTestPeer(t, sessionID, password)
	defer peerA.conn.Close()

	// A registers (and creates the session) so it is already present in the session.
	if _, err := session.Register(srv.URL, sessionID, password, peerA.addr, peerA.pubB64, true); err != nil {
		t.Fatalf("peer A register: %v", err)
	}

	// B opens the stream and must receive A's address together with A's pubkey.
	quit := make(chan struct{})
	defer close(quit)
	stream := session.StreamPeers(srv.URL, sessionID, password, "127.0.0.1:1", quit)

	select {
	case p := <-stream:
		if p.Public != peerA.addr {
			t.Fatalf("stream gave addr %q, want %q", p.Public, peerA.addr)
		}
		if p.PubKey != peerA.pubB64 {
			t.Fatalf("stream gave pubkey %q, want %q", p.PubKey, peerA.pubB64)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("did not receive peer A over the stream")
	}
}

func TestStreamPeersFallsBackToLegacyPasswordQuery(t *testing.T) {
	const sessionID, password = "legacy-stream-session", "streampass1"

	peerA := newTestPeer(t, sessionID, password)
	defer peerA.conn.Close()

	type seenRequest struct {
		rawQuery string
		auth     string
	}
	seen := make(chan seenRequest, 2)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/join_session/"+sessionID+"/stream" {
			http.NotFound(w, r)
			return
		}
		seen <- seenRequest{rawQuery: r.URL.RawQuery, auth: r.Header.Get("Authorization")}
		if r.URL.Query().Get("password") != password {
			http.Error(w, "missing password query", http.StatusUnauthorized)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		data, _ := json.Marshal(rvPeer{IP: peerA.addr, PubKey: peerA.pubB64})
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	}))
	defer srv.Close()

	quit := make(chan struct{})
	defer close(quit)
	stream := session.StreamPeers(srv.URL, sessionID, password, "127.0.0.1:1", quit)

	select {
	case p := <-stream:
		if p.Public != peerA.addr || p.PubKey != peerA.pubB64 {
			t.Fatalf("stream gave peer %+v, want addr %q pubkey %q", p, peerA.addr, peerA.pubB64)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("did not receive peer from legacy password stream")
	}

	first := <-seen
	if first.auth != "Bearer "+password {
		t.Fatalf("first stream request auth = %q, want bearer password", first.auth)
	}
	if got := first.rawQuery; got != "udp_addr=127.0.0.1%3A1" {
		t.Fatalf("first stream query = %q, want only udp_addr", got)
	}
	second := <-seen
	if got := second.rawQuery; got != "password=streampass1&udp_addr=127.0.0.1%3A1" {
		t.Fatalf("fallback stream query = %q, want legacy password query", got)
	}
}
