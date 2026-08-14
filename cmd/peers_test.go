package cmd

import (
	"encoding/base64"
	"testing"

	"github.com/neozmmv/blindspot/internal/session"
)

const testSelfAddr = "203.0.113.9:51820"

func validPubKey() string {
	return base64.StdEncoding.EncodeToString(make([]byte, 32))
}

// A peer's own registration is announced back to it: the room excludes the
// caller from what it returns and streams, but every re-registration is pushed
// to all open streams, our own included. Adding ourselves starts a handshake
// against our own address that can never complete, because the initiator role is
// decided by comparing two distinct static keys.
//
// The roster is deliberately built with a nil PeerConn: reaching it at all means
// the guard let our own address through.
func TestRosterIgnoresOwnAnnouncement(t *testing.T) {
	r := newPeerRoster(nil, nil, testSelfAddr, validPubKey())

	if _, added := r.add(session.PeerAddr{
		Public: testSelfAddr,
		Local:  "192.168.0.11:51820",
		PubKey: validPubKey(),
	}); added {
		t.Fatal("a peer's own announcement must not be added as a peer")
	}
}

// A peer behind the same NAT is a different peer despite the shared public IP,
// and must be reached on its local address rather than dropped as self.
func TestRosterPrefersLocalAddrOfSameNetworkPeer(t *testing.T) {
	r := newPeerRoster(nil, nil, testSelfAddr, validPubKey())

	// PubKey is deliberately unusable so add stops before the nil PeerConn: the
	// address choice is what this asserts.
	addrStr, _ := r.add(session.PeerAddr{
		Public: "203.0.113.9:44444",
		Local:  "192.168.0.12:44444",
		PubKey: "not-base64",
	})
	if addrStr != "192.168.0.12:44444" {
		t.Fatalf("same-network peer should be reached locally, got %q", addrStr)
	}
}
