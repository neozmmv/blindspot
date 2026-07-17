package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/neozmmv/blindspot/internal/crypto"
	"github.com/neozmmv/blindspot/internal/network"
	"github.com/neozmmv/blindspot/internal/session"
)

// rvPeer mirrors the JSON shape the real rendezvous server sends, including the
// static public key it now distributes alongside each address.
type rvPeer struct {
	IP        string `json:"ip"`
	LocalAddr string `json:"local_addr"`
	PubKey    string `json:"pub_key"`
}

type rvSession struct {
	mu      sync.Mutex
	peers   []rvPeer
	streams []chan rvPeer
}

// addPeer stores the peer and notifies all open SSE streams.
// Returns the list of peers that were already present before this registration.
func (s *rvSession) addPeer(p rvPeer) []rvPeer {
	s.mu.Lock()
	existing := make([]rvPeer, len(s.peers))
	copy(existing, s.peers)
	s.peers = append(s.peers, p)
	streams := make([]chan rvPeer, len(s.streams))
	copy(streams, s.streams)
	s.mu.Unlock()

	for _, ch := range streams {
		select {
		case ch <- p:
		default:
		}
	}
	return existing
}

// addStream registers an SSE listener and returns a cleanup function. Like the
// real server, it first replays the peers already present in the session.
func (s *rvSession) addStream() (chan rvPeer, func()) {
	ch := make(chan rvPeer, len(s.peers)+16)
	s.mu.Lock()
	for _, p := range s.peers {
		ch <- p
	}
	s.streams = append(s.streams, ch)
	s.mu.Unlock()
	return ch, func() {
		s.mu.Lock()
		for i, c := range s.streams {
			if c == ch {
				s.streams = append(s.streams[:i], s.streams[i+1:]...)
				break
			}
		}
		s.mu.Unlock()
		close(ch)
	}
}

// mockRendezvous implements a minimal rendezvous server for testing.
// It handles both the password-less (/session/) and password (/join_session/) variants
// and carries the pub_key field through registration, POST responses, and SSE.
type mockRendezvous struct {
	mu       sync.Mutex
	sessions map[string]*rvSession
}

func newMockRendezvous() *mockRendezvous {
	return &mockRendezvous{sessions: make(map[string]*rvSession)}
}

func (m *mockRendezvous) getOrCreate(id string) *rvSession {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		s = &rvSession{}
		m.sessions[id] = s
	}
	return s
}

func (m *mockRendezvous) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// POST /create_session — just ensure the session slot exists
	if r.Method == "POST" && path == "/create_session" {
		var body struct {
			ID string `json:"id"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		m.getOrCreate(body.ID)
		json.NewEncoder(w).Encode(map[string]string{})
		return
	}

	// Parse /session/{id}[/suffix] and /join_session/{id}[/suffix]
	var sessionID, suffix string
	for _, prefix := range []string{"/join_session/", "/session/"} {
		if rest, ok := strings.CutPrefix(path, prefix); ok {
			parts := strings.SplitN(rest, "/", 2)
			sessionID = parts[0]
			if len(parts) > 1 {
				suffix = parts[1]
			}
			break
		}
	}

	switch suffix {
	case "stream":
		m.handleStream(w, r, sessionID)
	case "leave":
		w.WriteHeader(http.StatusOK)
	default:
		if r.Method != "POST" {
			http.NotFound(w, r)
			return
		}
		var body struct {
			UDPAddr   string `json:"udp_addr"`
			LocalAddr string `json:"local_addr"`
			PubKey    string `json:"pub_key"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		s := m.getOrCreate(sessionID)
		existing := s.addPeer(rvPeer{IP: body.UDPAddr, LocalAddr: body.LocalAddr, PubKey: body.PubKey})
		json.NewEncoder(w).Encode(map[string]any{"peers": existing})
	}
}

func (m *mockRendezvous) handleStream(w http.ResponseWriter, r *http.Request, sessionID string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	s := m.getOrCreate(sessionID)
	ch, remove := s.addStream()
	defer remove()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case p, ok := <-ch:
			if !ok {
				return
			}
			data, _ := json.Marshal(p)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

// recvMsg is a decrypted transport message surfaced by a test peer's read loop.
type recvMsg struct {
	typ  byte
	data []byte
	addr *net.UDPAddr
}

// testPeer wraps a local UDP socket + PeerConn for use in tests.
type testPeer struct {
	conn   *net.UDPConn
	addr   string
	kp     *crypto.KeyPair
	pubB64 string
	pc     *network.PeerConn
	recv   chan recvMsg
}

// newTestPeer builds a peer whose PeerConn is configured exactly like the client:
// static keypair + Argon2id PSK (from password + sessionId) + version/session prologue.
func newTestPeer(t *testing.T, sessionID, password string) *testPeer {
	t.Helper()
	return newTestPeerWithKey(t, sessionID, password, mustKeyPair(t))
}

func newTestPeerWithKey(t *testing.T, sessionID, password string, kp *crypto.KeyPair) *testPeer {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", conn.LocalAddr().(*net.UDPAddr).Port)
	psk := crypto.DerivePSK(password, sessionID)
	pc := network.NewPeerConn(network.WrapUDPConn(conn), kp.PrivateKey, kp.PublicKey, psk, network.Prologue(sessionID))
	return &testPeer{
		conn:   conn,
		addr:   addr,
		kp:     kp,
		pubB64: base64.StdEncoding.EncodeToString(kp.PublicKey),
		pc:     pc,
		recv:   make(chan recvMsg, 16),
	}
}

func mustKeyPair(t *testing.T) *crypto.KeyPair {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return kp
}

// startReadLoop drives the PeerConn event loop. Handshake, punch, and keepalive
// packets are handled internally by PeerConn.Read; decrypted data/tun messages are
// forwarded to the recv channel.
func (tp *testPeer) startReadLoop() {
	go func() {
		for {
			typ, data, addr, err := tp.pc.Read()
			if err != nil {
				if strings.Contains(err.Error(), "use of closed network connection") {
					return
				}
				continue
			}
			select {
			case tp.recv <- recvMsg{typ: typ, data: data, addr: addr}:
			default:
			}
		}
	}()
}

func (tp *testPeer) waitConnected(t *testing.T, timeout time.Duration) *net.UDPAddr {
	t.Helper()
	select {
	case addr := <-tp.pc.Connected:
		return addr
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for peer connection after %v", timeout)
		return nil
	}
}

// notConnected asserts the peer does NOT complete a handshake within the window.
func (tp *testPeer) notConnected(t *testing.T, timeout time.Duration) {
	t.Helper()
	select {
	case addr := <-tp.pc.Connected:
		t.Fatalf("expected no connection, but handshake completed with %v", addr)
	case <-time.After(timeout):
	}
}

func mustResolve(t *testing.T, addr string) *net.UDPAddr {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("ResolveUDPAddr(%s): %v", addr, err)
	}
	return a
}

func mustDecodeKey(t *testing.T, b64 string) []byte {
	t.Helper()
	k, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode pubkey: %v", err)
	}
	return k
}

// runConnectionTest exercises the full Noise IKpsk2 flow for both -s and -s -p
// scenarios: register through the (mock) rendezvous, learn each other's pinned
// static key, complete the handshake, and round-trip an encrypted message.
func runConnectionTest(t *testing.T, sessionID, password string) {
	t.Helper()

	rv := newMockRendezvous()
	srv := httptest.NewServer(rv)
	defer srv.Close()

	peerA := newTestPeer(t, sessionID, password)
	defer peerA.conn.Close()
	defer peerA.pc.Shutdown()

	peerB := newTestPeer(t, sessionID, password)
	defer peerB.conn.Close()
	defer peerB.pc.Shutdown()

	peerA.startReadLoop()
	peerB.startReadLoop()

	// Peer A registers first (creating the session when a password is provided).
	if _, err := session.Register(srv.URL, sessionID, password, peerA.addr, peerA.pubB64, password != ""); err != nil {
		t.Fatalf("peer A register: %v", err)
	}

	// Peer B registers and receives Peer A's address AND pinned pubkey.
	peersForB, err := session.Register(srv.URL, sessionID, password, peerB.addr, peerB.pubB64, false)
	if err != nil {
		t.Fatalf("peer B register: %v", err)
	}
	if len(peersForB) != 1 {
		t.Fatalf("peer B expected 1 peer, got %d", len(peersForB))
	}
	if peersForB[0].PubKey != peerA.pubB64 {
		t.Fatalf("peer B expected peer A pubkey %s, got %s", peerA.pubB64, peersForB[0].PubKey)
	}

	// Each side registers the other's rendezvous-pinned static and starts the handshake.
	peerB.pc.AddKnownPeer(mustResolve(t, peerA.addr), mustDecodeKey(t, peerA.pubB64))
	peerA.pc.AddKnownPeer(mustResolve(t, peerB.addr), mustDecodeKey(t, peerB.pubB64))

	connectedOnA := peerA.waitConnected(t, 5*time.Second)
	connectedOnB := peerB.waitConnected(t, 5*time.Second)

	// The authenticated key each side sees must be the other's real static key.
	if gotB, ok := peerA.pc.PeerPublicKey(connectedOnA); !ok || !strings.EqualFold(base64.StdEncoding.EncodeToString(gotB), peerB.pubB64) {
		t.Fatalf("peer A did not authenticate peer B's static key")
	}

	// Encrypted round-trip A → B over the established Noise session.
	msg := []byte("hello from A")
	if err := peerA.pc.Send(connectedOnA, msg); err != nil {
		t.Fatalf("peer A send: %v", err)
	}
	select {
	case got := <-peerB.recv:
		if string(got.data) != string(msg) {
			t.Fatalf("peer B received %q, want %q", got.data, msg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("peer B did not receive the message")
	}
	_ = connectedOnB
}

// TestRekeyHealsAfterOneSidedTimeout covers the mid-transfer blackout bug: one
// side declares the peer dead (keepalive timeout) and re-arms its handshake
// while the other side still holds the established session. Without the
// CtrlRekey notice the still-established side answers every fresh msg1 with its
// stale cached msg2 and the two deadlock until the second side's own keepalive
// times out (~30s). With the notice, both sides must re-establish within a few
// seconds and pass traffic again.
func TestRekeyHealsAfterOneSidedTimeout(t *testing.T) {
	sessionID, password := "rekey-session", "pass1234!"

	peerA := newTestPeer(t, sessionID, password)
	defer peerA.conn.Close()
	defer peerA.pc.Shutdown()

	peerB := newTestPeer(t, sessionID, password)
	defer peerB.conn.Close()
	defer peerB.pc.Shutdown()

	peerA.startReadLoop()
	peerB.startReadLoop()

	peerB.pc.AddKnownPeer(mustResolve(t, peerA.addr), peerA.kp.PublicKey)
	peerA.pc.AddKnownPeer(mustResolve(t, peerB.addr), peerB.kp.PublicKey)

	addrOnA := peerA.waitConnected(t, 5*time.Second)
	peerB.waitConnected(t, 5*time.Second)

	// Simulate a keepalive timeout on A only. B still believes the session is
	// established and healthy.
	peerA.pc.TimeoutPeer(addrOnA)
	select {
	case <-peerA.pc.Dead:
	case <-time.After(3 * time.Second):
		t.Fatal("TimeoutPeer did not surface a Dead event on A")
	}

	// Both sides must re-establish far faster than B's own 30s keepalive limit.
	reconnectedOnA := peerA.waitConnected(t, 5*time.Second)
	peerB.waitConnected(t, 5*time.Second)

	// The healed session must carry traffic both ways.
	if err := peerA.pc.Send(reconnectedOnA, []byte("post-rekey A->B")); err != nil {
		t.Fatalf("send A->B after rekey: %v", err)
	}
	select {
	case got := <-peerB.recv:
		if string(got.data) != "post-rekey A->B" {
			t.Fatalf("peer B received %q after rekey", got.data)
		}
		if err := peerB.pc.Send(got.addr, []byte("post-rekey B->A")); err != nil {
			t.Fatalf("send B->A after rekey: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("peer B did not receive data after rekey")
	}
	select {
	case got := <-peerA.recv:
		if string(got.data) != "post-rekey B->A" {
			t.Fatalf("peer A received %q after rekey", got.data)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("peer A did not receive data after rekey")
	}
}

// TestConnectionNoPassword simulates `blindspot connect -s <session>` with two peers.
func TestConnectionNoPassword(t *testing.T) {
	runConnectionTest(t, "test-session", "")
}

// TestConnectionWithPassword simulates `blindspot connect -s <session> -p <password>` with two peers.
func TestConnectionWithPassword(t *testing.T) {
	runConnectionTest(t, "test-session-pw", "pass1234!")
}
