package main

import (
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

// rvPeer mirrors the JSON shape the real rendezvous server sends.
type rvPeer struct {
	IP        string `json:"ip"`
	LocalAddr string `json:"local_addr"`
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

// addStream registers an SSE listener and returns a cleanup function.
func (s *rvSession) addStream() (chan rvPeer, func()) {
	ch := make(chan rvPeer, 16)
	s.mu.Lock()
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
// It handles both the password-less (/session/) and password (/join_session/) variants.
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
		}
		json.NewDecoder(r.Body).Decode(&body)
		s := m.getOrCreate(sessionID)
		existing := s.addPeer(rvPeer{IP: body.UDPAddr, LocalAddr: body.LocalAddr})
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

// testPeer wraps a local UDP socket + PeerConn for use in tests.
type testPeer struct {
	conn *net.UDPConn
	addr string
	pc   *network.PeerConn
}

func newTestPeer(t *testing.T) *testPeer {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", conn.LocalAddr().(*net.UDPAddr).Port)
	pc := network.NewPeerConn(conn, kp.PrivateKey, kp.PublicKey)
	return &testPeer{conn: conn, addr: addr, pc: pc}
}

// startReadLoop drives the PeerConn event loop in a background goroutine.
// Handshake (PacketHello) and keepalive (PacketPing/Pong) are handled internally
// by PeerConn.Read, so this loop is what makes peer connections actually complete.
func (tp *testPeer) startReadLoop() {
	go func() {
		for {
			_, _, _, err := tp.pc.Read()
			if err != nil && strings.Contains(err.Error(), "use of closed network connection") {
				return
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

// runConnectionTest is the shared body for both -s and -s -p scenarios.
//
// Flow:
//  1. Peer A registers (creates the session when a password is provided).
//  2. Peer B registers and receives Peer A's address in the response.
//  3. Peer B initiates a UDP hole-punch towards Peer A.
//  4. Peer A's Read loop receives the Hello, responds, and fires Connected.
//  5. Peer B's Read loop receives the echo Hello and fires Connected.
//  6. Both Connected events must arrive within 3 seconds.
func runConnectionTest(t *testing.T, sessionID, password string) {
	t.Helper()

	rv := newMockRendezvous()
	srv := httptest.NewServer(rv)
	defer srv.Close()

	peerA := newTestPeer(t)
	defer peerA.conn.Close()

	peerB := newTestPeer(t)
	defer peerB.conn.Close()

	peerA.startReadLoop()
	peerB.startReadLoop()

	// Peer A registers first. When a password is provided it also creates the session.
	_, err := session.Register(srv.URL, sessionID, password, peerA.addr, password != "")
	if err != nil {
		t.Fatalf("peer A register: %v", err)
	}

	// Peer B registers and should receive Peer A's address in the response.
	peersForB, err := session.Register(srv.URL, sessionID, password, peerB.addr, false)
	if err != nil {
		t.Fatalf("peer B register: %v", err)
	}
	if len(peersForB) != 1 {
		t.Fatalf("peer B expected 1 peer, got %d", len(peersForB))
	}
	if peersForB[0].Public != peerA.addr {
		t.Fatalf("peer B expected peer A at %s, got %s", peerA.addr, peersForB[0].Public)
	}

	t.Logf("peer A addr: %s", peerA.addr)
	t.Logf("peer B addr: %s", peerB.addr)

	// Peer B punches towards Peer A. Peer A's Read loop auto-responds with its own
	// Hello, which causes Peer B's Read loop to complete the handshake on both sides.
	peerAUDP, _ := net.ResolveUDPAddr("udp", peersForB[0].Public)
	go peerB.pc.PunchHole(peerAUDP)

	connectedOnA := peerA.waitConnected(t, 3*time.Second)
	connectedOnB := peerB.waitConnected(t, 3*time.Second)

	t.Logf("peer A sees peer at: %s", connectedOnA)
	t.Logf("peer B sees peer at: %s", connectedOnB)
}

// TestConnectionNoPassword simulates `blindspot connect -s <session>` with two peers.
func TestConnectionNoPassword(t *testing.T) {
	runConnectionTest(t, "test-session", "")
}

// TestConnectionWithPassword simulates `blindspot connect -s <session> -p <password>` with two peers.
func TestConnectionWithPassword(t *testing.T) {
	runConnectionTest(t, "test-session-pw", "pass1234!")
}
