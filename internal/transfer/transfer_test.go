package transfer

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// collect drains prog into a counter until it is closed, signalling done when finished.
// It models a caller's render goroutine under the "caller owns and closes prog" contract.
func collect(prog <-chan Progress, count *int, done chan<- struct{}) {
	for range prog {
		*count++
	}
	close(done)
}

func TestRoundTrip(t *testing.T) {
	const ip = "127.0.0.1"
	content := bytes.Repeat([]byte("blindspot-"), 5000) // 50 KB
	src := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(src, content, 0644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	destDir := t.TempDir()

	recv, err := Listen(context.Background(), ip)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer recv.Close()

	type recvOutcome struct {
		res      *Result
		err      error
		progSeen int
	}
	recvCh := make(chan recvOutcome, 1)
	go func() {
		prog := make(chan Progress, 64)
		seen := 0
		pdone := make(chan struct{})
		go collect(prog, &seen, pdone)
		res, err := recv.Accept(context.Background(), destDir, prog)
		close(prog)
		<-pdone
		recvCh <- recvOutcome{res, err, seen}
	}()

	// Send from the "main" goroutine.
	sendProg := make(chan Progress, 64)
	sendSeen := 0
	sdone := make(chan struct{})
	go collect(sendProg, &sendSeen, sdone)
	sendRes, sendErr := Send(context.Background(), ip, src, sendProg)
	close(sendProg)
	<-sdone
	if sendErr != nil {
		t.Fatalf("Send: %v", sendErr)
	}

	out := <-recvCh
	if out.err != nil {
		t.Fatalf("Accept: %v", out.err)
	}

	// Bytes match on both sides.
	if sendRes.Bytes != int64(len(content)) {
		t.Errorf("send bytes = %d, want %d", sendRes.Bytes, len(content))
	}
	if out.res.Bytes != int64(len(content)) {
		t.Errorf("recv bytes = %d, want %d", out.res.Bytes, len(content))
	}

	// The saved file matches the source, at the expected path.
	wantPath := filepath.Join(destDir, "payload.bin")
	if out.res.Path != wantPath {
		t.Errorf("dest path = %q, want %q", out.res.Path, wantPath)
	}
	got, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("received content differs from source (got %d bytes)", len(got))
	}

	// At least the header snapshot must reach each side.
	if sendSeen < 1 {
		t.Errorf("no send progress observed")
	}
	if out.progSeen < 1 {
		t.Errorf("no receive progress observed")
	}
}

// TestListenRebind proves the one-shot receive lifecycle the tray relies on: after a
// receiver accepts a file and is closed, the port is free and a fresh Listen on the same
// address binds cleanly (no "address already in use").
func TestListenRebind(t *testing.T) {
	const ip = "127.0.0.1"
	src := filepath.Join(t.TempDir(), "f.bin")
	if err := os.WriteFile(src, []byte("round two payload"), 0644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	for i := range 2 {
		recv, err := Listen(context.Background(), ip)
		if err != nil {
			t.Fatalf("Listen (iteration %d): %v", i, err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := recv.Accept(context.Background(), t.TempDir(), nil)
			done <- err
		}()
		if _, err := Send(context.Background(), ip, src, nil); err != nil {
			t.Fatalf("Send (iteration %d): %v", i, err)
		}
		if err := <-done; err != nil {
			t.Fatalf("Accept (iteration %d): %v", i, err)
		}
		recv.Close()
	}
}

func TestAcceptCancel(t *testing.T) {
	const ip = "127.0.0.1"
	recv, err := Listen(context.Background(), ip)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer recv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := recv.Accept(ctx, t.TempDir(), nil)
		errCh <- err
	}()

	// No peer ever connects; cancel should unblock Accept.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Accept error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not return after cancellation")
	}
}

func TestSendPeerUnreachable(t *testing.T) {
	src := filepath.Join(t.TempDir(), "f.bin")
	if err := os.WriteFile(src, []byte("hi"), 0644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	// 127.0.0.1 with nothing listening on Port -> dial fails.
	_, err := Send(context.Background(), "127.0.0.1", src, nil)
	var te *Error
	if !errors.As(err, &te) || te.Op != OpDial {
		t.Fatalf("Send error = %v, want *Error{Op: OpDial}", err)
	}
	if te.Peer != "127.0.0.1" {
		t.Errorf("dial error peer = %q, want 127.0.0.1", te.Peer)
	}
}
