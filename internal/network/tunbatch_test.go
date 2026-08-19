package network

import (
	"bytes"
	"testing"
	"time"
)

// TestReadTunBatchHeadroom pins the contract the TUN write path depends on: the
// plaintext lands at bufs[i][headroom:], with the headroom bytes in front of it
// left free for the device's own header. A Linux TUN rejects a whole write
// batch that has no room for its virtio header, which turns into a tunnel that
// sends fine and delivers nothing.
func TestReadTunBatchHeadroom(t *testing.T) {
	sa, sb := benchPair(t)

	const headroom = 16
	packet := make([]byte, 120)
	packet[0] = 0x45 // IPv4, no options
	for i := range packet[20:] {
		packet[20+i] = byte(i)
	}

	if err := sa.pc.SendTunBatch(sb.addr, [][]byte{packet}); err != nil {
		t.Fatalf("SendTunBatch: %v", err)
	}

	bufs := make([][]byte, sb.pc.BatchSize())
	for i := range bufs {
		b := make([]byte, headroom+1600)
		for j := range b {
			b[j] = 0xAA // so a plaintext written at the wrong offset is visible
		}
		bufs[i] = b
	}
	senders := make([]string, len(bufs))

	done := make(chan int, 1)
	go func() {
		n, err := sb.pc.ReadTunBatch(bufs, senders, headroom)
		if err != nil {
			done <- -1
			return
		}
		done <- n
	}()

	var n int
	select {
	case n = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ReadTunBatch did not return")
	}
	if n != 1 {
		t.Fatalf("ReadTunBatch returned %d packets, want 1", n)
	}

	got := bufs[0]
	if len(got) != headroom+len(packet) {
		t.Fatalf("buffer length = %d, want headroom+packet = %d", len(got), headroom+len(packet))
	}
	if !bytes.Equal(got[headroom:], packet) {
		t.Fatalf("packet at [headroom:] does not match what was sent")
	}
	if got[0] == 0x45 {
		t.Fatal("plaintext was written at offset 0, leaving no headroom for the device header")
	}
}
