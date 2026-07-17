package transfer

import (
	"context"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkLoopbackTransfer measures the whole transfer path (header framing,
// 1 MB copy buffer, progress writer) over loopback TCP — the tunnel-free
// baseline the tunnelled number is compared against. Reported MB/s is file
// payload throughput.
func BenchmarkLoopbackTransfer(b *testing.B) {
	const size = 64 << 20 // 64 MB per op

	srcDir := b.TempDir()
	destDir := b.TempDir()
	src := filepath.Join(srcDir, "payload.bin")
	buf := make([]byte, size)
	rand.New(rand.NewSource(1)).Read(buf)
	if err := os.WriteFile(src, buf, 0644); err != nil {
		b.Fatalf("writing payload: %v", err)
	}

	ctx := context.Background()
	b.SetBytes(size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recv, err := Listen(ctx, "127.0.0.1")
		if err != nil {
			b.Fatalf("Listen: %v", err)
		}
		errCh := make(chan error, 1)
		go func() {
			_, err := recv.Accept(ctx, destDir, nil)
			errCh <- err
		}()
		if _, err := Send(ctx, "127.0.0.1", src, nil); err != nil {
			recv.Close()
			b.Fatalf("Send: %v", err)
		}
		if err := <-errCh; err != nil {
			b.Fatalf("Accept: %v", err)
		}
		recv.Close()
	}
}
