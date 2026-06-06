package cmd

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

type progressWriter struct {
	w     io.Writer
	bytes atomic.Int64
}

func (pw *progressWriter) Write(p []byte) (n int, err error) {
	n, err = pw.w.Write(p)
	pw.bytes.Add(int64(n))
	return
}

// progressReader wraps a reader and counts bytes read.
// Use this on the send side so the dst stays a bare *net.TCPConn,
// allowing the Go runtime to use the sendfile(2) syscall (zero-copy).
type progressReader struct {
	r     io.Reader
	bytes atomic.Int64
}

func (pr *progressReader) Read(p []byte) (n int, err error) {
	n, err = pr.r.Read(p)
	pr.bytes.Add(int64(n))
	return
}

func (pr *progressReader) bytesRead() int64 { return pr.bytes.Load() }

type byteCounter interface {
	bytesRead() int64
}

func (pw *progressWriter) bytesRead() int64 { return pw.bytes.Load() }

// startProgress starts a goroutine that prints a live speed/ETA line.
// Call the returned stop func when the transfer is done.
func startProgress(total int64, pw byteCounter) func() {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		var lastBytes int64
		lastTick := time.Now()
		for {
			select {
			case <-done:
				return
			case t := <-ticker.C:
				current := pw.bytesRead()
				delta := current - lastBytes
				elapsed := t.Sub(lastTick)
				lastBytes = current
				lastTick = t

				speed := float64(delta) / elapsed.Seconds()
				pct := float64(current) / float64(total) * 100
				var eta string
				if speed > 0 {
					secs := float64(total-current) / speed
					eta = fmt.Sprintf("ETA %s", time.Duration(secs*float64(time.Second)).Round(time.Second))
				} else {
					eta = "ETA --"
				}
				fmt.Printf("\r  %.1f%%  %s  %s      ",
					pct, formatBytes(speed)+"/s", eta)
			}
		}
	}()
	return func() { close(done) }
}

func formatBytes(b float64) string {
	switch {
	case b >= 1024*1024:
		return fmt.Sprintf("%.2f MB", b/1024/1024)
	case b >= 1024:
		return fmt.Sprintf("%.2f KB", b/1024)
	default:
		return fmt.Sprintf("%.0f B", b)
	}
}
