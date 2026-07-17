// Package transfer is the headless core of Blindspot's file-transfer path on the
// :28125 port. It owns the wire protocol and the send/receive logic, exposing them as
// plain in-process calls: no flag parsing, no printing, no os.Exit. Cancellation flows
// through context.Context and progress through a channel of Progress snapshots, so both
// the CLI and the tray can drive it as peers.
//
// Wire protocol (unchanged, big-endian): uint16 name length, name bytes, uint64 file
// size, then the raw file body.
package transfer

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// Port is the TCP port used for file transfers.
const Port = 28125

// dialTimeout matches the historical CLI dial timeout.
const dialTimeout = 5 * time.Second

// sampleInterval is how often live progress snapshots are emitted during a transfer.
const sampleInterval = 500 * time.Millisecond

// copyBufSize is the userspace copy buffer for the file body. io.Copy's default
// 32 KB means one write syscall per 32 KB; 1 MB cuts the syscall count ~32x on a
// bulk transfer for a fixed, one-off allocation.
//
// Note: we deliberately do NOT call SetReadBuffer/SetWriteBuffer on the TCP
// connection. A fixed SO_RCVBUF/SO_SNDBUF disables the OS's TCP window
// autotuning, which on both Linux (tcp_rmem, up to ~6 MB) and Windows (receive
// autotuning, up to 16 MB) already grows past anything we could safely pin —
// and on Linux the fixed value would additionally be clamped to rmem_max
// (~416 KB), a hard regression on high-BDP paths.
const copyBufSize = 1 << 20

// bodyReader hides any WriteTo/ReadFrom fast paths of the underlying reader so
// io.CopyBuffer actually uses our large buffer instead of falling back to the
// generic 32 KB path inside os.File.WriteTo.
type bodyReader struct{ r io.Reader }

func (br bodyReader) Read(p []byte) (int, error) { return br.r.Read(p) }

// progressWriter is an io.Writer that counts the bytes passing through it, so a
// background sampler can report progress without disturbing the copy.
type progressWriter struct {
	w     io.Writer
	bytes atomic.Int64
}

func (pw *progressWriter) Write(p []byte) (n int, err error) {
	n, err = pw.w.Write(p)
	pw.bytes.Add(int64(n))
	return
}

// startSampler emits a Progress snapshot every sampleInterval, carrying the current
// byte count over the given base (Name/Total/PeerAddr). It runs in its own goroutine
// and blocking sends never gate the copy. The returned stop func closes the sampler
// and waits for it to finish, so the caller may safely close prog afterwards. If prog
// is nil the sampler is a no-op.
func startSampler(prog chan<- Progress, pw *progressWriter, base Progress) func() {
	if prog == nil {
		return func() {}
	}
	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		ticker := time.NewTicker(sampleInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				p := base
				p.Transferred = pw.bytes.Load()
				select {
				case prog <- p:
				case <-stopCh:
					return
				}
			}
		}
	}()
	return func() {
		close(stopCh)
		<-doneCh
	}
}

// closeOnCancel closes c when ctx is done, unblocking a pending Accept/Read/Copy. The
// returned stop func ends the watch (call it before c is otherwise closed).
func closeOnCancel(ctx context.Context, c io.Closer) func() {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			c.Close()
		case <-done:
		}
	}()
	return func() { close(done) }
}

// Send dials peer:Port, writes the header, and streams the file at path. peer is the IP
// only; the package appends Port. Progress snapshots are pushed on prog (which may be
// nil to skip progress); the caller owns and closes prog after Send returns. On failure
// Send returns a *transfer.Error, or a context error if ctx was cancelled.
func Send(ctx context.Context, peer, path string, prog chan<- Progress) (*Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, &Error{Op: OpOpenFile, Err: err}
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, &Error{Op: OpStat, Err: err}
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", peer, Port), dialTimeout)
	if err != nil {
		return nil, &Error{Op: OpDial, Err: err, Peer: peer}
	}
	defer conn.Close()

	stopWatch := closeOnCancel(ctx, conn)
	defer stopWatch()

	name := []byte(filepath.Base(path))
	if err := binary.Write(conn, binary.BigEndian, uint16(len(name))); err != nil {
		return nil, &Error{Op: OpSendNameLen, Err: err}
	}
	if _, err := conn.Write(name); err != nil {
		return nil, &Error{Op: OpSendName, Err: err}
	}
	if err := binary.Write(conn, binary.BigEndian, uint64(info.Size())); err != nil {
		return nil, &Error{Op: OpSendSize, Err: err}
	}

	base := Progress{Name: filepath.Base(path), Total: info.Size()}
	if prog != nil {
		prog <- base // header snapshot (Transferred == 0), before any body bytes
	}

	pw := &progressWriter{w: conn}
	stopSampler := startSampler(prog, pw, base)
	start := time.Now()
	n, err := io.CopyBuffer(pw, bodyReader{f}, make([]byte, copyBufSize))
	stopSampler()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &Error{Op: OpSendBody, Err: err}
	}

	return &Result{
		Name:    base.Name,
		Path:    path,
		Bytes:   n,
		Elapsed: time.Since(start),
	}, nil
}

// Receiver is a bound, one-shot transfer listener. Listen returning without error means
// the port is already bound; call Accept to receive a single file, then Close.
type Receiver struct {
	ln   net.Listener
	addr string
}

// Listen binds ip:Port. A nil error guarantees the port is bound and the returned
// Receiver holds the ready listener. ip is the caller-derived virtual IP.
func Listen(ctx context.Context, ip string) (*Receiver, error) {
	addr := fmt.Sprintf("%s:%d", ip, Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, &Error{Op: OpListen, Err: err, Addr: addr}
	}
	return &Receiver{ln: ln, addr: addr}, nil
}

// Addr returns the bound address, e.g. "10.x.y.z:28125".
func (r *Receiver) Addr() string { return r.addr }

// Close closes the underlying listener.
func (r *Receiver) Close() error { return r.ln.Close() }

// Accept blocks for one connection, reads the header, and saves the file into destDir,
// streaming the body. It is one-shot. Progress snapshots are pushed on prog (which may
// be nil); the caller owns and closes prog after Accept returns. On failure it returns
// a *transfer.Error, or a context error if ctx was cancelled.
func (r *Receiver) Accept(ctx context.Context, destDir string, prog chan<- Progress) (*Result, error) {
	stopLnWatch := closeOnCancel(ctx, r.ln)
	conn, err := r.ln.Accept()
	stopLnWatch()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &Error{Op: OpAccept, Err: err}
	}
	defer conn.Close()

	stopConnWatch := closeOnCancel(ctx, conn)
	defer stopConnWatch()

	var nameLen uint16
	if err := binary.Read(conn, binary.BigEndian, &nameLen); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &Error{Op: OpReadNameLen, Err: err}
	}
	nameBuf := make([]byte, nameLen)
	if _, err := io.ReadFull(conn, nameBuf); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &Error{Op: OpReadName, Err: err}
	}

	var fileSize uint64
	if err := binary.Read(conn, binary.BigEndian, &fileSize); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &Error{Op: OpReadSize, Err: err}
	}

	filename := string(nameBuf)
	destPath := filepath.Join(destDir, filename)

	base := Progress{Name: filename, PeerAddr: conn.RemoteAddr().String(), Total: int64(fileSize)}
	if prog != nil {
		prog <- base // header snapshot (Transferred == 0), before any body bytes
	}

	f, err := os.Create(destPath)
	if err != nil {
		return nil, &Error{Op: OpCreateFile, Err: err}
	}
	defer f.Close()

	pw := &progressWriter{w: f}
	stopSampler := startSampler(prog, pw, base)
	start := time.Now()
	n, err := io.CopyBuffer(pw, bodyReader{io.LimitReader(conn, int64(fileSize))}, make([]byte, copyBufSize))
	if err == nil && n < int64(fileSize) {
		err = io.EOF // peer closed early; matches io.CopyN's short-read error
	}
	stopSampler()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &Error{Op: OpRecvBody, Err: err, Got: n, Total: int64(fileSize)}
	}

	return &Result{
		Name:    filename,
		Path:    destPath,
		Bytes:   n,
		Elapsed: time.Since(start),
	}, nil
}

// DownloadsDir returns the ~/Downloads directory, creating it if needed. It is shared by
// the CLI and the tray for the default (non---here) receive destination. On failure it
// returns a *transfer.Error whose message matches the historical CLI wording.
func DownloadsDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", &Error{Op: OpHomeDir, Err: err}
	}
	dir := filepath.Join(home, "Downloads")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", &Error{Op: OpMkdirDownloads, Err: err}
	}
	return dir, nil
}
