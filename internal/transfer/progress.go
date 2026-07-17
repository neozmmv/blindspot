package transfer

import (
	"fmt"
	"time"
)

// Progress is a raw byte-count snapshot pushed during a transfer. The set-once fields
// (Name, PeerAddr, Total) repeat on every snapshot. The first snapshot sent for a
// transfer has Transferred == 0 and arrives before any bytes flow, so a caller can
// render its "Sending…/Receiving…" header from it. The caller owns the channel and
// closes it once Send/Accept has returned; Send and Accept never close it.
type Progress struct {
	Name        string // file base name
	PeerAddr    string // remote address (receive); empty for send
	Transferred int64
	Total       int64
}

// Result summarizes a finished transfer and drives the persistent summary line.
type Result struct {
	Name    string
	Path    string // receive: destination path; send: source path
	Bytes   int64
	Elapsed time.Duration
}

// FormatBytes renders a byte count in B / KB / MB, matching the historical CLI output.
func FormatBytes(b float64) string {
	switch {
	case b >= 1024*1024:
		return fmt.Sprintf("%.2f MB", b/1024/1024)
	case b >= 1024:
		return fmt.Sprintf("%.2f KB", b/1024)
	default:
		return fmt.Sprintf("%.0f B", b)
	}
}

// LineRenderer turns consecutive Progress snapshots into the transient one-line
// "  50.0%  12.00 MB/s  ETA 3s      " progress display (without the leading carriage
// return, which the caller adds). It tracks the last sample to compute the live speed,
// exactly as the old startProgress ticker did. Seed it with the first snapshot so the
// first rendered line measures from the transfer's start.
type LineRenderer struct {
	lastBytes int64
	lastTick  time.Time
	seeded    bool
}

// Seed records the starting point (typically the Transferred==0 header snapshot) so the
// next Line call measures speed from here.
func (lr *LineRenderer) Seed(p Progress) {
	lr.lastBytes = p.Transferred
	lr.lastTick = time.Now()
	lr.seeded = true
}

// Line renders the progress display for snapshot p and advances the internal cursor.
func (lr *LineRenderer) Line(p Progress) string {
	now := time.Now()
	if !lr.seeded {
		lr.lastBytes = 0
		lr.lastTick = now
		lr.seeded = true
	}
	delta := p.Transferred - lr.lastBytes
	elapsed := now.Sub(lr.lastTick)
	lr.lastBytes = p.Transferred
	lr.lastTick = now

	var speed float64
	if elapsed > 0 {
		speed = float64(delta) / elapsed.Seconds()
	}
	pct := float64(p.Transferred) / float64(p.Total) * 100
	var eta string
	if speed > 0 {
		secs := float64(p.Total-p.Transferred) / speed
		eta = fmt.Sprintf("ETA %s", time.Duration(secs*float64(time.Second)).Round(time.Second))
	} else {
		eta = "ETA --"
	}
	return fmt.Sprintf("  %.1f%%  %s  %s      ", pct, FormatBytes(speed)+"/s", eta)
}
