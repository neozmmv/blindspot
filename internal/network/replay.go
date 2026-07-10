package network

// ReplayWindowSize is the width of the anti-replay sliding window, in packets.
// It must be well above real-world UDP reordering depth: a reordered packet
// that falls outside the window is dropped, which a tunnelled TCP stream reads
// as congestion loss. 2048 packets (~3 MB of flight at the tunnel MTU) matches
// WireGuard's sizing.
const ReplayWindowSize = 2048

// ReplayWindow is a sliding-window anti-replay filter (RFC 6479 style): a
// bitmap of the last ReplayWindowSize counters, indexed by counter modulo the
// window, plus the highest counter accepted so far. The zero value is ready to
// use. It is not safe for concurrent use; callers must provide their own
// locking (peerSession guards it with its mutex).
type ReplayWindow struct {
	max  uint64
	bits [ReplayWindowSize / 64]uint64
}

// Check reports whether counter is fresh (neither already seen nor older than
// the window) and records it. Bit counter%ReplayWindowSize tracks each
// counter; advancing the window zeroes the words it newly covers. It must be
// called only after the packet has been successfully authenticated, so that a
// forged packet can never advance or poke holes in the window.
func (w *ReplayWindow) Check(counter uint64) bool {
	const words = ReplayWindowSize / 64
	if counter > w.max {
		if counter-w.max >= ReplayWindowSize {
			w.bits = [words]uint64{}
		} else {
			for i := w.max/64 + 1; i <= counter/64; i++ {
				w.bits[i%words] = 0
			}
		}
		w.max = counter
	} else if w.max-counter > ReplayWindowSize-64 {
		// Too old. The enforced window is one word narrower than the bitmap
		// (RFC 6479): words are cleared with 64-counter granularity, so a counter
		// in the oldest word could otherwise alias a bit already reused by a
		// newer epoch — accepting it would let a replay through.
		return false
	}
	word := (counter / 64) % words
	mask := uint64(1) << (counter % 64)
	if w.bits[word]&mask != 0 {
		return false // replay
	}
	w.bits[word] |= mask
	return true
}
