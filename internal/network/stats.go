package network

import "sync/atomic"

// TunnelStats are process-global counters across the tunnel hot paths, cheap
// enough (single atomic add per event) to leave always-on. The daemon samples
// them once per second and logs deltas so a misbehaving transfer shows exactly
// which stage packets die at: sent-but-not-received is path loss, received-
// but-failing-decrypt is a key/session problem, replay drops are reordering
// beyond the window, rekeys/timeouts are session churn.
type TunnelStats struct {
	TxPkts  atomic.Uint64 // transport packets handed to the bind
	TxBytes atomic.Uint64 // wire bytes across those packets
	TxErrs  atomic.Uint64 // batches whose bind.Send returned an error

	RxPkts  atomic.Uint64 // data/tun packets received and queued (pre-decrypt)
	RxBytes atomic.Uint64 // wire bytes across those packets

	RxDecryptFail atomic.Uint64 // packets failing AEAD authentication
	RxReplayDrop  atomic.Uint64 // authenticated packets outside the replay window

	Rekeys   atomic.Uint64 // sessions re-armed (keepalive timeout or CtrlRekey)
	Timeouts atomic.Uint64 // peers declared dead by the keepalive

	// PaceBps is a gauge: the adaptive shaper's current rate in bytes/sec
	// (last session updated wins; 0 = uncapped).
	PaceBps atomic.Uint64
}

// Stats is the process-wide instance updated by PeerConn.
var Stats TunnelStats
