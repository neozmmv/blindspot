package network

import (
	"testing"
	"time"
)

// ackStep simulates one CtrlAck arriving after `elapsed`, with the session
// having sent sentB bytes / dMax packets of which dAcc were accepted.
func ackStep(p *PeerConn, s *peerSession, elapsed time.Duration, sentB uint64, dMax, dAcc uint64) {
	s.paceMu.Lock()
	s.lastAckAt = time.Now().Add(-elapsed)
	s.paceSentB = sentB
	base := s.lastAckMax
	baseAcc := s.lastAckAcc
	s.paceMu.Unlock()
	p.handleAck(s, base+dMax, baseAcc+dAcc)
}

// TestAdaptiveShaper drives handleAck through the engage → cut → probe cycle
// and checks the control law: uncapped until real loss, engaged near the
// observed send rate on a loss event, growing again on clean utilized
// intervals, and not double-cutting within the guard window.
func TestAdaptiveShaper(t *testing.T) {
	p := &PeerConn{}
	s := &peerSession{}

	// Baseline ack: seeds the snapshot, no rate yet.
	p.handleAck(s, 100, 100)
	if got := p.effectiveRate(s); got != 0 {
		t.Fatalf("rate engaged with no loss signal: %v", got)
	}

	// Clean traffic: stays uncapped.
	ackStep(p, s, 200*time.Millisecond, 2_000_000, 1000, 1000)
	if got := p.effectiveRate(s); got != 0 {
		t.Fatalf("rate engaged on clean interval: %v", got)
	}

	// 15% loss while sending 2 MB in 200ms (10 MB/s): engages at
	// sendRate*cutBig = 10e6*0.6 = 6 MB/s.
	ackStep(p, s, 200*time.Millisecond, 2_000_000, 1000, 850)
	rate := p.effectiveRate(s)
	if rate < 5e6 || rate > 7e6 {
		t.Fatalf("expected ~6 MB/s after severe loss engage, got %.0f", rate)
	}

	// Another severe-loss ack immediately after: inside the cut guard, no
	// second cut.
	ackStep(p, s, 200*time.Millisecond, 1_200_000, 800, 600)
	if got := p.effectiveRate(s); got != rate {
		t.Fatalf("double cut within guard window: %.0f -> %.0f", rate, got)
	}

	// Clean and >50%% utilized: probes upward by paceGrow.
	s.paceMu.Lock()
	s.lastCut = time.Now().Add(-time.Second) // move past the guard
	s.paceMu.Unlock()
	ackStep(p, s, 200*time.Millisecond, uint64(rate*0.2), 800, 800)
	if got := p.effectiveRate(s); got <= rate {
		t.Fatalf("expected upward probe on clean utilized interval, got %.0f (was %.0f)", got, rate)
	}

	// Clean but idle (2%% utilization): rate must hold, not balloon.
	before := p.effectiveRate(s)
	ackStep(p, s, 200*time.Millisecond, uint64(before*0.2*0.02), 60, 60)
	if got := p.effectiveRate(s); got != before {
		t.Fatalf("rate changed on idle interval: %.0f -> %.0f", before, got)
	}

	// Tiny sample (below ackMinPkts): ignored entirely.
	ackStep(p, s, 200*time.Millisecond, 10_000, 10, 2)
	if got := p.effectiveRate(s); got != before {
		t.Fatalf("rate reacted to sub-threshold sample: %.0f -> %.0f", before, got)
	}

	// Manual override wins over the adaptive rate and freezes adaptation.
	p.SetFixedUploadRate(1e6)
	if got := p.effectiveRate(s); got != 1e6 {
		t.Fatalf("fixed override not applied: %.0f", got)
	}
	ackStep(p, s, 200*time.Millisecond, 2_000_000, 1000, 500)
	if got := p.effectiveRate(s); got != 1e6 {
		t.Fatalf("adaptive logic ran under fixed override: %.0f", got)
	}
	p.SetFixedUploadRate(0)
	if got := p.effectiveRate(s); got != before {
		t.Fatalf("adaptive rate lost after clearing override: %.0f (want %.0f)", got, before)
	}
}

// TestPaceAdmitThrottles checks the virtual-clock pacer actually spaces sends:
// pushing ~3x a 10 MB/s budget's worth of bytes in a tight loop must take
// roughly the budgeted time, while an uncapped session must not sleep.
func TestPaceAdmitThrottles(t *testing.T) {
	s := &peerSession{}

	start := time.Now()
	for range 100 {
		s.paceAdmit(1500, 0)
	}
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Fatalf("uncapped paceAdmit slept: %v", d)
	}

	const rate = 10e6 // 10 MB/s
	total := 0
	start = time.Now()
	for range 100 {
		s.paceAdmit(15_000, rate) // 1.5 MB total = 150ms of budget
		total += 15_000
	}
	elapsed := time.Since(start)
	want := time.Duration(float64(total) / rate * float64(time.Second))
	if elapsed < want/2 {
		t.Fatalf("paced sends finished in %v, want >= ~%v", elapsed, want)
	}
}
