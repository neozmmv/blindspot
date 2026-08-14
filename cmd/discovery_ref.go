package cmd

import (
	"sync"
	"sync/atomic"

	"github.com/neozmmv/blindspot/internal/session"
)

// discoveryRef holds the discovery endpoint a session is currently using, and
// allows it to be replaced while the session keeps running.
//
// This exists for onion rooms, where hosting moves between peers. When a host
// disappears and another peer takes over, only the discovery endpoint changes:
// the UDP transport, the Noise sessions and the TUN device are all still valid
// and must survive the handover. Swapping the client behind this reference is
// what makes that possible — tearing the daemon down and restarting it would
// drop every established peer connection.
//
// `blindspot rendezvous` never swaps; it holds a single clearnet client for the
// life of the session.
type discoveryRef struct {
	mu         sync.Mutex
	client     *session.Client
	superseded chan struct{}

	// wake nudges the periodic re-register to run immediately. After a
	// handover the new host's room starts empty, so waiting out the normal
	// interval would leave the room without even its own host in it.
	wake chan struct{}

	// selfIndex is this peer's join order, as last reported by the room. It is
	// the stagger used to decide who takes over first, so it is read from
	// another goroutine than the one that registers.
	selfIndex atomic.Int64
}

func newDiscoveryRef(c *session.Client) *discoveryRef {
	return &discoveryRef{client: c, superseded: make(chan struct{}), wake: make(chan struct{}, 1)}
}

// current returns the client to use, plus a channel that closes when this
// client has been replaced. Long-lived users (the SSE stream) select on that
// channel to know when to reconnect against the new endpoint.
func (d *discoveryRef) current() (*session.Client, <-chan struct{}) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.client, d.superseded
}

// swap installs a new discovery endpoint and wakes anything waiting on the old.
func (d *discoveryRef) swap(c *session.Client) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.client == c {
		return
	}
	d.client = c
	close(d.superseded)
	d.superseded = make(chan struct{})

	select {
	case d.wake <- struct{}{}:
	default: // a wake is already pending; one is enough
	}
}

// wakeCh fires when the endpoint changed and a re-registration is due.
func (d *discoveryRef) wakeCh() <-chan struct{} { return d.wake }

func (d *discoveryRef) setSelfIndex(i int) { d.selfIndex.Store(int64(i)) }
func (d *discoveryRef) SelfIndex() int     { return int(d.selfIndex.Load()) }

// anyClosed returns a channel that closes as soon as any of the inputs does. It
// lets the stream shut down either because the session is ending or because the
// endpoint it is talking to has been superseded.
func anyClosed(chans ...<-chan struct{}) chan struct{} {
	out := make(chan struct{})
	var once sync.Once
	for _, ch := range chans {
		go func(c <-chan struct{}) {
			select {
			case <-c:
				once.Do(func() { close(out) })
			case <-out:
			}
		}(ch)
	}
	return out
}
