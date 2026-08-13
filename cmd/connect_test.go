package cmd

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// roundTripFunc lets a test stand in for the Tor-backed transport.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func probeClient(t *testing.T, calls *int, fn func(int) (*http.Response, error)) *http.Client {
	t.Helper()
	return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		*calls++
		return fn(*calls)
	})}
}

func okResponse() *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"version":"test"}`)),
		Header:     make(http.Header),
	}
}

// The plain case: somebody is hosting, so we join rather than publishing a
// second descriptor over theirs.
func TestHostedElsewhereDetectsLiveHost(t *testing.T) {
	calls := 0
	client := probeClient(t, &calls, func(int) (*http.Response, error) { return okResponse(), nil })

	hosted, why := hostedElsewhere(client, "http://example.onion")
	if !hosted {
		t.Fatalf("expected the live host to be detected, got not-hosted (%s)", why)
	}
	if calls != 1 {
		t.Fatalf("a reachable host should be settled in one request, took %d", calls)
	}
}

// Tor's "host unreachable" means no descriptor is published. Two of those in a
// row is conclusive, and must short-circuit rather than burning every attempt —
// this is what keeps hosting an empty room at ~20s instead of ~200s.
func TestHostedElsewhereShortCircuitsOnUnreachable(t *testing.T) {
	roomProbeBackoff = time.Millisecond
	t.Cleanup(func() { roomProbeBackoff = 3 * time.Second })

	calls := 0
	client := probeClient(t, &calls, func(int) (*http.Response, error) {
		return nil, errors.New("socks connect tcp 127.0.0.1:9050->x.onion:80: unknown error host unreachable")
	})

	hosted, why := hostedElsewhere(client, "http://example.onion")
	if hosted {
		t.Fatal("unreachable onion should not be reported as hosted")
	}
	if calls != 2 {
		t.Fatalf("two consecutive definitive misses should settle it; made %d requests", calls)
	}
	if !strings.Contains(why, "host unreachable") {
		t.Fatalf("reason should name the failure, got %q", why)
	}
}

// An ambiguous failure (timeout, circuit trouble) is not evidence the room is
// empty, so it must use the full retry budget before concluding.
func TestHostedElsewhereRetriesAmbiguousFailures(t *testing.T) {
	roomProbeBackoff = time.Millisecond
	t.Cleanup(func() { roomProbeBackoff = 3 * time.Second })

	calls := 0
	client := probeClient(t, &calls, func(int) (*http.Response, error) {
		return nil, errors.New("context deadline exceeded")
	})

	if hosted, _ := hostedElsewhere(client, "http://example.onion"); hosted {
		t.Fatal("should not report hosted when every attempt failed")
	}
	if calls != roomProbeAttempts {
		t.Fatalf("ambiguous failures should use all %d attempts, made %d", roomProbeAttempts, calls)
	}
}

// A host that is briefly unreachable and then answers must be found, not
// steamrolled — publishing over a live host is the split-brain case.
func TestHostedElsewhereRecoversAfterSingleMiss(t *testing.T) {
	roomProbeBackoff = time.Millisecond
	t.Cleanup(func() { roomProbeBackoff = 3 * time.Second })

	calls := 0
	client := probeClient(t, &calls, func(n int) (*http.Response, error) {
		if n == 1 {
			return nil, errors.New("unknown error host unreachable")
		}
		return okResponse(), nil
	})

	if hosted, why := hostedElsewhere(client, "http://example.onion"); !hosted {
		t.Fatalf("host answering on the second attempt should be found, got %s", why)
	}
}

// A non-200 answer means something is listening but is not a healthy room, so
// it should not be treated as a miss that licenses taking over.
func TestHostedElsewhereTreatsNon200AsNotHosted(t *testing.T) {
	roomProbeBackoff = time.Millisecond
	t.Cleanup(func() { roomProbeBackoff = 3 * time.Second })

	calls := 0
	client := probeClient(t, &calls, func(int) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadGateway,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
		}, nil
	})

	hosted, why := hostedElsewhere(client, "http://example.onion")
	if hosted {
		t.Fatal("a non-200 response should not count as a healthy host")
	}
	if calls != roomProbeAttempts {
		t.Fatalf("non-200 is ambiguous and should be retried %d times, made %d", roomProbeAttempts, calls)
	}
	if !strings.Contains(why, "502") {
		t.Fatalf("reason should report the status code, got %q", why)
	}
}
