package client

import (
	"math/rand/v2"
	"time"
)

// Backoff spaces out reconnect attempts.
//
// The client used to wait a fixed 3 s, and 0 s after a UDP stall. When a censor degrades the
// path rather than cutting it, that turns one phone into a TLS handshake to the same foreign IP
// every few seconds for hours, which is a far stronger signal than the traffic itself. Backoff
// doubles the wait after every session that dies young, adds jitter so the attempts do not form
// a clean period, and starts over once a session has lived long enough to count as healthy.
type Backoff struct {
	Base        time.Duration // first wait after a healthy session ends
	Max         time.Duration // upper bound for one wait
	StableAfter time.Duration // a session that lived this long resets the backoff

	fails int
}

// DefaultBackoff is the reconnect schedule of both clients: about 2, 4, 8, 16, 32, 60, 60... s.
func DefaultBackoff() *Backoff {
	return &Backoff{Base: 2 * time.Second, Max: 60 * time.Second, StableAfter: 2 * time.Minute}
}

// Next returns how long to wait after a session that lasted lived (dial time included).
func (b *Backoff) Next(lived time.Duration) time.Duration {
	if lived >= b.StableAfter {
		b.fails = 0
	}
	d := b.Base
	for i := 0; i < b.fails && d < b.Max; i++ {
		d *= 2
	}
	if d > b.Max {
		d = b.Max
	}
	b.fails++
	// ±25% jitter.
	j := time.Duration(rand.Int64N(int64(d)/2+1)) - d/4
	return d + j
}

// Reset forgets earlier failures, for example after the user reconnects by hand.
func (b *Backoff) Reset() { b.fails = 0 }
