package client

import (
	"testing"
	"time"
)

func TestBackoffGrowsCapsAndResets(t *testing.T) {
	b := DefaultBackoff()
	want := []time.Duration{2, 4, 8, 16, 32, 60, 60}
	for i, w := range want {
		w *= time.Second
		d := b.Next(time.Second) // sessions that die young
		if d < w*3/4 || d > w*5/4 {
			t.Fatalf("attempt %d: wait %v, want %v ±25%%", i, d, w)
		}
	}
	// A session that lived long enough starts the schedule over.
	if d := b.Next(3 * time.Minute); d > 2500*time.Millisecond {
		t.Fatalf("after a healthy session the wait is %v", d)
	}
}

// The schedule must not let a client hammer the server: within the first ten minutes of a
// path that keeps failing, no more than a handful of handshakes.
func TestBackoffBoundsHandshakeRate(t *testing.T) {
	b := DefaultBackoff()
	var elapsed time.Duration
	attempts := 0
	for elapsed < 10*time.Minute {
		elapsed += b.Next(500*time.Millisecond) + 500*time.Millisecond
		attempts++
	}
	if attempts > 16 {
		t.Fatalf("%d handshakes in 10 minutes", attempts)
	}
	t.Logf("%d handshakes in 10 minutes of failures (fixed 3 s used to give 171)", attempts)
}

func TestBackoffJitterVaries(t *testing.T) {
	seen := map[time.Duration]bool{}
	for i := 0; i < 20; i++ {
		b := DefaultBackoff()
		b.Next(time.Second)
		seen[b.Next(time.Second)] = true
	}
	if len(seen) < 5 {
		t.Fatalf("jitter produced only %d distinct waits", len(seen))
	}
}
