package main

import (
	"sync"
	"testing"
	"time"
)

// A downlink packet that has waited longer than routedMaxSojourn must be dropped at
// dequeue time instead of being sent after seconds of queueing.
func TestRoutedSessionDropsStalePackets(t *testing.T) {
	r := newTunRouter(nil)

	var mu sync.Mutex
	var sent []string
	s := r.registerSession("test", func(p []byte) error {
		mu.Lock()
		sent = append(sent, string(p))
		mu.Unlock()
		return nil
	})
	defer s.Close()

	stale := getRoutedPacket(4)
	copy(stale, "old!")
	s.out <- routedPacket{buf: stale, at: time.Now().Add(-time.Second)}

	fresh := getRoutedPacket(4)
	copy(fresh, "new!")
	s.out <- routedPacket{buf: fresh, at: time.Now()}

	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(sent)
		mu.Unlock()
		if n >= 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(sent) != 1 || sent[0] != "new!" {
		t.Fatalf("expected only the fresh packet to be sent, got %q", sent)
	}
}

func TestRateLimitedLogGatesHotPathLines(t *testing.T) {
	l := newRateLimitedLog(time.Hour)
	if !l.Ready() {
		t.Fatal("first line must be allowed")
	}
	for i := 0; i < 100; i++ {
		if l.Ready() {
			t.Fatal("lines inside the interval must be suppressed")
		}
	}
	if l.suppressed != 100 {
		t.Fatalf("expected 100 suppressed lines, got %d", l.suppressed)
	}
}
