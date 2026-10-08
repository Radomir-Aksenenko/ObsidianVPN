package main

import (
	"log"
	"sync"
	"time"
)

// rateLimitedLog gates hot-path diagnostics (per-packet drops under congestion) to at
// most one line per interval. Logging on every drop is a synchronous write per packet
// exactly when the server is already overloaded. Call sites check Ready() before they
// format arguments, so suppressed lines cost one mutex and no fmt work.
type rateLimitedLog struct {
	mu         sync.Mutex
	interval   time.Duration
	last       time.Time
	suppressed int
}

func newRateLimitedLog(interval time.Duration) *rateLimitedLog {
	return &rateLimitedLog{interval: interval}
}

// Ready reports whether a line may be printed now. Suppressed lines are counted and
// reported with the next printed line.
func (l *rateLimitedLog) Ready() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.last) < l.interval {
		l.suppressed++
		return false
	}
	if l.suppressed > 0 {
		log.Printf("(%d similar data-path messages suppressed)", l.suppressed)
		l.suppressed = 0
	}
	l.last = now
	return true
}

// dropLog is used for per-packet drop diagnostics on the data path.
var dropLog = newRateLimitedLog(time.Second)
