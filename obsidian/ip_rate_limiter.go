package obsidian

import (
	"net/netip"
	"sync"
	"time"
)

// IPRateLimiter is a lightweight token-bucket limiter keyed by remote IP.
// It is intended for cheap pre-handshake filtering before expensive crypto work.
type IPRateLimiter struct {
	mu              sync.Mutex
	ratePerSecond   int64
	burst           int64
	cleanupInterval time.Duration
	entryTTL        time.Duration
	lastCleanup     time.Time
	entries         map[netip.Addr]*ipRateEntry
}

type ipRateEntry struct {
	last   time.Time
	tokens int64
}

func NewIPRateLimiter(ratePerSecond, burst int) *IPRateLimiter {
	if ratePerSecond <= 0 {
		ratePerSecond = 20
	}
	if burst <= 0 {
		burst = 5
	}
	now := time.Now()
	return &IPRateLimiter{
		ratePerSecond:   int64(ratePerSecond),
		burst:           int64(burst),
		cleanupInterval: time.Second,
		entryTTL:        10 * time.Second,
		lastCleanup:     now,
		entries:         make(map[netip.Addr]*ipRateEntry),
	}
}

// Allow returns true when addr still has enough tokens. The implementation uses
// integer nanosecond accounting to avoid floats in the hot path.
func (r *IPRateLimiter) Allow(addr netip.Addr) bool {
	if r == nil || !addr.IsValid() {
		return true
	}
	now := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()

	if now.Sub(r.lastCleanup) >= r.cleanupInterval {
		for ip, entry := range r.entries {
			if now.Sub(entry.last) > r.entryTTL {
				delete(r.entries, ip)
			}
		}
		r.lastCleanup = now
	}

	maxTokens := r.burst * int64(time.Second)
	cost := int64(time.Second)
	entry := r.entries[addr]
	if entry == nil {
		r.entries[addr] = &ipRateEntry{last: now, tokens: maxTokens - cost}
		return true
	}

	elapsed := now.Sub(entry.last)
	entry.last = now
	entry.tokens += elapsed.Nanoseconds() * r.ratePerSecond
	if entry.tokens > maxTokens {
		entry.tokens = maxTokens
	}
	if entry.tokens < cost {
		return false
	}
	entry.tokens -= cost
	return true
}
