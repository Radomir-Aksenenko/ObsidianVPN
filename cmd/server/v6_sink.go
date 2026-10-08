package main

import (
	"io"

	"obsidian/obsidian"
)

// clientSink is what the client-to-server relay loops write into. When server IPv6 is
// enabled it is a plain pass-through to the server TUN. When it is disabled, IPv6 packets
// from the client are answered locally (TCP RST or ICMPv6 Destination Unreachable) and
// sent back to that client, instead of vanishing and leaving the client to time out.
type clientSink struct {
	route   *routedSession
	limiter *obsidian.RejectLimiter
}

func newClientSink(route *routedSession, serverIPv6 bool) io.Writer {
	if serverIPv6 {
		return route
	}
	return &clientSink{route: route, limiter: obsidian.NewRejectLimiter(100, 20)}
}

func (c *clientSink) Write(p []byte) (int, error) {
	if len(p) == 0 || p[0]>>4 != 6 {
		return c.route.Write(p)
	}
	// Allocate per reply: rejects are rate limited, and two relay goroutines may write concurrently.
	out := make([]byte, obsidian.IPv6RejectBufSize)
	n, ok := obsidian.BuildIPv6Reject(p, out)
	if ok && c.limiter.Allow() {
		c.route.enqueue(out[:n])
	}
	return len(p), nil
}
