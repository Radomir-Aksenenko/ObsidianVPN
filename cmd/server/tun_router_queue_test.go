package main

import (
	"encoding/binary"
	"slices"
	"strings"
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

// testIPv4 builds an IPv4 packet with a 20-byte header followed by l4. Addresses and checksums
// stay zero because neither the classifier nor the queue reads them.
func testIPv4(proto byte, l4 []byte) []byte {
	pkt := make([]byte, 20+len(l4))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[9] = proto
	copy(pkt[20:], l4)
	return pkt
}

// testIPv6 builds an IPv6 packet with a 40-byte header followed by l4.
func testIPv6(next byte, l4 []byte) []byte {
	pkt := make([]byte, 40+len(l4))
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(l4)))
	pkt[6] = next
	copy(pkt[40:], l4)
	return pkt
}

// testTCP returns a TCP segment with a 20-byte header, the given flags and payload bytes.
func testTCP(flags byte, payload int) []byte {
	seg := make([]byte, 20+payload)
	seg[12] = 5 << 4
	seg[13] = flags
	return seg
}

// Packet sizes used by the queue tests, so the recorded send order can be compared by length.
const (
	smallLen = 100  // smallUDP
	bulkLen  = 1000 // bulkPacket
)

func smallUDP() []byte   { return testIPv4(17, make([]byte, 80)) }
func bulkPacket() []byte { return testIPv4(6, testTCP(0x18, 960)) }

func TestIsLatencySensitive(t *testing.T) {
	badOffset := testTCP(0x10, 0)
	badOffset[12] = 0

	cases := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"small udp", smallUDP(), true},
		{"udp over 600 bytes", testIPv4(17, make([]byte, 1180)), false},
		{"tcp pure ack", testIPv4(6, testTCP(0x10, 0)), true},
		{"tcp syn", testIPv4(6, testTCP(0x02, 0)), true},
		{"tcp with payload", bulkPacket(), false},
		{"tcp bad data offset", testIPv4(6, badOffset), false},
		{"icmp", testIPv4(1, make([]byte, 8)), true},
		{"truncated ipv4", smallUDP()[:30], false},
		{"truncated tcp header", testIPv4(6, testTCP(0x10, 0))[:30], false},
		{"small udp ipv6", testIPv6(17, make([]byte, 8)), true},
		{"icmpv6", testIPv6(58, make([]byte, 8)), true},
		{"tcp ack ipv6", testIPv6(6, testTCP(0x10, 0)), true},
		{"tcp with payload ipv6", testIPv6(6, testTCP(0x10, 100)), false},
		{"empty", nil, false},
		{"unknown version", []byte{0x70, 0, 0, 0}, false},
	}
	for _, c := range cases {
		if got := isLatencySensitive(c.pkt); got != c.want {
			t.Errorf("%s: isLatencySensitive = %v, want %v", c.name, got, c.want)
		}
	}
}

// gatedSession registers a session whose first send blocks until release is closed, so a test
// can queue packets while the sender is holding one. sent returns the lengths sent so far.
func gatedSession(r *tunRouter) (s *routedSession, started, release chan struct{}, sent func() []int) {
	started = make(chan struct{})
	release = make(chan struct{})
	var mu sync.Mutex
	var lens []int
	calls := 0 // only touched by the session's writeLoop
	s = r.registerSession("test", func(p []byte) error {
		calls++
		if calls == 1 {
			close(started)
			<-release
		}
		mu.Lock()
		lens = append(lens, len(p))
		mu.Unlock()
		return nil
	})
	return s, started, release, func() []int {
		mu.Lock()
		defer mu.Unlock()
		return append([]int(nil), lens...)
	}
}

func mustEnqueue(t *testing.T, s *routedSession, pkt []byte) {
	t.Helper()
	if !s.enqueue(pkt) {
		t.Fatal("enqueue refused a packet")
	}
}

// waitSent polls until n packets have been sent or the test times out.
func waitSent(t *testing.T, sent func() []int, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for len(sent()) < n {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d sends, have %d", n, len(sent()))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A small UDP packet queued behind bulk data must go out before the bulk packets still waiting.
func TestRoutedSessionSendsSmallUDPBeforeQueuedBulk(t *testing.T) {
	r := newTunRouter(nil)
	s, started, release, sent := gatedSession(r)
	defer s.Close()

	mustEnqueue(t, s, bulkPacket())
	<-started
	for i := 0; i < 3; i++ {
		mustEnqueue(t, s, bulkPacket())
	}
	mustEnqueue(t, s, smallUDP())
	close(release)

	waitSent(t, sent, 5)
	want := []int{bulkLen, smallLen, bulkLen, bulkLen, bulkLen}
	if got := sent(); !slices.Equal(got, want) {
		t.Fatalf("send order = %v, want %v", got, want)
	}
}

// With latency-sensitive packets always waiting, bulk must still get a turn within the first
// routedPrioBurst+2 sends (the held packet, then a burst of latency-sensitive ones, then bulk).
func TestRoutedSessionBulkNotStarvedByLatencyLane(t *testing.T) {
	r := newTunRouter(nil)
	s, started, release, sent := gatedSession(r)
	defer s.Close()

	mustEnqueue(t, s, bulkPacket())
	<-started
	for i := 0; i < 200; i++ {
		mustEnqueue(t, s, smallUDP())
	}
	for i := 0; i < 5; i++ {
		mustEnqueue(t, s, bulkPacket())
	}
	close(release)

	waitSent(t, sent, 206)
	got := sent()
	for i := 1; i < len(got); i++ {
		if got[i] == bulkLen {
			if i >= routedPrioBurst+2 {
				t.Fatalf("first bulk send after the held one is at index %d, want < %d", i, routedPrioBurst+2)
			}
			return
		}
	}
	t.Fatalf("no bulk packet was sent after the held one: %v", got)
}

// With a batch sender, queued bulk packets leave in one call, stale ones are dropped first,
// and a waiting latency-sensitive packet goes out before the batch.
func TestRoutedSessionBatchedBulk(t *testing.T) {
	var events []string
	s := &routedSession{
		sid: "batch",
		send: func(p []byte) error {
			events = append(events, "one:"+string(p))
			return nil
		},
		out:  make(chan routedPacket, 8),
		prio: make(chan routedPacket, 8),
		done: make(chan struct{}),
	}
	s.setBatchSender(func(pkts [][]byte) (int, error) {
		names := make([]string, len(pkts))
		for i, p := range pkts {
			names[i] = string(p)
		}
		events = append(events, "batch:"+strings.Join(names, ","))
		return len(pkts), nil
	})
	pkt := func(name string, age time.Duration) routedPacket {
		b := getRoutedPacket(len(name))
		copy(b, name)
		return routedPacket{buf: b, at: time.Now().Add(-age)}
	}
	s.prio <- pkt("P", 0)
	first := pkt("b1", 0)
	s.out <- pkt("old", time.Second)
	s.out <- pkt("b2", 0)
	s.out <- pkt("b3", 0)

	var batch [routedBatchSize]routedPacket
	s.sendBulk(first, batch[:])

	want := []string{"one:P", "batch:b1,b2,b3"}
	if !slices.Equal(events, want) {
		t.Fatalf("events = %q, want %q", events, want)
	}
	for i, p := range batch {
		if p.buf != nil {
			t.Fatalf("batch slot %d still holds a buffer", i)
		}
	}
}
