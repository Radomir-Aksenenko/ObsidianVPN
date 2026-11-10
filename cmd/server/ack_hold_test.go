package main

import (
	"encoding/binary"
	"sync"
	"testing"
	"time"
)

func testPureACK(port uint16, ack uint32) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 443)
	binary.BigEndian.PutUint16(tcp[2:4], port)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 5 << 4
	tcp[13] = 0x10
	return testIPv4(6, tcp)
}

func testTCPData(port uint16, n int) []byte {
	tcp := make([]byte, 20+n)
	binary.BigEndian.PutUint16(tcp[0:2], 443)
	binary.BigEndian.PutUint16(tcp[2:4], port)
	tcp[12] = 5 << 4
	tcp[13] = 0x18
	return testIPv4(6, tcp)
}

type sentLog struct {
	mu   sync.Mutex
	pkts [][]byte
	at   []time.Time
}

func (l *sentLog) add(p []byte) {
	l.mu.Lock()
	l.pkts = append(l.pkts, append([]byte(nil), p...))
	l.at = append(l.at, time.Now())
	l.mu.Unlock()
}

func (l *sentLog) wait(t *testing.T, n int) ([][]byte, []time.Time) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		l.mu.Lock()
		if len(l.pkts) >= n {
			p, a := l.pkts, l.at
			l.pkts, l.at = nil, nil
			l.mu.Unlock()
			return p, a
		}
		l.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("only %d of %d packets sent", len(l.pkts), n)
	return nil, nil
}

func ackOf(p []byte) uint32 { return binary.BigEndian.Uint32(p[28:32]) }

// Pure ACKs on the latency lane are held briefly and only the newest per connection is sent;
// any other packet ends the hold at once.
func TestRoutedSessionHoldsDownlinkACKs(t *testing.T) {
	old := downlinkACKHold
	downlinkACKHold = 30 * time.Millisecond
	defer func() { downlinkACKHold = old }()

	r := newTunRouter(nil)
	var log sentLog
	s := r.registerSession("ack", func(p []byte) error { log.add(p); return nil })
	defer s.Close()
	s.setBatchSender(func(pkts [][]byte) (int, error) {
		for _, p := range pkts {
			log.add(p)
		}
		return len(pkts), nil
	})
	enqueue := func(p []byte) {
		b := getRoutedPacket(len(p))
		copy(b, p)
		if !s.enqueue(b) {
			t.Fatal("enqueue failed")
		}
	}

	start := time.Now()
	enqueue(testPureACK(1000, 100))
	enqueue(testPureACK(1000, 200))
	enqueue(testPureACK(1000, 300))
	enqueue(testPureACK(2000, 50))
	pkts, at := log.wait(t, 2)
	time.Sleep(40 * time.Millisecond)
	if extra, _ := log.wait2(); extra != 0 {
		t.Fatalf("%d superseded ACKs were sent too", extra)
	}
	if ackOf(pkts[0]) != 300 || ackOf(pkts[1]) != 50 {
		t.Fatalf("sent acks %d, %d; want 300, 50", ackOf(pkts[0]), ackOf(pkts[1]))
	}
	if d := at[0].Sub(start); d < 20*time.Millisecond {
		t.Fatalf("ACK run left after %v, before the hold", d)
	}

	start = time.Now()
	enqueue(testPureACK(1000, 400))
	enqueue(testTCPData(1000, 1000))
	_, at = log.wait(t, 2)
	if d := at[1].Sub(start); d > 20*time.Millisecond {
		t.Fatalf("data waited %v behind held ACKs", d)
	}
}

func (l *sentLog) wait2() (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.pkts), nil
}
