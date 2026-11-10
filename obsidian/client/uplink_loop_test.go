package client

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"obsidian/obsidian"
)

// fakeTun serves queued packets to Read and records Write.
type fakeTun struct {
	in  chan []byte
	mu  sync.Mutex
	out [][]byte
}

func (f *fakeTun) Read(b []byte) (int, error) { return copy(b, <-f.in), nil }
func (f *fakeTun) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.out = append(f.out, append([]byte(nil), p...))
	return len(p), nil
}

func testIPv4(i int) []byte {
	p := make([]byte, 40+i%300)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[9] = 17
	binary.BigEndian.PutUint32(p[20:24], uint32(i))
	return p
}

func testIPv6SYN() []byte {
	p := make([]byte, 60)
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:6], 20)
	p[6], p[7] = 6, 64
	p[8], p[24] = 0xfd, 0x20
	p[40+12], p[40+13] = 5<<4, 0x02
	return p
}

// The batched uplink loop must deliver every IPv4 packet in order through the tunnel and answer
// IPv6 locally when it is disabled, also when packets arrive in bursts.
func TestCopyTunToTunnelBatchesInOrder(t *testing.T) {
	s := newIPv6DisabledSession(t)
	cliConn, srvConn := net.Pipe()
	cfg := obsidian.DefaultTunnelConfig()
	cfg.NoiseMinInterval, cfg.NoiseMaxInterval = time.Hour, time.Hour
	cfg.KeepaliveInterval, cfg.KeepaliveJitter = time.Hour, 0
	mk := func(k, iv byte) *obsidian.Cipher {
		c, err := obsidian.NewCipher([obsidian.KeySize]byte{k}, [obsidian.NonceSize]byte{iv})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	cli := obsidian.NewTunnel(cliConn, obsidian.NewStreamFramer(mk(1, 2), mk(3, 4)), cfg)
	srv := obsidian.NewTunnel(srvConn, obsidian.NewStreamFramer(mk(3, 4), mk(1, 2)), cfg)
	defer cli.Close()
	defer srv.Close()

	tun := &fakeTun{in: make(chan []byte, 256)}
	const n = 200
	for i := 0; i < n; i++ {
		tun.in <- testIPv4(i)
		if i%50 == 0 {
			tun.in <- testIPv6SYN()
		}
	}
	done := make(chan error, 1)
	go func() { done <- s.copyTunToTunnel(tun, cli) }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	buf := make([]byte, 2048)
	for i := 0; i < n; i++ {
		m, err := srv.RecvDataInto(ctx, buf)
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		if m < 24 || buf[0] != 0x45 || int(binary.BigEndian.Uint32(buf[20:24])) != i {
			t.Fatalf("packet %d arrived out of order or changed", i)
		}
	}
	close(s.stopCh)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("loop returned %v after stop", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("loop did not stop")
	}
	tun.mu.Lock()
	rejects := len(tun.out)
	tun.mu.Unlock()
	if rejects != 4 {
		t.Fatalf("got %d IPv6 rejects written to TUN, want 4", rejects)
	}
	if got := s.pktsSent.Load(); got != n+4 {
		t.Fatalf("pktsSent = %d, want %d", got, n+4)
	}
}
