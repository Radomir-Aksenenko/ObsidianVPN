package main

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"obsidian/obsidian"
)

// batchTUN records batched writes the way the offload device receives them.
type batchTUN struct {
	fakeTUN
	bmu     sync.Mutex
	batches [][][]byte
	reads   chan [][]byte
}

func (b *batchTUN) WriteBatch(bufs [][]byte) (int, error) {
	var batch [][]byte
	for _, buf := range bufs {
		if len(buf) < tunWriteHeadroom {
			panic("buffer without headroom")
		}
		batch = append(batch, append([]byte(nil), buf[tunWriteHeadroom:]...))
	}
	b.bmu.Lock()
	b.batches = append(b.batches, batch)
	b.bmu.Unlock()
	return len(bufs), nil
}

func (b *batchTUN) BatchSize() int { return 8 }

func (b *batchTUN) ReadBatch(bufs [][]byte, sizes []int) (int, error) {
	pkts, ok := <-b.reads
	if !ok {
		return 0, io.EOF
	}
	for i, p := range pkts {
		sizes[i] = copy(bufs[i], p)
	}
	return len(pkts), nil
}

func (b *batchTUN) all() [][]byte {
	b.bmu.Lock()
	defer b.bmu.Unlock()
	var out [][]byte
	for _, batch := range b.batches {
		out = append(out, batch...)
	}
	return out
}

func testTunnelPair(t *testing.T) (client, server *obsidian.Tunnel) {
	t.Helper()
	mk := func(k, iv byte) *obsidian.Cipher {
		c, err := obsidian.NewCipher([obsidian.KeySize]byte{k}, [obsidian.NonceSize]byte{iv})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	cfg := obsidian.DefaultTunnelConfig()
	cfg.Jitter = obsidian.JitterOff
	cfg.NoiseMinInterval, cfg.NoiseMaxInterval = time.Hour, time.Hour
	cfg.KeepaliveInterval, cfg.KeepaliveJitter = time.Hour, 0
	a, b := net.Pipe()
	client = obsidian.NewTunnel(a, obsidian.NewStreamFramer(mk(1, 2), mk(3, 4)), cfg)
	server = obsidian.NewTunnel(b, obsidian.NewStreamFramer(mk(3, 4), mk(1, 2)), cfg)
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}

// A burst from the client must reach the TUN complete and in order through batched writes, with
// forwardable IPv6 rejected by the sink and multicast name queries dropped.
func TestTunnelToTUNBatchKeepsOrder(t *testing.T) {
	tun := &batchTUN{}
	r := newTunRouter(tun)
	sess := newPhone(r, "one")
	defer sess.Close()
	client, server := testTunnelPair(t)
	go tunnelToTUN(server, newClientSink(sess, false), "one")

	var want [][]byte
	var burst [][]byte
	for i := 0; i < 100; i++ {
		pkt := buildIPv4(6, phoneIP4, testRemote4, tcpSegment(string(rune('a'+i%26))+"payload"))
		burst = append(burst, pkt)
		want = append(want, append([]byte(nil), pkt...))
		if i%10 == 0 {
			v6 := make([]byte, 60)
			v6[0] = 0x60
			v6[6] = 17
			v6[24] = 0x20
			burst = append(burst, v6)
		}
	}
	if _, err := client.SendDataBatch(burst); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(tun.all()) < len(want) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	got := tun.all()
	if len(got) != len(want) {
		t.Fatalf("TUN got %d packets, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("packet %d differs or is out of order", i)
		}
	}
	for _, p := range got {
		if p[0]>>4 == 6 {
			t.Fatal("an IPv6 packet reached the TUN of an IPv4-only server")
		}
	}
	tun.bmu.Lock()
	batches := len(tun.batches)
	tun.bmu.Unlock()
	if batches >= len(want) {
		t.Fatalf("%d writes for %d packets: nothing was batched", batches, len(want))
	}
}

// Without batch support the sink must still get every packet through single writes.
func TestTunnelToTUNBatchFallsBackToSingleWrites(t *testing.T) {
	tun := &fakeTUN{}
	r := newTunRouter(tun)
	sess := newPhone(r, "one")
	defer sess.Close()
	client, server := testTunnelPair(t)
	go tunnelToTUN(server, sess, "one")
	pkt := buildIPv4(6, phoneIP4, testRemote4, tcpSegment("x"))
	if _, err := client.SendDataBatch([][]byte{pkt, pkt, pkt}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		tun.mu.Lock()
		n := len(tun.written)
		tun.mu.Unlock()
		if n == 3 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("packets did not reach a TUN without batch support")
}

// Every segment of a batched read must be routed to its session, in order.
func TestRouterBatchReadRoutesEverySegment(t *testing.T) {
	tun := &batchTUN{reads: make(chan [][]byte, 1)}
	r := newTunRouter(tun)
	var mu sync.Mutex
	var sent [][]byte
	sess := r.registerSession("one", func(p []byte) error {
		mu.Lock()
		sent = append(sent, append([]byte(nil), p...))
		mu.Unlock()
		return nil
	})
	defer sess.Close()
	// Bind the session's address with one uplink packet.
	if err := sess.writeToTUN(buildIPv4(6, phoneIP4, testRemote4, tcpSegment("hi"))); err != nil {
		t.Fatal(err)
	}
	var read [][]byte
	for i := 0; i < 5; i++ {
		read = append(read, buildIPv4(6, testRemote4, phoneIP4, tcpSegment(string(rune('0'+i))+"data")))
	}
	go r.run()
	tun.reads <- read
	close(tun.reads)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(sent)
		mu.Unlock()
		if n >= len(read) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(sent) != len(read) {
		t.Fatalf("session got %d packets, want %d", len(sent), len(read))
	}
	for i := range read {
		if !bytes.Equal(sent[i], read[i]) {
			t.Fatalf("segment %d differs or is out of order", i)
		}
	}
}
