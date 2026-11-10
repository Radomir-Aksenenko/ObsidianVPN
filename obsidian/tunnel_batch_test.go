package obsidian

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func newTunnelPair(t *testing.T, tweak func(*TunnelConfig)) (client, server *Tunnel) {
	t.Helper()
	keyC, ivC := [KeySize]byte{1}, [NonceSize]byte{2}
	keyS, ivS := [KeySize]byte{3}, [NonceSize]byte{4}
	mk := func(k [KeySize]byte, iv [NonceSize]byte) *Cipher {
		c, err := NewCipher(k, iv)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	cliConn, srvConn := net.Pipe()
	cfg := DefaultTunnelConfig()
	cfg.Jitter = JitterOff
	cfg.NoiseMinInterval, cfg.NoiseMaxInterval = time.Hour, time.Hour
	cfg.KeepaliveInterval, cfg.KeepaliveJitter = time.Hour, 0
	if tweak != nil {
		tweak(&cfg)
	}
	client = NewTunnel(cliConn, NewStreamFramer(mk(keyC, ivC), mk(keyS, ivS)), cfg)
	server = NewTunnel(srvConn, NewStreamFramer(mk(keyS, ivS), mk(keyC, ivC)), cfg)
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}

// A batch must arrive as the same packets, in order, mixed with single sends, including a
// batch larger than tunnelBatchLimit that is flushed in several writes.
func TestTunnelSendDataBatchRoundTrip(t *testing.T) {
	t.Run("default", func(t *testing.T) { testTunnelBatch(t, nil) })
	t.Run("bucket padding", func(t *testing.T) {
		testTunnelBatch(t, func(c *TunnelConfig) {
			c.UseBucketPadding, c.BucketMTU, c.MaxTrailer = true, 1360, 64
			c.DataPadMin, c.DataPadMax = 0, 255
		})
	})
}

func testTunnelBatch(t *testing.T, tweak func(*TunnelConfig)) {
	client, server := newTunnelPair(t, tweak)

	var want [][]byte
	var batches [][][]byte
	for b := 0; b < 3; b++ {
		var batch [][]byte
		for i := 0; i < 60; i++ {
			p := bytes.Repeat([]byte{byte(b*60 + i)}, 40+(i*97)%1400)
			batch = append(batch, p)
		}
		batches = append(batches, batch)
	}

	errc := make(chan error, 1)
	go func() {
		for i, batch := range batches {
			if n, err := client.SendDataBatch(batch); err != nil || n != len(batch) {
				errc <- err
				return
			}
			if err := client.SendData([]byte{0xEE, byte(i)}); err != nil {
				errc <- err
				return
			}
		}
		errc <- nil
	}()
	for i, batch := range batches {
		want = append(want, batch...)
		want = append(want, []byte{0xEE, byte(i)})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for i, w := range want {
		got, err := server.RecvData(ctx)
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		if !bytes.Equal(got, w) {
			t.Fatalf("packet %d: got %d bytes, want %d", i, len(got), len(w))
		}
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

// Sender cost over loopback TCP: 32 full-size packets per turn, one write each or one per batch.
func BenchmarkTunnelSend(b *testing.B) {
	run := func(b *testing.B, batched, records bool) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			b.Fatal(err)
		}
		defer ln.Close()
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 256*1024)
			for {
				if _, err := c.Read(buf); err != nil {
					return
				}
			}
		}()
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			b.Fatal(err)
		}
		setOptimalTCPConn(c.(*net.TCPConn))
		if records {
			c, err = newRealityRecordConn(c, make([]byte, 32), make([]byte, 32), true)
			if err != nil {
				b.Fatal(err)
			}
		}
		enc, _ := NewCipher([KeySize]byte{1}, [NonceSize]byte{2})
		dec, _ := NewCipher([KeySize]byte{3}, [NonceSize]byte{4})
		cfg := DefaultTunnelConfig()
		cfg.Jitter = JitterOff
		cfg.NoiseMinInterval, cfg.NoiseMaxInterval = time.Hour, time.Hour
		cfg.KeepaliveInterval, cfg.KeepaliveJitter = time.Hour, 0
		tun := NewTunnel(c, NewStreamFramer(enc, dec), cfg)
		defer tun.Close()
		pkts := make([][]byte, 32)
		for i := range pkts {
			pkts[i] = make([]byte, 1380)
		}
		b.SetBytes(int64(32 * 1380))
		for b.Loop() {
			if batched {
				_, _ = tun.SendDataBatch(pkts)
			} else {
				for _, p := range pkts {
					_ = tun.SendData(p)
				}
			}
		}
	}
	b.Run("SendData", func(b *testing.B) { run(b, false, false) })
	b.Run("SendDataBatch", func(b *testing.B) { run(b, true, false) })
	b.Run("SendData/records", func(b *testing.B) { run(b, false, true) })
	b.Run("SendDataBatch/records", func(b *testing.B) { run(b, true, true) })
}

// BenchmarkTunnelRoundTrip moves batches through a sending and a receiving tunnel over loopback
// TCP, raw and inside TLS records, so the cost of record framing on both ends shows up.
func BenchmarkTunnelRoundTrip(b *testing.B) {
	run := func(b *testing.B, mode string) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			b.Fatal(err)
		}
		defer ln.Close()
		key, _ := GenerateKeypair()
		if mode == "native" {
			cover := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			cover.EnableHTTP2 = true
			cover.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
			cover.StartTLS()
			defer cover.Close()
			ln, err = NewNativeRealityListener(context.Background(), ln, NativeRealityServerConfig{Target: cover.Listener.Addr().String(), ServerNames: []string{"example.com"}, PrivateKey: hex.EncodeToString(key.Private[:]), ShortIDs: []string{"1234567890abcdef"}})
			if err != nil {
				b.Fatal(err)
			}
			defer ln.Close()
		}
		cfg := DefaultTunnelConfig()
		cfg.Jitter = JitterOff
		cfg.NoiseMinInterval, cfg.NoiseMaxInterval = time.Hour, time.Hour
		cfg.KeepaliveInterval, cfg.KeepaliveJitter = time.Hour, 0
		k1, k2 := [KeySize]byte{1}, [KeySize]byte{3}
		n1, n2 := [NonceSize]byte{2}, [NonceSize]byte{4}
		const batch = 32
		got := make(chan int, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if tcp, ok := c.(*net.TCPConn); ok {
				setOptimalTCPConn(tcp)
			}
			if mode == "records" {
				c, err = newRealityRecordConn(c, make([]byte, 32), make([]byte, 32), false)
				if err != nil {
					return
				}
			}
			enc, _ := NewCipher(k2, n2)
			dec, _ := NewCipher(k1, n1)
			rx := NewTunnel(c, NewStreamFramer(enc, dec), cfg)
			defer rx.Close()
			n := 0
			for {
				if _, err := rx.RecvData(nil); err != nil {
					got <- n
					return
				}
				n++
			}
		}()
		var c net.Conn
		if mode == "native" {
			_, port, _ := net.SplitHostPort(ln.Addr().String())
			c, err = DialNativeReality(context.Background(), ClientTransportConfig{ServerHost: "127.0.0.1", ServerPort: port, SNI: "example.com"}, hex.EncodeToString(key.Public[:]), "1234567890abcdef", "chrome")
		} else {
			c, err = net.Dial("tcp", ln.Addr().String())
		}
		if err != nil {
			b.Fatal(err)
		}
		if tcp, ok := c.(*net.TCPConn); ok {
			setOptimalTCPConn(tcp)
		}
		if mode == "records" {
			c, err = newRealityRecordConn(c, make([]byte, 32), make([]byte, 32), true)
			if err != nil {
				b.Fatal(err)
			}
		}
		enc, _ := NewCipher(k1, n1)
		dec, _ := NewCipher(k2, n2)
		tx := NewTunnel(c, NewStreamFramer(enc, dec), cfg)
		pkts := make([][]byte, batch)
		for i := range pkts {
			pkts[i] = make([]byte, 1380)
		}
		b.SetBytes(int64(batch * 1380))
		for b.Loop() {
			if _, err := tx.SendDataBatch(pkts); err != nil {
				b.Fatal(err)
			}
		}
		tx.Close()
		if n := <-got; n != b.N*batch {
			b.Fatalf("received %d packets, expected %d", n, b.N*batch)
		}
	}
	b.Run("raw", func(b *testing.B) { run(b, "raw") })
	b.Run("records", func(b *testing.B) { run(b, "records") })
	b.Run("native", func(b *testing.B) { run(b, "native") })
}

// writeSizes records the size of every write and discards the data.
type writeSizes struct {
	net.Conn
	mu    sync.Mutex
	sizes []int
}

func (w *writeSizes) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.sizes = append(w.sizes, len(p))
	w.mu.Unlock()
	return len(p), nil
}

func (w *writeSizes) take() []int {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := w.sizes
	w.sizes = nil
	return s
}

// A write made only of small packets must not carry their exact size; a write that carries a
// bulk packet, such as a split 1420 + 120 pair, gets no padding at all.
func TestSmallWritesArePadded(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	w := &writeSizes{Conn: a}
	c, err := NewCipher([KeySize]byte{1}, [NonceSize]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultTunnelConfig()
	cfg.Jitter = JitterOff
	cfg.NoiseMinInterval, cfg.NoiseMaxInterval = time.Hour, time.Hour
	cfg.KeepaliveInterval, cfg.KeepaliveJitter = time.Hour, 0
	tun := NewTunnel(w, NewStreamFramer(c, c), cfg)
	defer tun.Close()
	w.take()

	for i := 0; i < 64; i++ {
		if err := tun.SendData(make([]byte, 52)); err != nil {
			t.Fatal(err)
		}
	}
	small := map[int]bool{}
	for _, n := range w.take() {
		small[n] = true
	}
	if len(small) < 8 {
		t.Fatalf("lone 52-byte packets made only %d write sizes", len(small))
	}
	for i := 0; i < 16; i++ {
		if _, err := tun.SendDataBatch([][]byte{make([]byte, 1420), make([]byte, 120)}); err != nil {
			t.Fatal(err)
		}
	}
	bulk := map[int]bool{}
	for _, n := range w.take() {
		bulk[n] = true
	}
	if len(bulk) != 1 {
		t.Fatalf("writes with a bulk packet got padding: %d sizes", len(bulk))
	}
}
