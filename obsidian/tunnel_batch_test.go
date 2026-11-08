package obsidian

import (
	"bytes"
	"context"
	"net"
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
	run := func(b *testing.B, batched bool) {
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
	b.Run("SendData", func(b *testing.B) { run(b, false) })
	b.Run("SendDataBatch", func(b *testing.B) { run(b, true) })
}
