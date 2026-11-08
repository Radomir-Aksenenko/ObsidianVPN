package obsidian

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
	"time"
)

// newBatchPair returns a server session whose client address is already known and the client
// channel that receives from it.
func newBatchPair(t *testing.T, padding bool) (*UDPSession, *UDPChannel) {
	t.Helper()
	srvConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srvConn.Close() })

	var sk SessionKeys
	_, _ = rand.Read(sk.ClientKey[:])
	_, _ = rand.Read(sk.ServerKey[:])
	_, _ = rand.Read(sk.SessionID[:])

	sess, err := NewUDPMux(srvConn).RegisterSession(DeriveUDPKeys(&sk, false))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sess.Close)

	cliConn, err := net.DialUDP("udp4", nil, srvConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cliConn.Close() })
	ch, err := NewUDPChannel(cliConn, DeriveUDPKeys(&sk, true))
	if err != nil {
		t.Fatal(err)
	}
	sess.clientAddr.Store(cliConn.LocalAddr().(*net.UDPAddr))
	sess.UseBucketPadding, ch.UseBucketPadding = padding, padding
	return sess, ch
}

// batchPayloads mixes equal-size runs, a shorter tail, a larger packet that must start a new
// run, and small packets, the shapes SendBatch groups differently.
func batchPayloads() [][]byte {
	sizes := []int{1300, 1300, 1300, 1300, 700, 1300, 1300, 1380, 64, 64, 1300, 40, 1300, 1300}
	out := make([][]byte, len(sizes))
	for i, n := range sizes {
		out[i] = make([]byte, n)
		_, _ = rand.Read(out[i])
		out[i][0] = byte(i)
	}
	return out
}

func recvAll(t *testing.T, ch *UDPChannel, want [][]byte) {
	t.Helper()
	_ = ch.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	for i, w := range want {
		n, err := ch.Recv(buf)
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		if !bytes.Equal(buf[:n], w) {
			t.Fatalf("packet %d: got %d bytes (first 0x%02x), want %d bytes (first 0x%02x)", i, n, buf[0], len(w), w[0])
		}
	}
}

func TestUDPSessionSendBatchDeliversInOrder(t *testing.T) {
	for _, padding := range []bool{false, true} {
		sess, ch := newBatchPair(t, padding)
		payloads := batchPayloads()
		sent, err := sess.SendBatch(payloads)
		if err != nil || sent != len(payloads) {
			t.Fatalf("padding=%v: SendBatch sent %d of %d: %v", padding, sent, len(payloads), err)
		}
		recvAll(t, ch, payloads)
	}
}

func TestUDPSessionSendBatchUnknownClient(t *testing.T) {
	sess, _ := newBatchPair(t, false)
	sess.clientAddr.Store(nil)
	if _, err := sess.SendBatch(batchPayloads()); err != ErrUDPClientAddrUnknown {
		t.Fatalf("err = %v, want ErrUDPClientAddrUnknown", err)
	}
}

func benchSession(b *testing.B) *UDPSession {
	srvConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { srvConn.Close() })
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { sink.Close() })
	go func() {
		buf := make([]byte, 65536)
		for {
			if _, _, err := sink.ReadFromUDP(buf); err != nil {
				return
			}
		}
	}()
	var sk SessionKeys
	_, _ = rand.Read(sk.ServerKey[:])
	sess, err := NewUDPMux(srvConn).RegisterSession(DeriveUDPKeys(&sk, false))
	if err != nil {
		b.Fatal(err)
	}
	sess.clientAddr.Store(sink.LocalAddr().(*net.UDPAddr))
	return sess
}

// Per-packet cost of the downlink: 32 full-size packets per turn, sent one by one or batched.
func BenchmarkUDPSessionDownlink(b *testing.B) {
	payloads := make([][]byte, 32)
	for i := range payloads {
		payloads[i] = make([]byte, 1380)
	}
	b.Run("Send", func(b *testing.B) {
		sess := benchSession(b)
		b.SetBytes(int64(1380 * len(payloads)))
		for b.Loop() {
			for _, p := range payloads {
				_ = sess.Send(p)
			}
		}
	})
	b.Run("SendBatch", func(b *testing.B) {
		sess := benchSession(b)
		b.SetBytes(int64(1380 * len(payloads)))
		for b.Loop() {
			_, _ = sess.SendBatch(payloads)
		}
	})
}
