package obsidian

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"
)

// ipv4TCP builds an IPv4 TCP segment with the given payload.
func ipv4TCP(payload []byte) []byte {
	p := make([]byte, 40+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8], p[9] = 64, 6
	p[32] = 5 << 4 // TCP data offset
	copy(p[40:], payload)
	return p
}

func ipv6TCP(payload []byte) []byte {
	p := make([]byte, 60+len(payload))
	p[0] = 0x60
	p[6] = 6
	p[52] = 5 << 4
	copy(p[60:], payload)
	return p
}

func TestLooksLikeTLSHandshake(t *testing.T) {
	hello := append([]byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01}, make([]byte, 100)...)
	cases := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"v4 client hello", ipv4TCP(hello), true},
		{"v6 client hello", ipv6TCP(hello), true},
		{"v4 app data", ipv4TCP([]byte{0x17, 0x03, 0x03, 0, 10}), false},
		{"v4 empty ack", ipv4TCP(nil), false},
		{"v4 udp", func() []byte { p := ipv4TCP(hello); p[9] = 17; return p }(), false},
		{"v4 fragment", func() []byte { p := ipv4TCP(hello); p[7] = 1; return p }(), false},
		{"truncated", ipv4TCP(hello)[:30], false},
		{"garbage", []byte{0xff}, false},
	}
	for _, c := range cases {
		if got := LooksLikeTLSHandshake(c.pkt); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

// A padded handshake packet must arrive unchanged, the NOISE frame must not reach the consumer,
// and packets after it must keep their order.
func TestHandshakePaddingRoundTrip(t *testing.T) {
	client, server := newTunnelPair(t, nil)
	hello := ipv4TCP(append([]byte{0x16, 0x03, 0x01, 0x02, 0x00}, bytes.Repeat([]byte{7}, 512)...))
	plain := ipv4TCP([]byte("plain"))
	go func() {
		_, _ = client.SendDataBatch([][]byte{hello, plain})
		_ = client.SendData(hello)
		_ = client.SendData(plain)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	buf := make([]byte, 4096)
	for i, want := range [][]byte{hello, plain, hello, plain} {
		n, err := server.RecvDataInto(ctx, buf)
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		if !bytes.Equal(buf[:n], want) {
			t.Fatalf("packet %d changed", i)
		}
	}
}

func TestHandshakePadBudgetCapsCost(t *testing.T) {
	var b handshakePadBudget
	now := time.Unix(1000, 0)
	spent := 0
	for b.take(1000, now) {
		spent += 1000
	}
	if spent > hsBudgetBurst {
		t.Fatalf("spent %d over the burst", spent)
	}
	if b.take(1000, now.Add(100*time.Millisecond)) {
		t.Fatal("refill faster than the rate")
	}
	if !b.take(1000, now.Add(1500*time.Millisecond)) {
		t.Fatal("budget did not refill")
	}
}
