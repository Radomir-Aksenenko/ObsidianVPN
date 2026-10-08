package client

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"obsidian/obsidian"
)

// bufWriter records what the engine writes back to the TUN.
type bufWriter struct{ data [][]byte }

func (w *bufWriter) Write(p []byte) (int, error) {
	w.data = append(w.data, append([]byte(nil), p...))
	return len(p), nil
}

func newIPv6DisabledSession(t *testing.T) *Session {
	t.Helper()
	kp, err := obsidian.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSession(&obsidian.ClientConfig{
		ServerPublicKey: hex.EncodeToString(kp.Public[:]),
		ServerHost:      "127.0.0.1",
		ServerPort:      "59999",
		EnableIPv6:      false,
	}, WithAutoReconnect(false))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestEngineRejectsIPv6WithRSTWhenDisabled(t *testing.T) {
	s := newIPv6DisabledSession(t)
	client := [16]byte{0xfd, 0x00, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}
	remote := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}

	seg := make([]byte, 20)
	binary.BigEndian.PutUint16(seg[0:2], 40000)
	binary.BigEndian.PutUint16(seg[2:4], 443)
	binary.BigEndian.PutUint32(seg[4:8], 99)
	seg[12] = 5 << 4
	seg[13] = 0x02 // SYN
	pkt := make([]byte, 60)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], 20)
	pkt[6] = 6
	pkt[7] = 64
	copy(pkt[8:24], client[:])
	copy(pkt[24:40], remote[:])
	copy(pkt[40:], seg)

	w := &bufWriter{}
	s.rejectIPv6(w, pkt, make([]byte, obsidian.IPv6RejectBufSize))
	if len(w.data) != 1 {
		t.Fatalf("expected exactly one reject written to TUN, got %d", len(w.data))
	}
	reply := w.data[0]
	if !bytes.Equal(reply[8:24], remote[:]) || !bytes.Equal(reply[24:40], client[:]) {
		t.Fatal("reply addresses are not swapped")
	}
	if reply[40+13] != 0x14 { // RST|ACK
		t.Fatalf("flags = %#x, want RST|ACK", reply[40+13])
	}
	if binary.BigEndian.Uint32(reply[40+8:40+12]) != 100 {
		t.Fatal("ack must be SYN seq + 1")
	}
}
