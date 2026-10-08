package main

import (
	"encoding/binary"
	"sync"
	"testing"
	"time"
)

type recordingTUN struct {
	mu     sync.Mutex
	writes [][]byte
}

func (r *recordingTUN) Read(p []byte) (int, error) { select {} }
func (r *recordingTUN) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.writes = append(r.writes, append([]byte(nil), p...))
	return len(p), nil
}

func TestClientSinkRejectsIPv6WhenServerIPv6Disabled(t *testing.T) {
	tun := &recordingTUN{}
	router := newTunRouter(tun)

	var mu sync.Mutex
	var toClient [][]byte
	route := router.registerSession("sink", func(p []byte) error {
		mu.Lock()
		toClient = append(toClient, append([]byte(nil), p...))
		mu.Unlock()
		return nil
	})
	defer route.Close()

	sink := newClientSink(route, false)

	client := [16]byte{0xfd, 0x00, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}
	remote := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	seg := make([]byte, 20)
	binary.BigEndian.PutUint16(seg[0:2], 40000)
	binary.BigEndian.PutUint16(seg[2:4], 443)
	binary.BigEndian.PutUint32(seg[4:8], 7)
	seg[12] = 5 << 4
	seg[13] = 0x02
	pkt := make([]byte, 60)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], 20)
	pkt[6] = 6
	pkt[7] = 64
	copy(pkt[8:24], client[:])
	copy(pkt[24:40], remote[:])
	copy(pkt[40:], seg)

	if _, err := sink.Write(pkt); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(toClient)
		mu.Unlock()
		if n >= 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(toClient) != 1 {
		t.Fatalf("expected one reject sent to client, got %d", len(toClient))
	}
	reply := toClient[0]
	if reply[40+13] != 0x14 {
		t.Fatalf("flags = %#x, want RST|ACK", reply[40+13])
	}
	if binary.BigEndian.Uint32(reply[40+8:40+12]) != 8 {
		t.Fatal("ack must be SYN seq + 1")
	}
	tun.mu.Lock()
	defer tun.mu.Unlock()
	if len(tun.writes) != 0 {
		t.Fatal("rejected IPv6 packet must not reach the server TUN")
	}
}

func TestClientSinkPassesIPv4ToTUN(t *testing.T) {
	tun := &recordingTUN{}
	router := newTunRouter(tun)
	route := router.registerSession("sink4", func([]byte) error { return nil })
	defer route.Close()

	sink := newClientSink(route, false)
	v4 := make([]byte, 20)
	v4[0] = 0x45
	binary.BigEndian.PutUint16(v4[2:4], 20)
	v4[9] = 17
	copy(v4[12:16], []byte{10, 8, 0, 2})
	copy(v4[16:20], []byte{1, 1, 1, 1})
	if _, err := sink.Write(v4); err != nil {
		t.Fatal(err)
	}
	tun.mu.Lock()
	defer tun.mu.Unlock()
	if len(tun.writes) != 1 {
		t.Fatalf("expected IPv4 packet to reach TUN, got %d writes", len(tun.writes))
	}
}
