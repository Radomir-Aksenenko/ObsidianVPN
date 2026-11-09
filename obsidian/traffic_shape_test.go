package obsidian

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func TestTrafficPaddingBudgetAndRoundTrip(t *testing.T) {
	lengths := make(map[int]bool)
	for _, n := range []int{0, 1, 64, 255, 256, 257, 1024, 1025, 1380, 1420, 2000} {
		for i := 0; i < 32; i++ {
			want := bytes.Repeat([]byte{0x42}, n)
			plain, holder := shapeUDPPayload(want)
			got, ok := unshapeUDPPayload(plain)
			if !ok || !bytes.Equal(got, want) {
				t.Fatalf("payload %d changed", n)
			}
			if n == 0 {
				if len(plain)+UDPOverhead < 60 || len(plain)+UDPOverhead > 188 {
					t.Fatal("control packet outside overhead budget")
				}
				lengths[len(plain)] = true
			} else if n > 1024 && len(plain) != n+2 {
				t.Fatal("padding taxed full bulk packets")
			}
			if n == 1420 && len(plain)+UDPOverhead+8+40 > 1500 {
				t.Fatal("native packet exceeds IPv6 MTU")
			}
			if holder != nil {
				putUDPPlainBuf(holder)
			}
		}
	}
	if len(lengths) < 2 {
		t.Fatal("control packets retained a constant length")
	}
	bad := make([]byte, 10)
	binary.BigEndian.PutUint16(bad, 100)
	if _, ok := unshapeUDPPayload(bad); ok {
		t.Fatal("accepted invalid authenticated length")
	}
}

func TestNativeUDPShapingBatchRoundTrip(t *testing.T) {
	sess, ch := newBatchPair(t, false)
	key := [KeySize]byte{1, 2, 3}
	sess.mux.SetRouteMaskKey(key)
	if !sess.UseMaskedFormat() {
		t.Fatal("missing mask")
	}
	ch.UseMaskedFormat(key)
	sess.TrafficPadding, ch.TrafficPadding = true, true
	want := batchPayloads()
	if _, err := sess.SendBatch(want); err != nil {
		t.Fatal(err)
	}
	recvAll(t, ch, want)
}

func TestNativeUDPControlHasNoConstantLength(t *testing.T) {
	sess, ch := newBatchPair(t, false)
	key := [KeySize]byte{1, 2, 3}
	sess.mux.SetRouteMaskKey(key)
	sess.UseMaskedFormat()
	sess.TrafficPadding = true
	lengths := make(map[int]bool)
	_ = ch.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	for i := 0; i < 32; i++ {
		if err := sess.Send(nil); err != nil {
			t.Fatal(err)
		}
		n, err := ch.conn.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if n < 60 || n > 188 || IsSTUNHeader(buf[:n]) {
			t.Fatalf("unexpected control wire length/header: %d", n)
		}
		lengths[n] = true
	}
	if len(lengths) < 2 {
		t.Fatal("constant control packet size")
	}
}

func TestNativeUDPUplinkAndProbeEcho(t *testing.T) {
	sess, ch := newBatchPair(t, false)
	key := [KeySize]byte{1, 2, 3}
	sess.mux.SetRouteMaskKey(key)
	sess.UseMaskedFormat()
	ch.UseMaskedFormat(key)
	sess.TrafficPadding, ch.TrafficPadding = true, true
	go sess.mux.Run()
	want := bytes.Repeat([]byte{0x45}, 1420)
	if err := ch.Send(want); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-sess.dataIn:
		if !bytes.Equal(got, want) {
			t.Fatal("uplink payload changed")
		}
		PutPacket(got)
	case <-time.After(time.Second):
		t.Fatal("shaped uplink was not routed")
	}
	// Recv must consume the randomized control reply without exposing it as IP.
	if err := ch.Send(nil); err != nil {
		t.Fatal(err)
	}
	_ = ch.conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 2048)
	type result struct {
		n   int
		err error
	}
	received := make(chan result, 1)
	go func() { n, err := ch.Recv(buf); received <- result{n, err} }()
	deadline := time.Now().Add(time.Second)
	for ch.LastAuthRecvNano() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if ch.LastAuthRecvNano() == 0 {
		t.Fatal("control echo was not authenticated")
	}
	select {
	case <-received:
		t.Fatal("control echo escaped as an IP packet")
	default:
	}
	if err := sess.Send(want); err != nil {
		t.Fatal(err)
	}
	r := <-received
	if r.err != nil || !bytes.Equal(buf[:r.n], want) {
		t.Fatalf("data after probe: %d, %v", r.n, r.err)
	}
}

func TestMaintenanceDoesNotProbeActiveBulkTraffic(t *testing.T) {
	now := time.Now()
	var schedule UDPProbeSchedule
	if schedule.Due(now, true, now.UnixNano()) {
		t.Fatal("unnecessary startup probe")
	}
	now = now.Add(time.Minute)
	if schedule.Due(now, true, now.UnixNano()) {
		t.Fatal("active data did not suppress keepalive")
	}
	if !schedule.Due(now, false, 0) {
		t.Fatal("UDP recovery must still be tried")
	}
	if schedule.Due(now, false, 0) {
		t.Fatal("recovery probe loop")
	}
	if !schedule.Due(now.Add(20*time.Second), false, 0) {
		t.Fatal("recovery never retried")
	}
	for i := 0; i < 100; i++ {
		if d := MaintenanceDelay(2 * time.Second); d < 1500*time.Millisecond || d > 2500*time.Millisecond {
			t.Fatal("health timer outside bound")
		}
	}
}
