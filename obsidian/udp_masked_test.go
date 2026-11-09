package obsidian

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
	"time"
)

// captureDatagrams sends count equal-size payloads through ch and returns the raw datagrams.
func captureDatagrams(t *testing.T, masked bool, count int) [][]byte {
	t.Helper()
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	cli, err := net.DialUDP("udp4", nil, sink.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	var sk SessionKeys
	_, _ = rand.Read(sk.ClientKey[:])
	_, _ = rand.Read(sk.ServerKey[:])
	_, _ = rand.Read(sk.SessionID[:])
	ch, err := NewUDPChannel(cli, DeriveUDPKeys(&sk, true))
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Close()
	if masked {
		var pub [KeySize]byte
		_, _ = rand.Read(pub[:])
		ch.UseMaskedFormat(pub)
	}
	payload := make([]byte, 1200)
	out := make([][]byte, 0, count)
	buf := make([]byte, 2048)
	_ = sink.SetReadDeadline(time.Now().Add(3 * time.Second))
	for i := 0; i < count; i++ {
		if err := ch.Send(payload); err != nil {
			t.Fatal(err)
		}
		n, err := sink.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, append([]byte(nil), buf[:n]...))
	}
	return out
}

// constantOffsets lists byte offsets that hold the same value in every datagram.
func constantOffsets(dgs [][]byte) []int {
	var consts []int
	for off := 0; off < len(dgs[0]); off++ {
		same := true
		for _, d := range dgs[1:] {
			if off >= len(d) || d[off] != dgs[0][off] {
				same = false
				break
			}
		}
		if same {
			consts = append(consts, off)
		}
	}
	return consts
}

func TestMaskedUDPFormatHasNoConstantBytes(t *testing.T) {
	old := captureDatagrams(t, false, 64)
	if c := constantOffsets(old); len(c) == 0 {
		t.Fatal("sanity: the STUN format should have constant bytes (cookie, RouteTag)")
	} else {
		t.Logf("old format: %d constant byte offsets %v", len(c), c)
	}
	masked := captureDatagrams(t, true, 64)
	if c := constantOffsets(masked); len(c) != 0 {
		t.Fatalf("masked format has constant bytes at offsets %v", c)
	}
	if IsSTUNHeader(masked[0]) && IsSTUNHeader(masked[1]) {
		t.Fatal("masked datagrams still carry a STUN header")
	}
	if len(masked[0]) != len(old[0])-STUNHeaderSize {
		t.Fatalf("masked datagram is %d bytes, want %d", len(masked[0]), len(old[0])-STUNHeaderSize)
	}
}

// One mux serves masked and old-format clients side by side, in both directions.
func TestUDPMuxServesMaskedAndOldClients(t *testing.T) {
	srvConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srvConn.Close()
	var serverPub [KeySize]byte
	_, _ = rand.Read(serverPub[:])
	mux := NewUDPMux(srvConn)
	mux.SetRouteMaskKey(serverPub)
	go mux.Run()

	for _, masked := range []bool{true, false} {
		var sk SessionKeys
		_, _ = rand.Read(sk.ClientKey[:])
		_, _ = rand.Read(sk.ServerKey[:])
		_, _ = rand.Read(sk.SessionID[:])
		sess, err := mux.RegisterSession(DeriveUDPKeys(&sk, false))
		if err != nil {
			t.Fatal(err)
		}
		defer sess.Close()
		cli, err := net.DialUDP("udp4", nil, srvConn.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		ch, err := NewUDPChannel(cli, DeriveUDPKeys(&sk, true))
		if err != nil {
			t.Fatal(err)
		}
		defer ch.Close()
		if masked {
			ch.UseMaskedFormat(serverPub)
			if !sess.UseMaskedFormat() {
				t.Fatal("mux has a route mask key")
			}
		}

		for i := 0; i < 20; i++ {
			up := make([]byte, 100+i)
			_, _ = rand.Read(up)
			if err := ch.Send(up); err != nil {
				t.Fatal(err)
			}
			got, err := recvSessionTimeout(sess, 2*time.Second)
			if err != nil {
				t.Fatalf("masked=%v uplink %d: %v", masked, i, err)
			}
			if !bytes.Equal(got, up) {
				t.Fatalf("masked=%v uplink %d mismatch", masked, i)
			}
			PutPacket(got)

			down := make([]byte, 200+i)
			_, _ = rand.Read(down)
			if err := sess.Send(down); err != nil {
				t.Fatal(err)
			}
			_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 2048)
			n, err := ch.Recv(buf)
			if err != nil {
				t.Fatalf("masked=%v downlink %d: %v", masked, i, err)
			}
			if !bytes.Equal(buf[:n], down) {
				t.Fatalf("masked=%v downlink %d mismatch", masked, i)
			}
		}
	}
}

func recvSessionTimeout(s *UDPSession, d time.Duration) ([]byte, error) {
	type res struct {
		b   []byte
		err error
	}
	c := make(chan res, 1)
	go func() {
		b, err := s.Recv()
		c <- res{b, err}
	}()
	select {
	case r := <-c:
		return r.b, r.err
	case <-time.After(d):
		return nil, net.ErrClosed
	}
}
