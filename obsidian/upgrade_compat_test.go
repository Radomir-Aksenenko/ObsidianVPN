package obsidian

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
	"time"
)

func TestMaskedSessionIDHasNoPlainTimestamp(t *testing.T) {
	authKey := []byte("reality-test-auth-key-32-bytes!!")
	var zeroPrefixes int
	for i := 0; i < 64; i++ {
		id, err := GenerateMaskedSessionID(authKey, "example.com")
		if err != nil {
			t.Fatal(err)
		}
		ts := id[AuthNonceSize : AuthNonceSize+AuthTimestampSize]
		if bytes.Equal(ts[:4], []byte{0, 0, 0, 0}) {
			zeroPrefixes++
		}
	}
	// A plain 64-bit Unix time always starts with four zero bytes.
	if zeroPrefixes != 0 {
		t.Fatalf("%d of 64 session IDs kept the zero prefix of a plain timestamp", zeroPrefixes)
	}
}

// A new server must keep accepting old clients, and new clients must reach old servers.
func TestSessionIDFormatsAcrossVersions(t *testing.T) {
	authKey := []byte("reality-test-auth-key-32-bytes!!")
	const sni = "example.com"

	plain, err := GenerateSessionID(authKey, sni)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifySessionID(plain[:], sni, authKey, 0) {
		t.Fatal("new server rejected an old client's SessionID")
	}

	masked, err := GenerateMaskedSessionID(authKey, sni)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifySessionID(masked[:], sni, authKey, 0) {
		t.Fatal("new server rejected a masked SessionID")
	}
	if VerifySessionID(masked[:], "other.example.com", authKey, 0) {
		t.Fatal("masked SessionID accepted for another SNI")
	}
	if VerifySessionID(masked[:], sni, []byte("another-auth-key-another-auth-ke"), 0) {
		t.Fatal("masked SessionID accepted with another key")
	}

	stale, err := generateMaskedSessionIDAt(authKey, sni, time.Now().Unix()-3600)
	if err != nil {
		t.Fatal(err)
	}
	if VerifySessionID(stale[:], sni, authKey, 60) {
		t.Fatal("stale masked SessionID accepted")
	}
}

func TestRealityAuthSelector(t *testing.T) {
	var s RealityAuthSelector
	if s.Legacy() {
		t.Fatal("must start with the masked format")
	}

	// An old server turns the masked attempt down, and the next one uses the format it knows.
	s.Reject()
	if !s.Legacy() {
		t.Fatal("must try the legacy format after a reject")
	}
	s.Confirm()

	// Once a format worked, a couple of rejects must not change it.
	s.Reject()
	s.Reject()
	if !s.Legacy() {
		t.Fatal("confirmed format changed on two rejects")
	}
	// A longer run can mean that the server was rolled back.
	s.Reject()
	if s.Legacy() {
		t.Fatal("selector never retried the other format")
	}
}

// A client must not stay on the plain timestamp after its server was updated.
func TestRealityAuthSelectorLeavesLegacyOnUpdatedServer(t *testing.T) {
	var s RealityAuthSelector
	s.Reject()
	s.Legacy()
	s.Confirm()

	for i := 0; i < legacyProbeEvery*2; i++ {
		if !s.Legacy() {
			s.Confirm() // the updated server accepted the masked probe
			if s.Legacy() {
				t.Fatal("selector went back to legacy after a masked success")
			}
			return
		}
		s.Confirm()
	}
	t.Fatal("selector never probed the masked format")
}

// A failed probe against a server that is still old must not cost the working format.
func TestRealityAuthSelectorKeepsLegacyWhenProbeFails(t *testing.T) {
	var s RealityAuthSelector
	s.Reject()
	s.Legacy()
	s.Confirm()

	for i := 0; i < legacyProbeEvery*3; i++ {
		if !s.Legacy() {
			s.Reject()
			continue
		}
		s.Confirm()
	}
	if !s.Legacy() {
		t.Fatal("failed probes moved the client off the format its server accepts")
	}
}

func TestDialHoppingUDPSurvivesPortChange(t *testing.T) {
	var sk SessionKeys
	_, _ = rand.Read(sk.ClientKey[:])
	_, _ = rand.Read(sk.ServerKey[:])
	_, _ = rand.Read(sk.SessionID[:])

	listen := func() (*net.UDPConn, *UDPChannel) {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		ch, err := NewUDPChannel(conn, DeriveUDPKeys(&sk, false))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ch.Close() })
		return conn, ch
	}
	connA, srvA := listen()
	connB, srvB := listen()

	cliConn, first, err := DialHoppingUDP("udp4", connA.LocalAddr().String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	cli, err := NewUDPChannel(cliConn, DeriveUDPKeys(&sk, true))
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	cli.SwitchDestination(first)

	expect := func(ch *UDPChannel, conn *net.UDPConn, want string) {
		t.Helper()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 2048)
		n, err := ch.Recv(buf)
		if err != nil {
			t.Fatalf("recv %q: %v", want, err)
		}
		if string(buf[:n]) != want {
			t.Fatalf("got %q, want %q", buf[:n], want)
		}
	}

	if err := cli.Send([]byte("before-hop")); err != nil {
		t.Fatalf("send before hop: %v", err)
	}
	expect(srvA, connA, "before-hop")

	cli.SetRemotePort(connB.LocalAddr().(*net.UDPAddr).Port)
	if err := cli.Send([]byte("after-hop")); err != nil {
		t.Fatalf("send after hop: %v", err)
	}
	expect(srvB, connB, "after-hop")
}

// A connected socket has no way to change its peer. The hop must be ignored, because writing
// to another address on it fails every time and pushes the session off UDP.
func TestConnectedSocketIgnoresPortChange(t *testing.T) {
	var sk SessionKeys
	_, _ = rand.Read(sk.ClientKey[:])
	_, _ = rand.Read(sk.ServerKey[:])
	_, _ = rand.Read(sk.SessionID[:])

	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	conn, err := net.DialUDP("udp4", nil, srv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	ch, err := NewUDPChannel(conn, DeriveUDPKeys(&sk, true))
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Close()

	ch.SetRemotePort(srv.LocalAddr().(*net.UDPAddr).Port + 1)
	ch.SwitchDestination(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	if err := ch.Send([]byte("still-up")); err != nil {
		t.Fatalf("send after ignored hop: %v", err)
	}
}
