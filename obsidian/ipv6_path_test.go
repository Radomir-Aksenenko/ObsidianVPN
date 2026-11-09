package obsidian

import (
	"bytes"
	"crypto/rand"
	"net"
	"strconv"
	"testing"
	"time"
)

func requireIPv6Loopback(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	ln.Close()
}

// The full record-mode REALITY handshake and the masked UDP data path over IPv6, with the
// server UDP socket bound dual-stack the way cmd/server now binds it.
func TestRealityAndMaskedUDPOverIPv6(t *testing.T) {
	requireIPv6Loopback(t)
	kp, _ := GenerateKeypair()
	ckp, _ := GenerateKeypair()
	authKey := []byte("reality-shared-auth-key-32-byte")

	ln, err := ListenObsidianREALITY("::1", "0", RealityDemuxConfig{
		FallbackTarget: startTLSTarget(t), AuthKey: authKey,
		HandshakeTimeout: 3 * time.Second, DialTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	isRecord := make(chan bool, 1)
	srvErr := make(chan error, 1)
	go obsidianServerSide(ln, kp, isRecord, srvErr)

	conn, err := DialObsidianREALITY(ClientTransportConfig{
		ServerHost: "::1", ServerPort: port, SNI: "example.com",
		RealityEnabled: true, RealityAuthKey: authKey,
	})
	if err != nil {
		t.Fatalf("dial over IPv6: %v", err)
	}
	defer conn.Close()
	if !<-isRecord {
		t.Fatal("server side not in record mode")
	}
	hs, _ := NewClientHandshakeWithStaticKey(kp.Public, ckp, DefaultObfuscationConfig())
	hello, _ := hs.BuildHello()
	frame, _ := BuildHelloFrame(kp.Public, hello)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	srvHello, err := ReadHelloFrame(conn, kp.Public, ClientHelloScanLimit, 8192)
	if err != nil {
		t.Fatal(err)
	}
	framer, err := hs.ProcessServerHello(srvHello)
	if err != nil {
		t.Fatal(err)
	}
	tun := NewTunnel(conn, framer, DefaultTunnelConfig())
	defer tun.Close()
	if err := tun.SendData([]byte("v6")); err != nil {
		t.Fatal(err)
	}
	if got, err := tun.RecvData(nil); err != nil || string(got) != "v6" {
		t.Fatalf("tcp echo over IPv6: %q %v", got, err)
	}

	// UDP: dual-stack server socket, client dialed with "udp" to the IPv6 literal.
	srvUDP, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer srvUDP.Close()
	mux := NewUDPMux(srvUDP)
	mux.SetRouteMaskKey(RealityRouteMaskKey(authKey))
	go mux.Run()
	sess, err := mux.RegisterSession(DeriveUDPKeys(hs.SessionKeys, false))
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	sess.UseMaskedFormat()

	udpPort := srvUDP.LocalAddr().(*net.UDPAddr).Port
	cli, err := DialProtectedUDP("udp", net.JoinHostPort("::1", strconv.Itoa(udpPort)), nil)
	if err != nil {
		t.Fatalf("udp dial to IPv6 literal: %v", err)
	}
	ch, err := NewUDPChannel(cli, DeriveUDPKeys(hs.SessionKeys, true))
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Close()
	ch.UseMaskedFormat(RealityRouteMaskKey(authKey))

	up := make([]byte, 1200)
	_, _ = rand.Read(up)
	if err := ch.Send(up); err != nil {
		t.Fatal(err)
	}
	got, err := recvSessionTimeout(sess, 2*time.Second)
	if err != nil || !bytes.Equal(got, up) {
		t.Fatalf("udp uplink over IPv6: %v", err)
	}
	PutPacket(got)
	if err := sess.Send(up[:600]); err != nil {
		t.Fatalf("udp downlink to IPv6 client: %v", err)
	}
	_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, err := ch.Recv(buf)
	if err != nil || !bytes.Equal(buf[:n], up[:600]) {
		t.Fatalf("udp downlink over IPv6: %v", err)
	}
}
