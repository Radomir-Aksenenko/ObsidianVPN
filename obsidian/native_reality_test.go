package obsidian

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	xreality "github.com/xtls/xray-core/transport/internet/reality"
)

func TestNativeRealityCompletedTLSAndInnerHandshake(t *testing.T) {
	cover := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ordinary-cover-site") }))
	cover.EnableHTTP2 = true
	cover.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	cover.StartTLS()
	defer cover.Close()
	transportKey, _ := GenerateKeypair()
	innerKey, _ := GenerateKeypair()
	shortID := "1234567890abcdef"
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := NewNativeRealityListener(ctx, raw, NativeRealityServerConfig{
		Target: cover.Listener.Addr().String(), ServerNames: []string{"example.com"},
		PrivateKey: hex.EncodeToString(transportKey.Private[:]), ShortIDs: []string{shortID},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	serverResult := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if !NativeRealityMode(conn) {
			serverResult <- io.ErrUnexpectedEOF
			return
		}
		hello, err := ReadHelloFrame(conn, innerKey.Public, 4096, 8192)
		if err != nil {
			serverResult <- err
			return
		}
		hs, err := NewServerHandshake(innerKey.Private, innerKey.Public, nil)
		if err != nil {
			serverResult <- err
			return
		}
		reply, framer, err := hs.ProcessClientHello(hello)
		if err != nil {
			serverResult <- err
			return
		}
		frame, _ := BuildHelloFrame(innerKey.Public, reply)
		if _, err := conn.Write(frame); err != nil {
			serverResult <- err
			return
		}
		tunnel := NewTunnel(conn, framer, DefaultTunnelConfig())
		defer tunnel.Close()
		data, err := tunnel.RecvData(nil)
		if err == nil {
			err = tunnel.SendData(data)
		}
		serverResult <- err
	}()
	conn, err := DialNativeReality(context.Background(), ClientTransportConfig{ServerHost: "127.0.0.1", ServerPort: port, SNI: "example.com"}, hex.EncodeToString(transportKey.Public[:]), shortID, "chrome")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	uc, ok := conn.(*nativeRealityConn).Conn.(*xreality.UConn)
	if !ok || !uc.Verified || !uc.ConnectionState().HandshakeComplete || uc.ConnectionState().Version != tls.VersionTLS13 {
		t.Fatal("native mode did not complete and authenticate the upstream TLS 1.3 handshake")
	}
	client, _ := NewClientHandshake(innerKey.Public)
	hello, _ := client.BuildHello()
	frame, _ := BuildHelloFrame(innerKey.Public, hello)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	reply, err := ReadHelloFrame(conn, innerKey.Public, ClientHelloScanLimit, 8192)
	if err != nil {
		select {
		case serverErr := <-serverResult:
			t.Fatalf("client read: %v; server: %v", err, serverErr)
		case <-time.After(time.Second):
			t.Fatalf("client read: %v; server still pending", err)
		}
	}
	framer, err := client.ProcessServerHello(reply)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Time{})
	tunnel := NewTunnel(conn, framer, DefaultTunnelConfig())
	defer tunnel.Close()
	want := bytes.Repeat([]byte("native-TLS-and-inner-MLKEM"), 30)
	if err := tunnel.SendData(want); err != nil {
		t.Fatal(err)
	}
	got, err := tunnel.RecvData(nil)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("round trip: %q, %v", got, err)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}

	// An ordinary HTTPS prober reaches the real cover HTTP service, not a fake
	// certificate or an Obsidian response. This request has no REALITY credential.
	host := ln.Addr().String()
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "example.com"}, ForceAttemptHTTP2: true}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	resp, err := httpClient.Get("https://" + host + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "ordinary-cover-site" || resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("cover fallback: %s, %v", body, err)
	}
	// Wrong credentials cannot return a usable tunnel; cancel bounds the
	// upstream fallback/spider path as well as the TLS handshake itself.
	badCtx, stop := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer stop()
	bad, err := DialNativeReality(badCtx, ClientTransportConfig{ServerHost: "127.0.0.1", ServerPort: port, SNI: "example.com"}, hex.EncodeToString(transportKey.Public[:]), "ffffffffffffffff", "chrome")
	if err == nil {
		bad.Close()
		t.Fatal("wrong short ID authenticated")
	}
	cancel()
	closed := make(chan error, 1)
	go func() { _, err := ln.Accept(); closed <- err }()
	select {
	case err := <-closed:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("cancelled Accept: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("listener did not stop on cancellation")
	}
}

func TestNativeRealityProtectsSocketBeforeHandshake(t *testing.T) {
	want := errors.New("socket protection rejected")
	_, err := DialNativeReality(context.Background(), ClientTransportConfig{
		ServerHost: "127.0.0.1", ServerPort: "443", SNI: "example.com",
		SocketProtector: func(int) error { return want },
	}, strings.Repeat("01", 32), "1234567890abcdef", "chrome")
	if !errors.Is(err, want) {
		t.Fatalf("protection failure lost: %v", err)
	}
}

func TestNativeRealityConfigCannotSilentlyDowngrade(t *testing.T) {
	cfg := ClientConfig{Transport: TransportNativeReality, RealityPublicKey: strings.Repeat("01", 32), RealityShortID: "1234567890abcdef", RealitySNI: "example.com", EnableUDPData: true, UDPPort: "443"}
	if err := cfg.ValidateTransport(); err != nil {
		t.Fatal(err)
	}
	if cfg.DirectUDPEnabled() {
		t.Fatal("native transport leaked direct UDP without explicit opt-in")
	}
	cfg.NoTLS = true
	if err := cfg.ValidateTransport(); err == nil {
		t.Fatal("accepted no-TLS downgrade")
	}
	cfg.NoTLS = false
	cfg.RealityLegacyFallback = true
	if err := cfg.ValidateTransport(); err == nil {
		t.Fatal("accepted legacy downgrade")
	}
	cfg.RealityLegacyFallback = false
	cfg.AllowDirectUDP = true
	if err := cfg.ValidateTransport(); err == nil {
		t.Fatal("direct UDP accepted without a routing secret")
	}
}

func TestNativeRealityURIRoundTrip(t *testing.T) {
	cfg := DefaultClientConfig()
	cfg.ServerHost, cfg.ServerPort, cfg.ServerPublicKey = "127.0.0.1", "443", strings.Repeat("02", 32)
	cfg.Transport, cfg.RealityPublicKey, cfg.RealityShortID, cfg.RealitySNI = TransportNativeReality, strings.Repeat("01", 32), "1234567890abcdef", "example.com"
	got, err := ParseURI(EncodeURI(&cfg, "native"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Transport != cfg.Transport || got.RealityPublicKey != cfg.RealityPublicKey || got.RealityShortID != cfg.RealityShortID || got.RealitySNI != cfg.RealitySNI {
		t.Fatalf("transport lost in URI: %+v", got)
	}
}
