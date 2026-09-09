package obsidian

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func TestREALITYAuthTokenValidation(t *testing.T) {
	authKey := []byte("obsidian-super-secret-auth-key-32b!")
	sni := "gateway.icloud.com"

	// 1. Valid token
	sessionID, err := GenerateSessionID(authKey, sni)
	if err != nil {
		t.Fatalf("GenerateSessionID error: %v", err)
	}
	if len(sessionID) != TLSSessionIDSize {
		t.Fatalf("expected sessionID size %d, got %d", TLSSessionIDSize, len(sessionID))
	}

	if !VerifySessionID(sessionID[:], sni, authKey, 30) {
		t.Fatal("expected valid sessionID to pass verification")
	}

	// 2. Case insensitive and trimmed SNI
	if !VerifySessionID(sessionID[:], "  GATEWAY.ICLOUD.COM ", authKey, 30) {
		t.Fatal("expected case-insensitive trimmed SNI to pass verification")
	}

	// 3. Wrong SNI
	if VerifySessionID(sessionID[:], "www.microsoft.com", authKey, 30) {
		t.Fatal("expected wrong SNI to fail verification")
	}

	// 4. Wrong auth key
	wrongKey := []byte("wrong-auth-key-0000000000000000000")
	if VerifySessionID(sessionID[:], sni, wrongKey, 30) {
		t.Fatal("expected wrong auth key to fail verification")
	}

	// 5. Corrupted tag
	corrupted := sessionID
	corrupted[len(corrupted)-1] ^= 0xff
	if VerifySessionID(corrupted[:], sni, authKey, 30) {
		t.Fatal("expected corrupted tag to fail verification")
	}

	// 6. Expired timestamp (>30s in the past)
	pastTS := time.Now().Unix() - 45
	pastSessionID, err := GenerateSessionIDWithTimestamp(authKey, sni, pastTS)
	if err != nil {
		t.Fatalf("GenerateSessionIDWithTimestamp error: %v", err)
	}
	if VerifySessionID(pastSessionID[:], sni, authKey, 30) {
		t.Fatal("expected expired timestamp to fail verification")
	}

	// 7. Future timestamp (>30s in the future)
	futureTS := time.Now().Unix() + 45
	futureSessionID, err := GenerateSessionIDWithTimestamp(authKey, sni, futureTS)
	if err != nil {
		t.Fatalf("GenerateSessionIDWithTimestamp error: %v", err)
	}
	if VerifySessionID(futureSessionID[:], sni, authKey, 30) {
		t.Fatal("expected future timestamp to fail verification")
	}
}

func TestREALITYClientHelloParsing(t *testing.T) {
	authKey := []byte("reality-test-auth-key-32-bytes!!")
	sni := "gateway.icloud.com"

	sessionID, err := GenerateSessionID(authKey, sni)
	if err != nil {
		t.Fatalf("generate session id: %v", err)
	}

	// Build realistic TLS 1.3 ClientHello record
	record, err := BuildTLSClientHelloRecord(sni, sessionID[:], &utls.HelloChrome_Auto)
	if err != nil {
		t.Fatalf("BuildTLSClientHelloRecord failed: %v", err)
	}

	// Parse record
	parsedSessionID, parsedSNI, isClientHello, err := ParseTLSClientHello(record)
	if err != nil {
		t.Fatalf("ParseTLSClientHello failed: %v", err)
	}
	if !isClientHello {
		t.Fatal("expected isClientHello = true")
	}
	if !bytes.Equal(parsedSessionID, sessionID[:]) {
		t.Fatalf("parsed session ID mismatch:\nexpected %x\ngot      %x", sessionID, parsedSessionID)
	}
	if parsedSNI != sni {
		t.Fatalf("parsed SNI mismatch: expected %q, got %q", sni, parsedSNI)
	}

	// Verify authentication on parsed output
	if !VerifySessionID(parsedSessionID, parsedSNI, authKey, 30) {
		t.Fatal("verification failed on parsed ClientHello fields")
	}

	// Test malformed / truncated inputs
	_, _, isCH, err := ParseTLSClientHello([]byte{0x16, 0x03, 0x01})
	if err == nil || isCH {
		t.Fatal("expected error on truncated record")
	}

	// Test non-TLS input
	_, _, isCH, err = ParseTLSClientHello([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	if err == nil || isCH {
		t.Fatal("expected error on non-TLS record")
	}
}

func TestREALITYReplayProtection(t *testing.T) {
	cache := NewRealityReplayCache(500 * time.Millisecond)

	authKey := []byte("reality-test-auth-key-32-bytes!!")
	sessionID, err := GenerateSessionID(authKey, "gateway.icloud.com")
	if err != nil {
		t.Fatalf("generate session ID: %v", err)
	}

	// 1. First presentation -> Accepted (false = not seen before)
	if cache.SeenOrAdd(sessionID[:]) {
		t.Fatal("expected first presentation to not be marked as replayed")
	}

	// 2. Immediate second presentation -> Blocked (true = replay detected)
	if !cache.SeenOrAdd(sessionID[:]) {
		t.Fatal("expected second presentation to be detected as replay")
	}

	// 3. Different sessionID -> Accepted
	sessionID2, _ := GenerateSessionID(authKey, "gateway.icloud.com")
	if cache.SeenOrAdd(sessionID2[:]) {
		t.Fatal("expected different session ID to be accepted")
	}

	// 4. Wait for TTL to expire
	time.Sleep(600 * time.Millisecond)
	if cache.SeenOrAdd(sessionID[:]) {
		t.Fatal("expected session ID to be accepted after TTL expiry")
	}
}

func TestREALITYActiveProbing(t *testing.T) {
	// 1. Start a mock real HTTPS backend server (e.g. simulating Apple / DigiCert HTTPS server)
	backendCert, err := GenerateSelfSignedCertificate("gateway.icloud.com", "localhost", "127.0.0.1")
	if err != nil {
		t.Fatalf("generate backend cert: %v", err)
	}

	backendTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{backendCert},
		ServerName:   "gateway.icloud.com",
	}

	backendListener, err := tls.Listen("tcp", "127.0.0.1:0", backendTLSConfig)
	if err != nil {
		t.Fatalf("backend listen: %v", err)
	}
	defer backendListener.Close()

	backendAddr := backendListener.Addr().String()

	// Backend HTTP handler returning known authentic content
	backendServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "Apple-iCloud-Gateway")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("GENUINE_APPLE_ICLOUD_RESPONSE_200_OK"))
		}),
	}
	go backendServer.Serve(backendListener)
	defer backendServer.Close()

	// 2. Start Obsidian REALITY server targeting this backend
	realityAuthKey := []byte("secret-reality-key-32-bytes-long!")
	realityCfg := RealityDemuxConfig{
		FallbackTarget:   backendAddr,
		ServerNames:      []string{"gateway.icloud.com"},
		AuthKey:          realityAuthKey,
		HandshakeTimeout: 3 * time.Second,
		DialTimeout:      3 * time.Second,
	}

	realityListener, err := ListenObsidianREALITY("127.0.0.1", "0", realityCfg)
	if err != nil {
		t.Fatalf("ListenObsidianREALITY error: %v", err)
	}
	defer realityListener.Close()

	// Run Demuxer Accept loop in background
	go func() {
		for {
			conn, err := realityListener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	realityAddr := realityListener.Addr().String()

	// 3. Test Active Probing Scanner (curl / standard TLS client without Obsidian token)
	// Scanner connects to Obsidian server expecting genuine response from target
	tlsClientConfig := &tls.Config{
		InsecureSkipVerify: true, // test cert
		ServerName:         "gateway.icloud.com",
	}

	clientConn, err := tls.Dial("tcp", realityAddr, tlsClientConfig)
	if err != nil {
		t.Fatalf("active prober TLS dial failed: %v", err)
	}
	defer clientConn.Close()

	// Send HTTP Request
	req := "GET / HTTP/1.1\r\nHost: gateway.icloud.com\r\nConnection: close\r\n\r\n"
	if _, err := clientConn.Write([]byte(req)); err != nil {
		t.Fatalf("scanner write request failed: %v", err)
	}

	respBytes, err := io.ReadAll(clientConn)
	if err != nil {
		t.Fatalf("scanner read response failed: %v", err)
	}

	respStr := string(respBytes)
	if !bytes.Contains(respBytes, []byte("GENUINE_APPLE_ICLOUD_RESPONSE_200_OK")) {
		t.Fatalf("scanner did not receive genuine backend response:\n%s", respStr)
	}
	if !bytes.Contains(respBytes, []byte("Apple-iCloud-Gateway")) {
		t.Fatalf("scanner did not receive genuine server headers:\n%s", respStr)
	}
}

func TestREALITYClientHandshakeSuccess(t *testing.T) {
	// 1. Setup keys
	serverKeypair, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	clientKeypair, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	realityAuthKey := []byte("reality-shared-auth-key-32-byte")
	sni := "gateway.icloud.com"

	// 2. Start REALITY Listener
	realityCfg := RealityDemuxConfig{
		FallbackTarget:   "127.0.0.1:1", // Dummy fallback
		ServerNames:      []string{sni},
		AuthKey:          realityAuthKey,
		HandshakeTimeout: 3 * time.Second,
		DialTimeout:      3 * time.Second,
	}

	listener, err := ListenObsidianREALITY("127.0.0.1", "0", realityCfg)
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	defer listener.Close()

	_, port, _ := net.SplitHostPort(listener.Addr().String())

	// Channel to signal server session completion
	serverErrCh := make(chan error, 1)

	// Server goroutine
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErrCh <- err
			return
		}
		defer conn.Close()

		// Read Obsidian Handshake
		helloData, err := ReadHelloFrame(conn, serverKeypair.Public, 4096, 8192)
		if err != nil {
			serverErrCh <- fmt.Errorf("read hello frame: %w", err)
			return
		}

		sh, err := NewServerHandshake(serverKeypair.Private, serverKeypair.Public, nil)
		if err != nil {
			serverErrCh <- fmt.Errorf("server handshake init: %w", err)
			return
		}

		serverHello, framer, err := sh.ProcessClientHello(helloData)
		if err != nil {
			serverErrCh <- fmt.Errorf("process client hello: %w", err)
			return
		}

		serverHelloFrame, err := BuildHelloFrame(serverKeypair.Public, serverHello)
		if err != nil {
			serverErrCh <- fmt.Errorf("build server hello frame: %w", err)
			return
		}

		if _, err := conn.Write(serverHelloFrame); err != nil {
			serverErrCh <- fmt.Errorf("send server hello: %w", err)
			return
		}

		tunnel := NewTunnel(conn, framer, DefaultTunnelConfig())
		defer tunnel.Close()

		// Receive data from client
		msg, err := tunnel.RecvData(nil)
		if err != nil {
			serverErrCh <- fmt.Errorf("recv data: %w", err)
			return
		}
		if string(msg) != "HELLO_OBSIDIAN_REALITY_POST_QUANTUM" {
			serverErrCh <- fmt.Errorf("unexpected message: %s", msg)
			return
		}

		// Reply
		if err := tunnel.SendData([]byte("PQC_TUNNEL_ESTABLISHED_SUCCESSFULLY")); err != nil {
			serverErrCh <- fmt.Errorf("send data: %w", err)
			return
		}

		serverErrCh <- nil
	}()

	// 3. Client establishes connection via DialObsidianREALITY
	clientTransportCfg := ClientTransportConfig{
		ServerHost:     "127.0.0.1",
		ServerPort:     port,
		SNI:            sni,
		RealityEnabled: true,
		RealityAuthKey: realityAuthKey,
	}

	conn, err := DialObsidianREALITY(clientTransportCfg)
	if err != nil {
		t.Fatalf("dial reality error: %v", err)
	}
	defer conn.Close()

	// Client runs post-quantum handshake
	hs, err := NewClientHandshakeWithStaticKey(serverKeypair.Public, clientKeypair, DefaultObfuscationConfig())
	if err != nil {
		t.Fatalf("client handshake init: %v", err)
	}

	hello, err := hs.BuildHello()
	if err != nil {
		t.Fatalf("build hello: %v", err)
	}

	helloFrame, err := BuildHelloFrame(serverKeypair.Public, hello)
	if err != nil {
		t.Fatalf("build hello frame: %v", err)
	}

	if _, err := conn.Write(helloFrame); err != nil {
		t.Fatalf("send hello: %v", err)
	}

	srvHello, err := ReadHelloFrame(conn, serverKeypair.Public, 4096, 8192)
	if err != nil {
		t.Fatalf("read server hello: %v", err)
	}

	framer, err := hs.ProcessServerHello(srvHello)
	if err != nil {
		t.Fatalf("process server hello: %v", err)
	}

	tunnel := NewTunnel(conn, framer, DefaultTunnelConfig())
	defer tunnel.Close()

	// Send test data
	if err := tunnel.SendData([]byte("HELLO_OBSIDIAN_REALITY_POST_QUANTUM")); err != nil {
		t.Fatalf("send client data: %v", err)
	}

	reply, err := tunnel.RecvData(nil)
	if err != nil {
		t.Fatalf("recv server reply: %v", err)
	}

	if string(reply) != "PQC_TUNNEL_ESTABLISHED_SUCCESSFULLY" {
		t.Fatalf("unexpected server reply: %s", reply)
	}

	if err := <-serverErrCh; err != nil {
		t.Fatalf("server side error: %v", err)
	}
}

func BenchmarkREALITYClientHelloParsing(b *testing.B) {
	authKey := []byte("reality-bench-key-32-bytes-long!")
	sni := "gateway.icloud.com"
	sessionID, _ := GenerateSessionID(authKey, sni)
	record, err := BuildTLSClientHelloRecord(sni, sessionID[:], &utls.HelloChrome_Auto)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sessID, parsedSNI, isCH, err := ParseTLSClientHello(record)
		if err != nil || !isCH || len(sessID) == 0 || parsedSNI == "" {
			b.Fatal("parsing failed in benchmark")
		}
	}
}

func BenchmarkREALITYAuthVerification(b *testing.B) {
	authKey := []byte("reality-bench-key-32-bytes-long!")
	sni := "gateway.icloud.com"
	sessionID, _ := GenerateSessionID(authKey, sni)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if !VerifySessionID(sessionID[:], sni, authKey, 30) {
			b.Fatal("verification failed in benchmark")
		}
	}
}
