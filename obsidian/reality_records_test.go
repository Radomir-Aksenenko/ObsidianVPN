package obsidian

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// startTLSTarget runs a real TLS 1.3 server that plays the camouflage site.
func startTLSTarget(t *testing.T) string {
	t.Helper()
	cert, err := GenerateSelfSignedCertificate("example.com")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	return ln.Addr().String()
}

// tap relays TCP between a client and target and records both directions.
type tap struct {
	ln      net.Listener
	mu      sync.Mutex
	up      bytes.Buffer // client -> server
	down    bytes.Buffer // server -> client
	wg      sync.WaitGroup
	backend string
}

func newTap(t *testing.T, backend string) *tap {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tp := &tap{ln: ln, backend: backend}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			b, err := net.Dial("tcp", backend)
			if err != nil {
				c.Close()
				continue
			}
			tp.wg.Add(2)
			go tp.copy(b, c, &tp.up)
			go tp.copy(c, b, &tp.down)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return tp
}

func (tp *tap) copy(dst, src net.Conn, rec *bytes.Buffer) {
	defer tp.wg.Done()
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			tp.mu.Lock()
			rec.Write(buf[:n])
			tp.mu.Unlock()
			if _, werr := dst.Write(buf[:n]); werr != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	dst.Close()
	src.Close()
}

func (tp *tap) port() string {
	_, p, _ := net.SplitHostPort(tp.ln.Addr().String())
	return p
}

// recordTypes walks stream as TLS records and fails unless it ends exactly on a record boundary.
func recordTypes(t *testing.T, name string, stream []byte) []byte {
	t.Helper()
	var types []byte
	for off := 0; off < len(stream); {
		if len(stream)-off < tlsRecordHeaderSize {
			t.Fatalf("%s: %d trailing bytes are not a record header", name, len(stream)-off)
		}
		h := stream[off : off+tlsRecordHeaderSize]
		n := int(binary.BigEndian.Uint16(h[3:5]))
		if h[1] != 0x03 || (h[2] != 0x01 && h[2] != 0x03) {
			t.Fatalf("%s: bad record version %x at %d", name, h[:3], off)
		}
		if n > tlsMaxCiphertext {
			t.Fatalf("%s: record of %d bytes at %d exceeds the TLS 1.3 limit", name, n, off)
		}
		switch h[0] {
		case recordTypeHandshake, recordTypeCCS, recordTypeAppData, recordTypeAlert:
		default:
			t.Fatalf("%s: record type 0x%02x at %d", name, h[0], off)
		}
		if off+tlsRecordHeaderSize+n > len(stream) {
			t.Fatalf("%s: record at %d runs past the end of the stream", name, off)
		}
		types = append(types, h[0])
		off += tlsRecordHeaderSize + n
	}
	return types
}

// obsidianServerSide accepts one connection and echoes tunnel packets until EOF.
func obsidianServerSide(ln net.Listener, kp *Keypair, isRecord chan<- bool, errCh chan<- error) {
	conn, err := ln.Accept()
	if err != nil {
		errCh <- err
		return
	}
	defer conn.Close()
	isRecord <- RealityRecordMode(conn)
	helloData, err := ReadHelloFrame(conn, kp.Public, 4096, 8192)
	if err != nil {
		errCh <- fmt.Errorf("read hello frame: %w", err)
		return
	}
	sh, err := NewServerHandshake(kp.Private, kp.Public, nil)
	if err != nil {
		errCh <- err
		return
	}
	reply, framer, err := sh.ProcessClientHello(helloData)
	if err != nil {
		errCh <- err
		return
	}
	frame, _ := BuildHelloFrame(kp.Public, reply)
	if _, err := conn.Write(frame); err != nil {
		errCh <- err
		return
	}
	tun := NewTunnel(conn, framer, DefaultTunnelConfig())
	defer tun.Close()
	for {
		msg, err := tun.RecvData(nil)
		if err != nil {
			errCh <- nil
			return
		}
		if err := tun.SendData(msg); err != nil {
			errCh <- err
			return
		}
	}
}

func TestRealityRecordModeStreamIsTLSRecords(t *testing.T) {
	target := startTLSTarget(t)
	kp, _ := GenerateKeypair()
	ckp, _ := GenerateKeypair()
	authKey := []byte("reality-shared-auth-key-32-byte")
	sni := "example.com"

	ln, err := ListenObsidianREALITY("127.0.0.1", "0", RealityDemuxConfig{
		FallbackTarget: target, ServerNames: []string{sni}, AuthKey: authKey,
		HandshakeTimeout: 3 * time.Second, DialTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tp := newTap(t, ln.Addr().String())

	isRecord := make(chan bool, 1)
	srvErr := make(chan error, 1)
	go obsidianServerSide(ln, kp, isRecord, srvErr)

	conn, err := DialObsidianREALITY(ClientTransportConfig{
		ServerHost: "127.0.0.1", ServerPort: tp.port(), SNI: sni,
		RealityEnabled: true, RealityAuthKey: authKey, RealityMode: RealityAuthRecords,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if !RealityRecordMode(conn) {
		t.Fatal("client conn is not in record mode")
	}
	if !<-isRecord {
		t.Fatal("server conn is not in record mode")
	}

	hs, _ := NewClientHandshakeWithStaticKey(kp.Public, ckp, DefaultObfuscationConfig())
	hello, _ := hs.BuildHello()
	frame, _ := BuildHelloFrame(kp.Public, hello)
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	srvHello, err := ReadHelloFrame(conn, kp.Public, ClientHelloScanLimit, 8192)
	if err != nil {
		t.Fatalf("read server hello: %v", err)
	}
	framer, err := hs.ProcessServerHello(srvHello)
	if err != nil {
		t.Fatal(err)
	}
	tun := NewTunnel(conn, framer, DefaultTunnelConfig())

	// Push enough data to need records split at the 16 KiB limit.
	for i := 0; i < 200; i++ {
		msg := make([]byte, 1200+i)
		_, _ = rand.Read(msg)
		if err := tun.SendData(msg); err != nil {
			t.Fatal(err)
		}
		got, err := tun.RecvData(nil)
		if err != nil {
			t.Fatalf("echo %d: %v", i, err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("echo %d mismatch", i)
		}
	}
	tun.Close()
	conn.Close()
	if err := <-srvErr; err != nil {
		t.Fatal(err)
	}
	tp.wg.Wait()

	tp.mu.Lock()
	up, down := tp.up.Bytes(), tp.down.Bytes()
	tp.mu.Unlock()
	upTypes := recordTypes(t, "client->server", up)
	downTypes := recordTypes(t, "server->client", down)

	if upTypes[0] != recordTypeHandshake || upTypes[1] != recordTypeCCS {
		t.Fatalf("client must open with ClientHello and CCS, got %x", upTypes[:2])
	}
	for i, ty := range upTypes[2:] {
		if ty != recordTypeAppData {
			t.Fatalf("client record %d has type 0x%02x after the handshake", i+2, ty)
		}
	}
	if downTypes[0] != recordTypeHandshake {
		t.Fatalf("server must open with ServerHello, got 0x%02x", downTypes[0])
	}
	sawApp := false
	for i, ty := range downTypes[1:] {
		if ty == recordTypeAppData {
			sawApp = true
		} else if sawApp {
			t.Fatalf("server record %d has type 0x%02x after encrypted records", i+1, ty)
		}
	}
	t.Logf("client->server %d records / %d bytes, server->client %d records / %d bytes", len(upTypes), len(up), len(downTypes), len(down))
}

func TestStreamFlightRelaysRealFlight(t *testing.T) {
	target := startTLSTarget(t)
	sid, _ := GenerateRecordSessionID([]byte("k"), "example.com")
	ch, err := BuildTLSClientHelloRecord("example.com", sid[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	sent, sawEncrypted, err := streamFlight(&out, target, ch, 3*time.Second)
	if !sawEncrypted {
		t.Fatalf("no encrypted record from a TLS 1.3 target: %v", err)
	}
	if sent != out.Len() {
		t.Fatalf("reported %d bytes, wrote %d", sent, out.Len())
	}
	types := recordTypes(t, "flight", out.Bytes())
	if types[0] != recordTypeHandshake || types[len(types)-1] != recordTypeAppData {
		t.Fatalf("unexpected flight shape %x", types)
	}
}

// A server that does not accept the record-mode SessionID hands the client to the real site.
// The client must fail quickly, not hang, so the selector can step down.
func TestRealityRecordModeFailsFastAgainstOtherServer(t *testing.T) {
	target := startTLSTarget(t)
	kp, _ := GenerateKeypair()
	ckp, _ := GenerateKeypair()
	ln, err := ListenObsidianREALITY("127.0.0.1", "0", RealityDemuxConfig{
		FallbackTarget: target, AuthKey: []byte("server-secret-key-at-least-16"),
		HandshakeTimeout: 3 * time.Second, DialTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { _, _ = ln.Accept() }()
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	conn, err := DialObsidianREALITY(ClientTransportConfig{
		ServerHost: "127.0.0.1", ServerPort: port, SNI: "example.com",
		RealityEnabled: true, RealityAuthKey: []byte("other-secret-key-at-least-16"),
	})
	if err != nil {
		// The demuxer relays to the real target, whose flight must reach the client intact:
		// the rejection may only show up after the client spoke, exactly as with a real site.
		t.Fatalf("dial must succeed against the relayed target, got %v", err)
	}
	defer conn.Close()
	hs, _ := NewClientHandshakeWithStaticKey(kp.Public, ckp, DefaultObfuscationConfig())
	hello, _ := hs.BuildHello()
	frame, _ := BuildHelloFrame(kp.Public, hello)
	start := time.Now()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	_, _ = conn.Write(frame)
	if _, err := ReadHelloFrame(conn, kp.Public, ClientHelloScanLimit, 8192); err == nil {
		t.Fatal("hello frame found on a connection to the real site")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("client needed %v to notice the rejection", d)
	}
}

// An idle prober must not hold up authenticated clients behind it.
func TestRealityDemuxerIdleProberDoesNotBlockAccept(t *testing.T) {
	authKey := []byte("reality-shared-auth-key-32-byte")
	ln, err := ListenObsidianREALITY("127.0.0.1", "0", RealityDemuxConfig{
		FallbackTarget: startTLSTarget(t),
		AuthKey:        authKey, HandshakeTimeout: 5 * time.Second, DialTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()
	_, port, _ := net.SplitHostPort(addr)

	idle, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	time.Sleep(50 * time.Millisecond) // make sure the idle socket is accepted first

	accepted := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
		accepted <- err
	}()
	start := time.Now()
	conn, err := DialObsidianREALITY(ClientTransportConfig{
		ServerHost: "127.0.0.1", ServerPort: port, SNI: "example.com",
		RealityEnabled: true, RealityAuthKey: authKey,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept was blocked by an idle connection")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("authenticated client waited %v", d)
	}
}

func TestTLSRecordConnSplitsAtRecordLimit(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	w := newTLSRecordConn(a)
	payload := make([]byte, 3*tlsMaxRecordPayload+123)
	_, _ = rand.Read(payload)
	go func() { _, _ = w.Write(payload) }()

	raw := make([]byte, len(payload)+4*tlsRecordHeaderSize)
	if _, err := io.ReadFull(b, raw); err != nil {
		t.Fatal(err)
	}
	types := recordTypes(t, "write", raw)
	if len(types) != 4 {
		t.Fatalf("want 4 records, got %d", len(types))
	}

	// And the reader undoes it, skipping CCS and handshake records.
	r := newTLSRecordConn(b)
	go func() {
		var out []byte
		out = appendRecordHeader(out, recordTypeCCS, 1)
		out = append(out, 1)
		out = appendRecordHeader(out, recordTypeAppData, 3)
		out = append(out, 'a', 'b', 'c')
		out = appendRecordHeader(out, recordTypeHandshake, 2)
		out = append(out, 4, 0)
		out = appendRecordHeader(out, recordTypeAppData, 2)
		out = append(out, 'd', 'e')
		_, _ = a.Write(out)
	}()
	got := make([]byte, 5)
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "abcde" {
		t.Fatalf("got %q", got)
	}
}

// TLS 1.2 cannot be continued with a TLS 1.3 flight; fail without inventing records.
func TestRelayFirstFlightTLS12Target(t *testing.T) {
	cert, err := GenerateSelfSignedCertificate("example.com")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MaxVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	if err := CheckRealityTarget(ln.Addr().String(), "example.com", 2*time.Second); err == nil {
		t.Fatal("CheckRealityTarget accepted a TLS 1.2 target")
	}

	sid, _ := GenerateRecordSessionID([]byte("k"), "example.com")
	ch, err := BuildTLSClientHelloRecord("example.com", sid[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	start := time.Now()
	if err := relayFirstFlight(&out, ln.Addr().String(), ch, sid[:], 10*time.Second); err == nil {
		t.Fatal("accepted a TLS 1.2 target")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("relay waited %v for a flight that never had encrypted records", d)
	}
	if out.Len() != 0 {
		t.Fatal("forwarded an incompatible first flight")
	}
}

func TestCheckRealityTargetAcceptsTLS13(t *testing.T) {
	if err := CheckRealityTarget(startTLSTarget(t), "example.com", 2*time.Second); err != nil {
		t.Fatal(err)
	}
}
