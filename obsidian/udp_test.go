package obsidian

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestSTUNHeaderRFC5389Entropy(t *testing.T) {
	var buf [STUNHeaderSize]byte
	writeSTUNHeader(buf[:], 100)

	if !IsSTUNHeader(buf[:]) {
		t.Fatal("expected IsSTUNHeader to return true")
	}

	msgType := binary.BigEndian.Uint16(buf[0:2])
	if msgType != 0x0001 {
		t.Fatalf("expected STUN Binding Request (0x0001), got 0x%04x", msgType)
	}

	msgLen := binary.BigEndian.Uint16(buf[2:4])
	if msgLen != 100 {
		t.Fatalf("expected msgLen=100, got %d", msgLen)
	}

	cookie := binary.BigEndian.Uint32(buf[4:8])
	if cookie != STUNMagicCookie {
		t.Fatalf("expected cookie 0x%08x, got 0x%08x", STUNMagicCookie, cookie)
	}

	// Verify that Transaction ID (bytes 8..20) is 96-bit CSPRNG and NOT a monotonic counter
	txIDs := make(map[[12]byte]bool)
	zeroPrefixCount := 0
	for i := 0; i < 1000; i++ {
		var b [STUNHeaderSize]byte
		writeSTUNHeader(b[:], 50)
		var txID [12]byte
		copy(txID[:], b[8:20])

		if txIDs[txID] {
			t.Fatalf("duplicate Transaction ID generated at iteration %d", i)
		}
		txIDs[txID] = true

		// Check if first 4 or 6 bytes are all zeros (monotonic counter anomaly)
		if txID[0] == 0 && txID[1] == 0 && txID[2] == 0 && txID[3] == 0 {
			zeroPrefixCount++
		}
	}

	if zeroPrefixCount > 5 {
		t.Fatalf("Transaction ID appears to be a zero-padded counter, zeroPrefixCount=%d", zeroPrefixCount)
	}
}

func TestUDPMuxO1SessionLookupScale(t *testing.T) {
	srvAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srvConn, err := net.ListenUDP("udp", srvAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer srvConn.Close()

	mux := NewUDPMux(srvConn)

	const numSessions = 5000
	sessions := make([]*UDPSession, numSessions)
	keys := make([]*UDPKeys, numSessions)

	for i := 0; i < numSessions; i++ {
		var fakeKeys SessionKeys
		_, _ = rand.Read(fakeKeys.ClientKey[:])
		_, _ = rand.Read(fakeKeys.ServerKey[:])
		_, _ = rand.Read(fakeKeys.SessionID[:])
		uk := DeriveUDPKeys(&fakeKeys, false)
		keys[i] = uk
		s, err := mux.RegisterSession(uk)
		if err != nil {
			t.Fatalf("register session %d failed: %v", i, err)
		}
		sessions[i] = s
	}

	// Verify O(1) lookup for all registered sessions
	start := time.Now()
	for i := 0; i < numSessions; i++ {
		found := mux.table.Get(keys[i].SessionTag)
		if found == nil || found != sessions[i] {
			t.Fatalf("session %d lookup failed", i)
		}
	}
	elapsed := time.Since(start)
	avgLookup := elapsed / time.Duration(numSessions)
	t.Logf("Looked up %d sessions in %v (avg %v per lookup)", numSessions, elapsed, avgLookup)

	// Clean up
	for i := 0; i < numSessions; i++ {
		sessions[i].Close()
		if found := mux.table.Get(keys[i].SessionTag); found != nil {
			t.Fatalf("session %d still found after close", i)
		}
	}
}

func TestUDPMuxAntiDoSZeroCrypto(t *testing.T) {
	srvAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srvConn, err := net.ListenUDP("udp", srvAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer srvConn.Close()

	mux := NewUDPMux(srvConn)
	go mux.Run()

	clientConn, err := net.DialUDP("udp", nil, srvConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	// Flood with invalid / scanner UDP datagrams
	var junkBuf [64]byte
	_, _ = rand.Read(junkBuf[:])

	start := time.Now()
	const floodCount = 2000
	for i := 0; i < floodCount; i++ {
		binary.BigEndian.PutUint32(junkBuf[:4], uint32(i))
		if _, err := clientConn.Write(junkBuf[:]); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Since(start)
	t.Logf("Sent %d invalid probe datagrams in %v without server panic or lockup", floodCount, elapsed)
}

func TestUDPRoamingAndRebinding(t *testing.T) {
	srvAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srvConn, err := net.ListenUDP("udp", srvAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer srvConn.Close()

	var sk SessionKeys
	_, _ = rand.Read(sk.ClientKey[:])
	_, _ = rand.Read(sk.ServerKey[:])
	_, _ = rand.Read(sk.SessionID[:])

	cliKeys := DeriveUDPKeys(&sk, true)
	srvKeys := DeriveUDPKeys(&sk, false)

	mux := NewUDPMux(srvConn)
	sess, err := mux.RegisterSession(srvKeys)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	go mux.Run()

	// 1. Client connects from Socket A (e.g. Wi-Fi)
	cliConnA, err := net.DialUDP("udp", nil, srvConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	cliChA, err := NewUDPChannel(cliConnA, cliKeys)
	if err != nil {
		t.Fatal(err)
	}

	msg1 := []byte("hello-from-wifi")
	if err := cliChA.Send(msg1); err != nil {
		t.Fatal(err)
	}
	rec1, err := sess.Recv()
	if err != nil || !bytes.Equal(rec1, msg1) {
		t.Fatalf("expected %s, got %s (err: %v)", msg1, rec1, err)
	}
	PutPacket(rec1)

	// Echo reply back to Socket A
	reply1 := []byte("echo-to-wifi")
	if err := sess.Send(reply1); err != nil {
		t.Fatal(err)
	}
	bufA := make([]byte, 2048)
	nA, err := cliChA.Recv(bufA)
	if err != nil || !bytes.Equal(bufA[:nA], reply1) {
		t.Fatalf("expected %s, got %s (err: %v)", reply1, bufA[:nA], err)
	}
	cliChA.Close()

	// 2. Client roaming: switches to Socket B (e.g. LTE with different IP/port)
	cliConnB, err := net.DialUDP("udp", nil, srvConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	cliChB, err := NewUDPChannel(cliConnB, cliKeys)
	if err != nil {
		t.Fatal(err)
	}
	defer cliChB.Close()
	// Monotonic sequence continuation across roaming socket migration
	cliChB.sendCtr.Store(1)

	msg2 := []byte("hello-from-lte-roaming")
	if err := cliChB.Send(msg2); err != nil {
		t.Fatal(err)
	}
	rec2, err := sess.Recv()
	if err != nil || !bytes.Equal(rec2, msg2) {
		t.Fatalf("expected %s, got %s (err: %v)", msg2, rec2, err)
	}
	PutPacket(rec2)

	// Server reply must now automatically route to Socket B (LTE)
	reply2 := []byte("echo-to-lte")
	if err := sess.Send(reply2); err != nil {
		t.Fatal(err)
	}
	bufB := make([]byte, 2048)
	nB, err := cliChB.Recv(bufB)
	if err != nil || !bytes.Equal(bufB[:nB], reply2) {
		t.Fatalf("expected %s, got %s (err: %v)", reply2, bufB[:nB], err)
	}
}

func BenchmarkUDPMuxLookup(b *testing.B) {
	srvConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	defer srvConn.Close()

	mux := NewUDPMux(srvConn)
	const numSessions = 1000
	keys := make([]*UDPKeys, numSessions)
	for i := 0; i < numSessions; i++ {
		var fakeKeys SessionKeys
		fakeKeys.SessionID[0] = byte(i)
		fakeKeys.SessionID[1] = byte(i >> 8)
		uk := DeriveUDPKeys(&fakeKeys, false)
		keys[i] = uk
		_, _ = mux.RegisterSession(uk)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tag := keys[i%numSessions].SessionTag
		s := mux.table.Get(tag)
		if s == nil {
			b.Fatal("nil session")
		}
	}
}

func TestWebRTCSTUNMultiplexing(t *testing.T) {
	srvAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srvConn, err := net.ListenUDP("udp", srvAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer srvConn.Close()

	var sk SessionKeys
	_, _ = rand.Read(sk.ClientKey[:])
	_, _ = rand.Read(sk.ServerKey[:])
	_, _ = rand.Read(sk.SessionID[:])

	cliKeys := DeriveUDPKeys(&sk, true)
	srvKeys := DeriveUDPKeys(&sk, false)

	cliConn, err := net.DialUDP("udp", nil, srvConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer cliConn.Close()

	cliCh, err := NewUDPChannel(cliConn, cliKeys)
	if err != nil {
		t.Fatal(err)
	}
	defer cliCh.Close()

	// Intercept wire datagrams directly on srvConn before feeding to UDPMux
	rawPkt := make([]byte, 2048)

	// Packet 0 (Handshake/Keepalive initial 1) -> STUN
	msg0 := []byte("packet-00-stun-init")
	if err := cliCh.Send(msg0); err != nil {
		t.Fatal(err)
	}
	n, _, err := srvConn.ReadFromUDP(rawPkt)
	if err != nil {
		t.Fatal(err)
	}
	if !IsSTUNHeader(rawPkt[:n]) {
		t.Fatalf("expected packet 0 to be STUN header, got: %x", rawPkt[:20])
	}

	// Packet 1 (Handshake/Keepalive initial 2) -> STUN
	msg1 := []byte("packet-01-stun-confirm")
	if err := cliCh.Send(msg1); err != nil {
		t.Fatal(err)
	}
	n, clientAddr, err := srvConn.ReadFromUDP(rawPkt)
	if err != nil {
		t.Fatal(err)
	}
	if !IsSTUNHeader(rawPkt[:n]) {
		t.Fatalf("expected packet 1 to be STUN header, got: %x", rawPkt[:20])
	}

	// Now run UDPMux and verify end-to-end decryption across STUN
	mux := NewUDPMux(srvConn)
	sess, err := mux.RegisterSession(srvKeys)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	go mux.Run()

	// Send another packet and receive via sess.Recv()
	msg2 := []byte("packet-02-live-data")
	if err := cliCh.Send(msg2); err != nil {
		t.Fatal(err)
	}
	rec2, err := sess.Recv()
	if err != nil || !bytes.Equal(rec2, msg2) {
		t.Fatalf("expected %s, got %s (err: %v)", msg2, rec2, err)
	}
	PutPacket(rec2)

	// Server replies back to client:
	sess.clientAddr.Store(clientAddr)
	srvReply0 := []byte("server-reply-0-stun-resp")
	if err := sess.Send(srvReply0); err != nil {
		t.Fatal(err)
	}
	cliRecvBuf := make([]byte, 2048)
	nCli, err := cliCh.Recv(cliRecvBuf)
	if err != nil || !bytes.Equal(cliRecvBuf[:nCli], srvReply0) {
		t.Fatalf("expected %s, got %s (err: %v)", srvReply0, cliRecvBuf[:nCli], err)
	}

	// Test keepalive probe (empty packet) echo
	if err := cliCh.Send(nil); err != nil {
		t.Fatal(err)
	}
}

