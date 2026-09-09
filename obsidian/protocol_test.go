package obsidian

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
)

func makeTestCipherPair(t *testing.T) (*Cipher, *Cipher) {
	t.Helper()
	key := [KeySize]byte{}
	iv := [NonceSize]byte{}
	io.ReadFull(rand.Reader, key[:])
	io.ReadFull(rand.Reader, iv[:])
	enc, err := NewCipher(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := NewCipher(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	return enc, dec
}

func TestEncodeDecodeData(t *testing.T) {
	enc, dec := makeTestCipherPair(t)
	payload := []byte("IP packet data here")

	raw, err := EncodePacket(enc, PacketData, payload)
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := DecodePacket(dec, raw)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.Type != PacketData {
		t.Fatalf("wrong type: %v", pkt.Type)
	}
	if !bytes.Equal(pkt.Payload, payload) {
		t.Fatal("payload mismatch")
	}
}

func TestEncodeDecodeNoise(t *testing.T) {
	enc, dec := makeTestCipherPair(t)
	pkt, err := NewNoisePacket()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodePacket(enc, pkt.Type, pkt.Payload)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePacket(dec, raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Type != PacketNoise {
		t.Fatal("wrong type")
	}
}

func TestMultiplePacketsCounter(t *testing.T) {
	enc, dec := makeTestCipherPair(t)
	payloads := make([][]byte, 20)
	encoded := make([][]byte, 20)

	for i := range payloads {
		payloads[i] = make([]byte, 50+i*7)
		io.ReadFull(rand.Reader, payloads[i])
		raw, err := EncodePacket(enc, PacketData, payloads[i])
		if err != nil {
			t.Fatal(err)
		}
		encoded[i] = raw
	}

	for i, raw := range encoded {
		pkt, err := DecodePacket(dec, raw)
		if err != nil {
			t.Fatalf("decode failed at i=%d: %v", i, err)
		}
		if !bytes.Equal(pkt.Payload, payloads[i]) {
			t.Fatalf("payload mismatch at i=%d", i)
		}
	}
}

func TestStreamFramerRoundtrip(t *testing.T) {
	keyC := [KeySize]byte{}
	ivC := [NonceSize]byte{}
	keyS := [KeySize]byte{}
	ivS := [NonceSize]byte{}
	io.ReadFull(rand.Reader, keyC[:])
	io.ReadFull(rand.Reader, ivC[:])
	io.ReadFull(rand.Reader, keyS[:])
	io.ReadFull(rand.Reader, ivS[:])

	cliEnc, _ := NewCipher(keyC, ivC)
	cliDec, _ := NewCipher(keyS, ivS)
	srvEnc, _ := NewCipher(keyS, ivS)
	srvDec, _ := NewCipher(keyC, ivC)

	cliFramer := NewStreamFramer(cliEnc, cliDec)
	srvFramer := NewStreamFramer(srvEnc, srvDec)

	messages := [][]byte{[]byte("hello"), []byte("world"), []byte("obsidian")}

	// Клиент шлёт 3 пакета в один буфер
	var stream bytes.Buffer
	for _, msg := range messages {
		frame, err := cliFramer.Frame(PacketData, msg)
		if err != nil {
			t.Fatal(err)
		}
		stream.Write(frame)
	}

	// Сервер читает покадрово
	buf := stream.Bytes()
	for i, expected := range messages {
		masked := uint32(buf[0])<<24 | uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3])
		frameLen := int(srvFramer.DecodeFrameLen(masked))
		raw := buf[4 : 4+frameLen]
		buf = buf[4+frameLen:]

		pkt, err := srvFramer.ParseFrame(raw)
		if err != nil {
			t.Fatalf("parse frame %d: %v", i, err)
		}
		if !bytes.Equal(pkt.Payload, expected) {
			t.Fatalf("message %d mismatch", i)
		}
	}
}

func TestTamperInTransit(t *testing.T) {
	enc, dec := makeTestCipherPair(t)
	raw, _ := EncodePacket(enc, PacketData, []byte("secret"))
	raw[10] ^= 0xFF // портим ciphertext

	_, err := DecodePacket(dec, raw)
	if err == nil {
		t.Fatal("tampered packet should fail")
	}
}

func TestBucketPadding(t *testing.T) {
	tests := []struct {
		payloadLen int
		maxMTU     int
		wantTotal  int
	}{
		{payloadLen: 10, maxMTU: 1360, wantTotal: 64},
		{payloadLen: 64, maxMTU: 1360, wantTotal: 64},
		{payloadLen: 65, maxMTU: 1360, wantTotal: 256},
		{payloadLen: 256, maxMTU: 1360, wantTotal: 256},
		{payloadLen: 300, maxMTU: 1360, wantTotal: 512},
		{payloadLen: 512, maxMTU: 1360, wantTotal: 512},
		{payloadLen: 700, maxMTU: 1360, wantTotal: 1024},
		{payloadLen: 1024, maxMTU: 1360, wantTotal: 1024},
		{payloadLen: 1200, maxMTU: 1360, wantTotal: 1360},
		{payloadLen: 1360, maxMTU: 1360, wantTotal: 1360},
		{payloadLen: 1400, maxMTU: 1360, wantTotal: 1400},
	}

	for _, tc := range tests {
		pad := CalculateBucketPadding(tc.payloadLen, tc.maxMTU)
		total := tc.payloadLen + pad
		if total != tc.wantTotal {
			t.Errorf("CalculateBucketPadding(%d, %d): total = %d, want %d (pad = %d)",
				tc.payloadLen, tc.maxMTU, total, tc.wantTotal, pad)
		}
	}
}

func TestSTUNHeaderDetection(t *testing.T) {
	stunSig, err := ParseCPS(PresetSTUN)
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := stunSig.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !IsSTUNHeader(pkt) {
		t.Fatalf("IsSTUNHeader returned false on valid generated STUN packet: %x", pkt)
	}
	nonSTUN := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if IsSTUNHeader(nonSTUN) {
		t.Fatal("IsSTUNHeader returned true on non-STUN packet")
	}
}

func TestUDPChannelAndMuxSTUNAndPadding(t *testing.T) {
	srvConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer srvConn.Close()

	cliConn, err := net.DialUDP("udp", nil, srvConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer cliConn.Close()

	sk := &SessionKeys{}
	io.ReadFull(rand.Reader, sk.SessionID[:])
	io.ReadFull(rand.Reader, sk.ClientKey[:])
	io.ReadFull(rand.Reader, sk.ServerKey[:])

	cliKeys := DeriveUDPKeys(sk, true)
	srvKeys := DeriveUDPKeys(sk, false)

	cliCh, err := NewUDPChannel(cliConn, cliKeys)
	if err != nil {
		t.Fatal(err)
	}
	defer cliCh.Close()

	mux := NewUDPMux(srvConn)
	sess, err := mux.RegisterSession(srvKeys)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	go mux.Run()

	testMessages := [][]byte{
		[]byte("short-ping"),
		bytes.Repeat([]byte("A"), 40),
		bytes.Repeat([]byte("B"), 300),
		bytes.Repeat([]byte("C"), 1200),
	}

	for i, msg := range testMessages {
		if err := cliCh.Send(msg); err != nil {
			t.Fatalf("client send %d: %v", i, err)
		}
		received, err := sess.Recv()
		if err != nil {
			t.Fatalf("server recv %d: %v", i, err)
		}
		if !bytes.Equal(received, msg) {
			t.Fatalf("message %d mismatch: got %d bytes, want %d bytes", i, len(received), len(msg))
		}
		PutPacket(received)

		// Echo back from server to client
		reply := append([]byte("echo:"), msg...)
		if err := sess.Send(reply); err != nil {
			t.Fatalf("server send %d: %v", i, err)
		}
		cliRecvBuf := make([]byte, 2048)
		n, err := cliCh.Recv(cliRecvBuf)
		if err != nil {
			t.Fatalf("client recv %d: %v", i, err)
		}
		if !bytes.Equal(cliRecvBuf[:n], reply) {
			t.Fatalf("reply %d mismatch", i)
		}
	}
}

func TestRandomTrailersPaddingDistribution(t *testing.T) {
	const maxMTU = 1360
	const maxTrailer = 32

	// 1. Check MTU boundary and non-negativity across wide range of payload sizes
	for payloadLen := 0; payloadLen <= 1500; payloadLen++ {
		for _, trailer := range []int{0, 16, 32, 64} {
			pad := CalculateBucketPaddingWithTrailer(payloadLen, maxMTU, trailer)
			if pad < 0 {
				t.Fatalf("negative padding %d for payload %d, trailer %d", pad, payloadLen, trailer)
			}
			if payloadLen+pad > maxMTU && payloadLen < maxMTU {
				t.Fatalf("MTU exceeded: payload=%d + pad=%d = %d > maxMTU=%d",
					payloadLen, pad, payloadLen+pad, maxMTU)
			}
			if payloadLen >= maxMTU && pad != 0 {
				t.Fatalf("oversized payload %d got non-zero pad %d", payloadLen, pad)
			}
		}
	}

	// 2. Statistical smearing test: for fixed payload length, trailer > 0 must generate varied paddings
	payloadLen := 100
	samples := make(map[int]bool)
	for i := 0; i < 200; i++ {
		p := CalculateBucketPaddingWithTrailer(payloadLen, maxMTU, maxTrailer)
		samples[p] = true
	}
	if len(samples) < 5 {
		t.Fatalf("expected varied random trailers, but only got %d distinct values", len(samples))
	}

	// 3. When maxTrailer == 0, padding must be deterministic
	samplesZero := make(map[int]bool)
	for i := 0; i < 50; i++ {
		p := CalculateBucketPaddingWithTrailer(payloadLen, maxMTU, 0)
		samplesZero[p] = true
	}
	if len(samplesZero) != 1 {
		t.Fatalf("expected deterministic padding when maxTrailer=0, got %d distinct values", len(samplesZero))
	}

	// 4. End-to-end UDP payload recovery test with random trailers
	srvConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer srvConn.Close()

	cliConn, err := net.DialUDP("udp", nil, srvConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer cliConn.Close()

	sk := &SessionKeys{}
	io.ReadFull(rand.Reader, sk.SessionID[:])
	io.ReadFull(rand.Reader, sk.ClientKey[:])
	io.ReadFull(rand.Reader, sk.ServerKey[:])

	cliKeys := DeriveUDPKeys(sk, true)
	srvKeys := DeriveUDPKeys(sk, false)

	cliCh, err := NewUDPChannel(cliConn, cliKeys)
	if err != nil {
		t.Fatal(err)
	}
	defer cliCh.Close()
	cliCh.MaxTrailer = 64

	mux := NewUDPMux(srvConn)
	sess, err := mux.RegisterSession(srvKeys)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	sess.MaxTrailer = 64

	go mux.Run()

	for size := 1; size <= 1200; size += 37 {
		msg := make([]byte, size)
		io.ReadFull(rand.Reader, msg)

		if err := cliCh.Send(msg); err != nil {
			t.Fatalf("client send size %d: %v", size, err)
		}
		received, err := sess.Recv()
		if err != nil {
			t.Fatalf("server recv size %d: %v", size, err)
		}
		if !bytes.Equal(received, msg) {
			t.Fatalf("data mismatch for size %d (got %d bytes, want %d bytes)", size, len(received), len(msg))
		}
		PutPacket(received)
	}
}
