package obsidian

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func doHandshake(t *testing.T, allowed [][KeySize]byte) (*StreamFramer, *StreamFramer, *ClientHandshake, *ServerHandshake) {
	t.Helper()
	serverKP, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClientHandshake(serverKP.Public)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServerHandshake(serverKP.Private, serverKP.Public, allowed)
	if err != nil {
		t.Fatal(err)
	}
	hello, err := client.BuildHello()
	if err != nil {
		t.Fatal(err)
	}
	serverHello, srvFramer, err := server.ProcessClientHello(hello)
	if err != nil {
		t.Fatal(err)
	}
	cliFramer, err := client.ProcessServerHello(serverHello)
	if err != nil {
		t.Fatal(err)
	}
	return cliFramer, srvFramer, client, server
}

func framePayloadFor(t *testing.T, recv *StreamFramer, frame []byte) []byte {
	t.Helper()
	if len(frame) < 4 {
		t.Fatal("frame too short")
	}
	masked := uint32(frame[0])<<24 | uint32(frame[1])<<16 | uint32(frame[2])<<8 | uint32(frame[3])
	fl := int(recv.DecodeFrameLen(masked))
	if len(frame) < 4+fl {
		t.Fatalf("frame truncated: have %d want %d", len(frame)-4, fl)
	}
	return frame[4 : 4+fl]
}

func TestHandshakeSuccess(t *testing.T) {
	cliFramer, srvFramer, _, _ := doHandshake(t, nil)

	msg := []byte("hello from client")
	frame, err := cliFramer.Frame(PacketData, msg)
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := srvFramer.ParseFrame(framePayloadFor(t, srvFramer, frame))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pkt.Payload, msg) {
		t.Fatal("payload mismatch c→s")
	}

	reply := []byte("hello from server")
	frame2, _ := srvFramer.Frame(PacketData, reply)
	pkt2, err := cliFramer.ParseFrame(framePayloadFor(t, cliFramer, frame2))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pkt2.Payload, reply) {
		t.Fatal("payload mismatch s→c")
	}
}

func TestHandshakeWrongServerKey(t *testing.T) {
	serverKP, _ := GenerateKeypair()
	wrongKP, _ := GenerateKeypair()

	client, _ := NewClientHandshake(wrongKP.Public)
	server, _ := NewServerHandshake(serverKP.Private, serverKP.Public, nil)

	hello, _ := client.BuildHello()
	_, _, err := server.ProcessClientHello(hello)
	if err == nil {
		t.Fatal("should reject wrong server key")
	}
}

func TestHandshakeAllowlistReject(t *testing.T) {
	serverKP, _ := GenerateKeypair()
	authorizedKP, _ := GenerateKeypair()
	allowed := [][KeySize]byte{authorizedKP.Public}

	client, _ := NewClientHandshake(serverKP.Public)
	server, _ := NewServerHandshake(serverKP.Private, serverKP.Public, allowed)

	hello, _ := client.BuildHello()
	_, _, err := server.ProcessClientHello(hello)
	if err == nil {
		t.Fatal("should reject unlisted client")
	}
}

func TestHandshakeAllowlistAllow(t *testing.T) {
	serverKP, _ := GenerateKeypair()
	client, _ := NewClientHandshake(serverKP.Public)
	allowed := [][KeySize]byte{client.ClientStaticPub()}
	server, _ := NewServerHandshake(serverKP.Private, serverKP.Public, allowed)

	hello, _ := client.BuildHello()
	serverHello, srvFramer, err := server.ProcessClientHello(hello)
	if err != nil {
		t.Fatalf("should allow listed client: %v", err)
	}
	cliFramer, err := client.ProcessServerHello(serverHello)
	if err != nil {
		t.Fatal(err)
	}
	if cliFramer.EncHeaderKey == nil || cliFramer.DecHeaderKey == nil || srvFramer.EncHeaderKey == nil || srvFramer.DecHeaderKey == nil {
		t.Fatal("handshake must enable protected TCP header/frame length keys")
	}
}

func TestHandshakeRejectsForgedStaticProof(t *testing.T) {
	serverKP, _ := GenerateKeypair()
	authorizedKP, _ := GenerateKeypair()
	attackerKP, _ := GenerateKeypair()
	forgedKP, err := KeypairFromPrivate(attackerKP.Private)
	if err != nil {
		t.Fatal(err)
	}
	forgedKP.Public = authorizedKP.Public

	client, err := NewClientHandshakeWithStaticKey(serverKP.Public, forgedKP, DefaultObfuscationConfig())
	if err != nil {
		t.Fatal(err)
	}
	server, _ := NewServerHandshake(serverKP.Private, serverKP.Public, [][KeySize]byte{authorizedKP.Public})

	hello, _ := client.BuildHello()
	_, _, err = server.ProcessClientHello(hello)
	if err == nil {
		t.Fatal("should reject allowlisted public key without matching private-key proof")
	}
}

func TestHandshakeRejectsForgedServerStaticProof(t *testing.T) {
	serverKP, _ := GenerateKeypair()
	client, err := NewClientHandshake(serverKP.Public)
	if err != nil {
		t.Fatal(err)
	}
	hello, err := client.BuildHello()
	if err != nil {
		t.Fatal(err)
	}
	offset := 1 + int(hello[0])
	var clientEph [KeySize]byte
	copy(clientEph[:], hello[offset:offset+KeySize])
	offset += KeySize
	clientMLKEMPub := hello[offset : offset+MLKEM768EncapsulationKeySize]
	offset += MLKEM768EncapsulationKeySize
	salt := append([]byte(nil), hello[offset:offset+32]...)

	// An on-path attacker can generate a final ephemeral exchange and encrypt a
	// syntactically valid confirmation, but cannot prove possession of the pinned
	// server static private key.
	attackerStatic, _ := GenerateKeypair()
	attackerEph, _ := GenerateKeypair()
	sharedMLKEM, fakeCiphertext, err := EncapsulateMLKEM(clientMLKEMPub)
	if err != nil {
		t.Fatal(err)
	}
	finalShared, err := DHSafe(attackerEph.Private, clientEph)
	if err != nil {
		t.Fatal(err)
	}
	hybridSecret := DeriveHybridSecret(finalShared[:], sharedMLKEM, salt)
	keys, err := DeriveKeys(hybridSecret, salt, clientEph, attackerEph.Public)
	if err != nil {
		t.Fatal(err)
	}
	wrongStaticShared, err := DHSafe(attackerStatic.Private, clientEph)
	if err != nil {
		t.Fatal(err)
	}
	proof := serverStaticProof(wrongStaticShared, clientEph, salt, attackerEph.Public, keys.SessionID)
	plain := append([]byte{}, keys.DynamicMagic[:]...)
	plain = append(plain, keys.SessionID[:]...)
	plain = append(plain, proof...)
	cipher, err := NewCipher(keys.ServerKey, keys.ServerIV)
	if err != nil {
		t.Fatal(err)
	}
	confirmAAD := make([]byte, 0, KeySize+len(fakeCiphertext))
	confirmAAD = append(confirmAAD, attackerEph.Public[:]...)
	confirmAAD = append(confirmAAD, fakeCiphertext...)
	confirm := cipher.Encrypt(plain, confirmAAD)

	fakeHello := append([]byte{0}, attackerEph.Public[:]...)
	fakeHello = append(fakeHello, fakeCiphertext...)
	fakeHello = appendUint16(fakeHello, uint16(len(confirm)))
	fakeHello = append(fakeHello, confirm...)
	fakeHello = appendUint16(fakeHello, 0)

	if _, err := client.ProcessServerHello(fakeHello); err == nil {
		t.Fatal("client accepted ServerHello without the pinned server static proof")
	}
}

func TestMLKEM768KeygenAndEncapsulate(t *testing.T) {
	kp, err := GenerateMLKEMKeypair()
	if err != nil {
		t.Fatal(err)
	}
	encPub := kp.EncapsulationKey.Bytes()
	if len(encPub) != MLKEM768EncapsulationKeySize {
		t.Fatalf("encPub len = %d, want %d", len(encPub), MLKEM768EncapsulationKeySize)
	}
	ssServer, ct, err := EncapsulateMLKEM(encPub)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) != MLKEM768CiphertextSize {
		t.Fatalf("ct len = %d, want %d", len(ct), MLKEM768CiphertextSize)
	}
	if len(ssServer) != MLKEM768SharedKeySize {
		t.Fatalf("ss len = %d, want %d", len(ssServer), MLKEM768SharedKeySize)
	}
	ssClient, err := DecapsulateMLKEM(kp.DecapsulationKey, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ssServer, ssClient) {
		t.Fatal("shared key mismatch between encapsulation and decapsulation")
	}
}

func TestHybridSecretCombiner(t *testing.T) {
	ssX25519 := make([]byte, 32)
	ssMLKEM := make([]byte, 32)
	io.ReadFull(rand.Reader, ssX25519)
	io.ReadFull(rand.Reader, ssMLKEM)
	salt := []byte("test_salt")

	h1 := DeriveHybridSecret(ssX25519, ssMLKEM, salt)
	h2 := DeriveHybridSecret(ssX25519, ssMLKEM, salt)
	if !bytes.Equal(h1[:], h2[:]) {
		t.Fatal("DeriveHybridSecret should be deterministic for identical inputs")
	}

	// Change 1 bit in X25519
	tamperedX := append([]byte(nil), ssX25519...)
	tamperedX[0] ^= 0x01
	h3 := DeriveHybridSecret(tamperedX, ssMLKEM, salt)
	if bytes.Equal(h1[:], h3[:]) {
		t.Fatal("DeriveHybridSecret must change when X25519 input changes")
	}

	// Change 1 bit in ML-KEM
	tamperedML := append([]byte(nil), ssMLKEM...)
	tamperedML[0] ^= 0x01
	h4 := DeriveHybridSecret(ssX25519, tamperedML, salt)
	if bytes.Equal(h1[:], h4[:]) {
		t.Fatal("DeriveHybridSecret must change when ML-KEM input changes")
	}
}

func TestPostQuantumHandshakeTamperedMLKEMCiphertext(t *testing.T) {
	serverKP, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClientHandshake(serverKP.Public)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServerHandshake(serverKP.Private, serverKP.Public, nil)
	if err != nil {
		t.Fatal(err)
	}
	hello, err := client.BuildHello()
	if err != nil {
		t.Fatal(err)
	}
	serverHello, _, err := server.ProcessClientHello(hello)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with 1 byte in ML-KEM ciphertext within ServerHello
	tamperedServerHello := append([]byte(nil), serverHello...)
	prePadLen := int(tamperedServerHello[0])
	ctOffset := 1 + prePadLen + KeySize
	tamperedServerHello[ctOffset+10] ^= 0xFF

	_, err = client.ProcessServerHello(tamperedServerHello)
	if err == nil {
		t.Fatal("client must reject ServerHello with tampered ML-KEM ciphertext")
	}
}

func TestHandshakeBidirectionalMany(t *testing.T) {
	cliFramer, srvFramer, _, _ := doHandshake(t, nil)

	for i := 0; i < 50; i++ {
		payload := make([]byte, 100+i*7)
		io.ReadFull(rand.Reader, payload)

		frame, _ := cliFramer.Frame(PacketData, payload)
		pkt, err := srvFramer.ParseFrame(framePayloadFor(t, srvFramer, frame))
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		if !bytes.Equal(pkt.Payload, payload) {
			t.Fatalf("payload mismatch at %d", i)
		}
	}
}

func TestSessionIDsDifferent(t *testing.T) {
	_, _, c1, _ := doHandshake(t, nil)
	_, _, c2, _ := doHandshake(t, nil)
	if c1.SessionKeys.SessionID == c2.SessionKeys.SessionID {
		t.Fatal("session IDs should be unique")
	}
}

func TestDynamicMagicUnique(t *testing.T) {
	_, _, c1, _ := doHandshake(t, nil)
	_, _, c2, _ := doHandshake(t, nil)
	if c1.SessionKeys.DynamicMagic == c2.SessionKeys.DynamicMagic {
		t.Fatal("DynamicMagic should be unique per session")
	}
}

func TestDynamicMagicClientServerMatch(t *testing.T) {
	_, _, client, server := doHandshake(t, nil)
	if client.SessionKeys.DynamicMagic != server.SessionKeys.DynamicMagic {
		t.Fatal("DynamicMagic should match between client and server")
	}
}

func TestJunkTrain(t *testing.T) {
	cfg := DefaultObfuscationConfig()
	cfg.JunkCount = 5
	cfg.JunkMin = 64
	cfg.JunkMax = 256

	data, count, err := BuildJunkTrain(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatal("expected junk packets")
	}
	if len(data) == 0 {
		t.Fatal("expected junk data")
	}
	// Проверяем что пакеты корректно фреймированы
	buf := data
	parsed := 0
	for len(buf) >= 4 {
		frameLen := int(buf[0])<<24 | int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
		if len(buf) < 4+frameLen {
			t.Fatalf("junk frame truncated at packet %d", parsed)
		}
		buf = buf[4+frameLen:]
		parsed++
	}
	if parsed != count {
		t.Fatalf("parsed %d junk packets, expected %d", parsed, count)
	}
}

func TestPrePaddingVaries(t *testing.T) {
	serverKP, _ := GenerateKeypair()
	sizes := make(map[int]bool)
	for i := 0; i < 20; i++ {
		client, _ := NewClientHandshake(serverKP.Public)
		hello, err := client.BuildHello()
		if err != nil {
			t.Fatal(err)
		}
		sizes[len(hello)] = true
	}
	// При PrePadMax=64 размеры должны варьироваться
	if len(sizes) < 3 {
		t.Fatal("pre-padding should produce varied hello sizes")
	}
}

func TestHandshakeWithCustomObfConfig(t *testing.T) {
	serverKP, _ := GenerateKeypair()
	cfg := ObfuscationConfig{
		JunkCount: 5, JunkMin: 128, JunkMax: 512,
		S1Min: 32, S1Max: 128,
		S2Min: 32, S2Max: 128,
		PrePadMax: 32,
	}
	client, err := NewClientHandshakeWithConfig(serverKP.Public, cfg)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServerHandshakeWithConfig(serverKP.Private, serverKP.Public, nil, cfg)
	if err != nil {
		t.Fatal(err)
	}

	hello, err := client.BuildHello()
	if err != nil {
		t.Fatal(err)
	}
	serverHello, framer, err := server.ProcessClientHello(hello)
	if err != nil {
		t.Fatal(err)
	}
	cliFramer, err := client.ProcessServerHello(serverHello)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("custom config test")
	frame, _ := cliFramer.Frame(PacketData, msg)
	pkt, err := framer.ParseFrame(framePayloadFor(t, framer, frame))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pkt.Payload, msg) {
		t.Fatal("payload mismatch")
	}
}

func BenchmarkHybridPostQuantumHandshake(b *testing.B) {
	serverKP, err := GenerateKeypair()
	if err != nil {
		b.Fatal(err)
	}
	cfg := DefaultObfuscationConfig()
	cfg.JunkCount = 0
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		client, err := NewClientHandshakeWithConfig(serverKP.Public, cfg)
		if err != nil {
			b.Fatal(err)
		}
		hello, err := client.BuildHello()
		if err != nil {
			b.Fatal(err)
		}
		server, err := NewServerHandshakeWithConfig(serverKP.Private, serverKP.Public, nil, cfg)
		if err != nil {
			b.Fatal(err)
		}
		serverHello, _, err := server.ProcessClientHello(hello)
		if err != nil {
			b.Fatal(err)
		}
		_, err = client.ProcessServerHello(serverHello)
		if err != nil {
			b.Fatal(err)
		}
	}
}
