package obsidian

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"
)

func TestGenerateKeypair(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if len(kp.Private) != KeySize || len(kp.Public) != KeySize {
		t.Fatal("wrong key sizes")
	}
	if bytes.Equal(kp.Private[:], kp.Public[:]) {
		t.Fatal("private == public")
	}
}

func TestDHSymmetry(t *testing.T) {
	kpA, _ := GenerateKeypair()
	kpB, _ := GenerateKeypair()

	sharedAB, err := DHSafe(kpA.Private, kpB.Public)
	if err != nil {
		t.Fatal(err)
	}
	sharedBA, err := DHSafe(kpB.Private, kpA.Public)
	if err != nil {
		t.Fatal(err)
	}
	if sharedAB != sharedBA {
		t.Fatal("DH is not symmetric")
	}
}

func TestDeriveKeys(t *testing.T) {
	kpA, _ := GenerateKeypair()
	kpB, _ := GenerateKeypair()
	shared, _ := DHSafe(kpA.Private, kpB.Public)

	salt := make([]byte, 32)
	io.ReadFull(rand.Reader, salt)

	sk, err := DeriveKeys(shared, salt, kpA.Public, kpB.Public)
	if err != nil {
		t.Fatal(err)
	}

	// Все поля разные
	if sk.ClientKey == sk.ServerKey {
		t.Fatal("client_key == server_key")
	}
	// Детерминированность: те же входы → те же ключи
	sk2, _ := DeriveKeys(shared, salt, kpA.Public, kpB.Public)
	if *sk != *sk2 {
		t.Fatal("DeriveKeys not deterministic")
	}
}

func TestCipherEncryptDecrypt(t *testing.T) {
	key := [KeySize]byte{}
	iv := [NonceSize]byte{}
	io.ReadFull(rand.Reader, key[:])
	io.ReadFull(rand.Reader, iv[:])

	enc, _ := NewCipher(key, iv)
	dec, _ := NewCipher(key, iv)

	for i := 0; i < 10; i++ {
		plaintext := make([]byte, 100+i*13)
		aad := make([]byte, 8)
		io.ReadFull(rand.Reader, plaintext)
		io.ReadFull(rand.Reader, aad)

		ct := enc.Encrypt(plaintext, aad)
		pt, err := dec.Decrypt(ct, aad)
		if err != nil {
			t.Fatalf("decrypt failed at i=%d: %v", i, err)
		}
		if !bytes.Equal(pt, plaintext) {
			t.Fatal("decrypted != original")
		}
	}
}

func TestCipherNonceMonotonic(t *testing.T) {
	key := [KeySize]byte{}
	iv := [NonceSize]byte{}
	io.ReadFull(rand.Reader, key[:])
	io.ReadFull(rand.Reader, iv[:])

	c1, _ := NewCipher(key, iv)
	c2, _ := NewCipher(key, iv)

	pt := []byte("hello")
	ct1 := c1.Encrypt(pt, nil)
	ct2 := c2.Encrypt(pt, nil)
	// Оба использовали nonce=0, результат должен совпадать
	if !bytes.Equal(ct1, ct2) {
		t.Fatal("same nonce should produce same ciphertext")
	}

	ct3 := c1.Encrypt(pt, nil) // nonce=1
	ct4 := c2.Encrypt(pt, nil) // nonce=1
	if !bytes.Equal(ct3, ct4) {
		t.Fatal("nonce counter out of sync")
	}

	// nonce=0 и nonce=1 должны давать разные ciphertext
	if bytes.Equal(ct1, ct3) {
		t.Fatal("different nonces produced same ciphertext")
	}
}

func TestCipherTamperDetection(t *testing.T) {
	key := [KeySize]byte{}
	iv := [NonceSize]byte{}
	io.ReadFull(rand.Reader, key[:])
	io.ReadFull(rand.Reader, iv[:])

	enc, _ := NewCipher(key, iv)
	dec, _ := NewCipher(key, iv)

	ct := enc.Encrypt([]byte("secret"), []byte("aad"))
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[5] ^= 0xFF

	_, err := dec.Decrypt(tampered, []byte("aad"))
	if err == nil {
		t.Fatal("tampered ciphertext should fail authentication")
	}
}

func TestRandomPadding(t *testing.T) {
	for i := 0; i < 1000; i++ {
		pad, err := RandomPadding(16, 64)
		if err != nil {
			t.Fatal(err)
		}
		if len(pad) < 16 || len(pad) >= 64 {
			t.Fatalf("padding size %d out of [16,64)", len(pad))
		}
	}
}

func TestDHSmallSubgroup(t *testing.T) {
	// Нулевой публичный ключ должен быть отклонён DHSafe
	var priv [KeySize]byte
	var zeroPub [KeySize]byte
	io.ReadFull(rand.Reader, priv[:])

	_, err := DHSafe(priv, zeroPub)
	if err == nil {
		t.Fatal("DHSafe should reject zero public key (small-subgroup attack)")
	}
}

func TestInTunnelRekeyingSeamless(t *testing.T) {
	// 1. Key ratchet property verification
	initSK := &SessionKeys{}
	io.ReadFull(rand.Reader, initSK.ClientKey[:])
	io.ReadFull(rand.Reader, initSK.ServerKey[:])
	io.ReadFull(rand.Reader, initSK.SessionID[:])

	epoch1, err := DeriveNextEpochKeys(initSK, 1)
	if err != nil {
		t.Fatal(err)
	}
	epoch2, err := DeriveNextEpochKeys(epoch1, 2)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(epoch1.ClientKey[:], epoch2.ClientKey[:]) {
		t.Fatal("epoch 2 client key must differ from epoch 1")
	}
	if bytes.Equal(epoch1.SessionID[:], epoch2.SessionID[:]) {
		t.Fatal("epoch 2 session ID must differ from epoch 1")
	}

	// Determinism
	epoch1Copy, _ := DeriveNextEpochKeys(initSK, 1)
	if *epoch1 != *epoch1Copy {
		t.Fatal("DeriveNextEpochKeys not deterministic")
	}

	// 2. Seamless in-flight UDP transmission across ratchet boundaries
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

	cliKeysE1 := DeriveUDPKeys(epoch1, true)
	srvKeysE1 := DeriveUDPKeys(epoch1, false)

	cliCh, err := NewUDPChannel(cliConn, cliKeysE1)
	if err != nil {
		t.Fatal(err)
	}
	defer cliCh.Close()

	mux := NewUDPMux(srvConn)
	sess, err := mux.RegisterSession(srvKeysE1)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	go mux.Run()

	// Transmit on epoch 1
	msg1 := []byte("payload-epoch-1")
	if err := cliCh.Send(msg1); err != nil {
		t.Fatal(err)
	}
	recv1, err := sess.Recv()
	if err != nil || !bytes.Equal(recv1, msg1) {
		t.Fatalf("epoch 1 recv failed: %v", err)
	}
	PutPacket(recv1)

	// Ratchet both sides to epoch 2
	cliKeysE2 := DeriveUDPKeys(epoch2, true)
	srvKeysE2 := DeriveUDPKeys(epoch2, false)

	if err := cliCh.RatchetEpoch(cliKeysE2); err != nil {
		t.Fatal(err)
	}
	if err := sess.RatchetEpoch(srvKeysE2); err != nil {
		t.Fatal(err)
	}

	// Transmit on epoch 2
	msg2 := []byte("payload-epoch-2-seamless")
	if err := cliCh.Send(msg2); err != nil {
		t.Fatal(err)
	}
	recv2, err := sess.Recv()
	if err != nil || !bytes.Equal(recv2, msg2) {
		t.Fatalf("epoch 2 recv failed: %v", err)
	}
	PutPacket(recv2)

	// Server replies back on epoch 2
	reply2 := []byte("reply-epoch-2")
	if err := sess.Send(reply2); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	n, err := cliCh.Recv(buf)
	if err != nil || !bytes.Equal(buf[:n], reply2) {
		t.Fatalf("epoch 2 reply recv failed: %v", err)
	}
}

func TestStatelessHandshakeCookieRejection(t *testing.T) {
	secret := make([]byte, 32)
	io.ReadFull(rand.Reader, secret)

	clientIP1 := net.ParseIP("198.51.100.42")
	clientIP2 := net.ParseIP("203.0.113.88")

	var ephPub1, ephPub2 [KeySize]byte
	io.ReadFull(rand.Reader, ephPub1[:])
	io.ReadFull(rand.Reader, ephPub2[:])

	salt1 := []byte("salt-alpha-12345678901234567890")
	salt2 := []byte("salt-beta-12345678901234567890")

	tsNow := time.Now()

	// Valid cookie
	cookie := GenerateHandshakeCookie(secret, clientIP1, ephPub1, salt1, tsNow)
	if len(cookie) != CookieSize {
		t.Fatalf("cookie size = %d, want %d", len(cookie), CookieSize)
	}
	if !ValidateHandshakeCookie(cookie, secret, clientIP1, ephPub1, salt1, 30*time.Second) {
		t.Fatal("valid cookie should be accepted")
	}

	// 1. Tampered token
	tampered := append([]byte(nil), cookie...)
	tampered[15] ^= 0xFF
	if ValidateHandshakeCookie(tampered, secret, clientIP1, ephPub1, salt1, 30*time.Second) {
		t.Fatal("tampered cookie MAC must be rejected")
	}

	// 2. Truncated cookie
	if ValidateHandshakeCookie(cookie[:20], secret, clientIP1, ephPub1, salt1, 30*time.Second) {
		t.Fatal("truncated cookie must be rejected")
	}

	// 3. Client IP mismatch (attacker on IP2 using cookie issued to IP1)
	if ValidateHandshakeCookie(cookie, secret, clientIP2, ephPub1, salt1, 30*time.Second) {
		t.Fatal("IP mismatch must be rejected")
	}

	// 4. Ephemeral key mismatch
	if ValidateHandshakeCookie(cookie, secret, clientIP1, ephPub2, salt1, 30*time.Second) {
		t.Fatal("ephemeral key mismatch must be rejected")
	}

	// 5. Salt mismatch
	if ValidateHandshakeCookie(cookie, secret, clientIP1, ephPub1, salt2, 30*time.Second) {
		t.Fatal("salt mismatch must be rejected")
	}

	// 6. Expired cookie
	expiredCookie := GenerateHandshakeCookie(secret, clientIP1, ephPub1, salt1, tsNow.Add(-45*time.Second))
	if ValidateHandshakeCookie(expiredCookie, secret, clientIP1, ephPub1, salt1, 30*time.Second) {
		t.Fatal("expired cookie must be rejected")
	}

	// 7. Future clock skew cookie
	futureCookie := GenerateHandshakeCookie(secret, clientIP1, ephPub1, salt1, tsNow.Add(60*time.Second))
	if ValidateHandshakeCookie(futureCookie, secret, clientIP1, ephPub1, salt1, 30*time.Second) {
		t.Fatal("future cookie must be rejected")
	}

	// 8. Wrong server secret
	wrongSecret := make([]byte, 32)
	io.ReadFull(rand.Reader, wrongSecret)
	if ValidateHandshakeCookie(cookie, wrongSecret, clientIP1, ephPub1, salt1, 30*time.Second) {
		t.Fatal("wrong secret must be rejected")
	}
}

func TestPortHoppingDerivation(t *testing.T) {
	var sessionID [SessionIDSize]byte
	io.ReadFull(rand.Reader, sessionID[:])

	pool := []int{443, 8443, 2083, 50000, 50001, 50002, 50003}

	// 1. Deterministic synchronization between two independent peers
	for epoch := uint64(0); epoch < 100; epoch++ {
		portClient, err := DeriveHoppingPort(sessionID, epoch, pool)
		if err != nil {
			t.Fatal(err)
		}
		portServer, err := DeriveHoppingPort(sessionID, epoch, pool)
		if err != nil {
			t.Fatal(err)
		}
		if portClient != portServer {
			t.Fatalf("port mismatch at epoch %d: client=%d, server=%d", epoch, portClient, portServer)
		}

		inPool := false
		for _, p := range pool {
			if portClient == p {
				inPool = true
				break
			}
		}
		if !inPool {
			t.Fatalf("derived port %d not in pool", portClient)
		}
	}

	// 2. Distribution: 100 epochs should hit multiple distinct ports in pool
	seen := make(map[int]bool)
	for epoch := uint64(0); epoch < 100; epoch++ {
		p, _ := DeriveHoppingPort(sessionID, epoch, pool)
		seen[p] = true
	}
	if len(seen) < 3 {
		t.Fatalf("expected well-distributed ports, got %d distinct ports", len(seen))
	}

	// 3. End-to-end multi-socket port switching
	srvConnA, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer srvConnA.Close()

	srvConnB, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer srvConnB.Close()

	portA := srvConnA.LocalAddr().(*net.UDPAddr).Port
	portB := srvConnB.LocalAddr().(*net.UDPAddr).Port

	mux := NewUDPMux(srvConnA)
	mux.AddListener(srvConnB)

	sk := &SessionKeys{}
	io.ReadFull(rand.Reader, sk.SessionID[:])
	io.ReadFull(rand.Reader, sk.ClientKey[:])
	io.ReadFull(rand.Reader, sk.ServerKey[:])

	srvKeys := DeriveUDPKeys(sk, false)
	cliKeys := DeriveUDPKeys(sk, true)

	sess, err := mux.RegisterSession(srvKeys)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	go mux.Run()

	// Client starts communicating on Port A
	cliConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer cliConn.Close()

	cliCh, err := NewUDPChannel(cliConn, cliKeys)
	if err != nil {
		t.Fatal(err)
	}
	defer cliCh.Close()
	cliCh.SwitchDestination(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: portA})

	msgA := []byte("data-via-port-A")
	if err := cliCh.Send(msgA); err != nil {
		t.Fatal(err)
	}
	recA, err := sess.Recv()
	if err != nil || !bytes.Equal(recA, msgA) {
		t.Fatalf("port A recv failed: %v", err)
	}
	PutPacket(recA)

	// Switch destination to Port B (Port Hopping)
	cliCh.SetRemotePort(portB)

	msgB := []byte("data-via-port-B-after-hop")
	if err := cliCh.Send(msgB); err != nil {
		t.Fatal(err)
	}
	recB, err := sess.Recv()
	if err != nil || !bytes.Equal(recB, msgB) {
		t.Fatalf("port B recv failed: %v", err)
	}
	PutPacket(recB)

	// Server sends reply -> must arrive back to client seamlessly
	replyB := []byte("reply-from-server-on-active-port")
	if err := sess.Send(replyB); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	n, err := cliCh.Recv(buf)
	if err != nil || !bytes.Equal(buf[:n], replyB) {
		t.Fatalf("reply after hop failed: %v", err)
	}
}
