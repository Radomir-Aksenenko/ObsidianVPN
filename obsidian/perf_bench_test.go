package obsidian

import (
	"crypto/rand"
	"io"
	"net"
	"testing"
)

func BenchmarkPerfCipherEncrypt(b *testing.B) {
	var key [KeySize]byte
	var iv [NonceSize]byte
	_, _ = io.ReadFull(rand.Reader, key[:])
	_, _ = io.ReadFull(rand.Reader, iv[:])

	cipher, err := NewCipher(key, iv)
	if err != nil {
		b.Fatal(err)
	}

	payload := make([]byte, 1400)
	aad := []byte("obsidian_aad")
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = cipher.Encrypt(payload, aad)
	}
}

func BenchmarkPerfCipherEncryptWithBuffer(b *testing.B) {
	var key [KeySize]byte
	var iv [NonceSize]byte
	_, _ = io.ReadFull(rand.Reader, key[:])
	_, _ = io.ReadFull(rand.Reader, iv[:])

	cipher, err := NewCipher(key, iv)
	if err != nil {
		b.Fatal(err)
	}

	payload := make([]byte, 1400)
	aad := []byte("obsidian_aad")
	dst := make([]byte, len(payload)+TagSize)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = cipher.EncryptWithBuffer(dst, payload, aad)
	}
}

func BenchmarkPerfCipherDecryptWithBuffer(b *testing.B) {
	var key [KeySize]byte
	var iv [NonceSize]byte
	_, _ = io.ReadFull(rand.Reader, key[:])
	_, _ = io.ReadFull(rand.Reader, iv[:])

	enc, err := NewCipher(key, iv)
	if err != nil {
		b.Fatal(err)
	}
	dec, err := NewCipher(key, iv)
	if err != nil {
		b.Fatal(err)
	}

	payload := make([]byte, 1400)
	aad := []byte("obsidian_aad")
	ct := enc.Encrypt(payload, aad)
	dst := make([]byte, len(payload))
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Reset cipher counter so decryption matches
		dec.counter.Store(enc.counter.Load() - 1)
		_, _ = dec.DecryptWithBuffer(dst, ct, aad)
	}
}

func BenchmarkPerfRandomPadding(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = RandomPadding(16, 64)
	}
}

func BenchmarkPerfStreamFramerFrame(b *testing.B) {
	var key1, key2 [KeySize]byte
	var iv1, iv2 [NonceSize]byte
	enc, _ := NewCipher(key1, iv1)
	dec, _ := NewCipher(key2, iv2)

	framer := NewStreamFramer(enc, dec)
	payload := make([]byte, 1400)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = framer.Frame(PacketData, payload)
	}
}

func BenchmarkPerfStreamFramerFrameWithBuffer(b *testing.B) {
	var key1, key2 [KeySize]byte
	var iv1, iv2 [NonceSize]byte
	enc, _ := NewCipher(key1, iv1)
	dec, _ := NewCipher(key2, iv2)

	framer := NewStreamFramer(enc, dec)
	payload := make([]byte, 1400)
	dst := make([]byte, 4096)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = framer.FrameWithBuffer(dst, PacketData, payload)
	}
}

func BenchmarkPerfStreamFramerParseFrame(b *testing.B) {
	var key [KeySize]byte
	var iv [NonceSize]byte
	enc, _ := NewCipher(key, iv)
	dec, _ := NewCipher(key, iv)

	framer := NewStreamFramer(enc, dec)
	payload := make([]byte, 1400)
	frame, err := framer.Frame(PacketData, payload)
	if err != nil {
		b.Fatal(err)
	}
	rawPacket := frame[4:] // without frame len
	dst := make([]byte, 2048)

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		dec.counter.Store(enc.counter.Load() - 1)
		framer.decFrameCtr = framer.encFrameCtr - 1
		_, _ = framer.ParseFrameWithBuffer(dst, rawPacket)
	}
}

func BenchmarkPerfStreamFramerParseFrameInto(b *testing.B) {
	var key [KeySize]byte
	var iv [NonceSize]byte
	enc, _ := NewCipher(key, iv)
	dec, _ := NewCipher(key, iv)

	framer := NewStreamFramer(enc, dec)
	payload := make([]byte, 1400)
	frame, err := framer.Frame(PacketData, payload)
	if err != nil {
		b.Fatal(err)
	}
	rawPacket := frame[4:]
	dst := make([]byte, 2048)

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		dec.counter.Store(enc.counter.Load() - 1)
		framer.decFrameCtr = framer.encFrameCtr - 1
		_, _, _ = framer.ParseFrameInto(dst, rawPacket)
	}
}

func BenchmarkPerfUDPChannelSendRecv(b *testing.B) {
	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		b.Fatal(err)
	}
	defer clientConn.Close()

	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		b.Fatal(err)
	}
	defer serverConn.Close()

	sk := &SessionKeys{}
	_, _ = io.ReadFull(rand.Reader, sk.ClientKey[:])
	_, _ = io.ReadFull(rand.Reader, sk.ServerKey[:])
	_, _ = io.ReadFull(rand.Reader, sk.SessionID[:])

	clientKeys := DeriveUDPKeys(sk, true)
	serverKeys := DeriveUDPKeys(sk, false)

	clientCh, err := NewUDPChannel(clientConn, clientKeys)
	if err != nil {
		b.Fatal(err)
	}
	defer clientCh.Close()
	clientCh.SwitchDestination(serverConn.LocalAddr().(*net.UDPAddr))

	serverCh, err := NewUDPChannel(serverConn, serverKeys)
	if err != nil {
		b.Fatal(err)
	}
	defer serverCh.Close()

	payload := make([]byte, 1360)
	recvBuf := make([]byte, 2048)
	sendBuf := make([]byte, 2048)

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		err := clientCh.SendWithBuffer(payload, sendBuf)
		if err != nil {
			b.Fatal(err)
		}
		_, err = serverCh.Recv(recvBuf)
		if err != nil {
			b.Fatal(err)
		}
	}
}
