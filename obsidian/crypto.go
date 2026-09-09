package obsidian

import (
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"
	randv2 "math/rand/v2"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	KeySize       = 32
	NonceSize     = 12
	TagSize       = 16
	SessionIDSize = 16

	// ML-KEM-768 (NIST FIPS 203) parameter sizes
	MLKEM768EncapsulationKeySize = 1184
	MLKEM768CiphertextSize       = 1088
	MLKEM768SharedKeySize        = 32
)

// ── Key generation ────────────────────────────────────────────────────────────

type Keypair struct {
	Private [KeySize]byte
	Public  [KeySize]byte
}

type MLKEMKeypair struct {
	DecapsulationKey *mlkem.DecapsulationKey768
	EncapsulationKey *mlkem.EncapsulationKey768
}

func GenerateMLKEMKeypair() (*MLKEMKeypair, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("generate ml-kem-768 key: %w", err)
	}
	return &MLKEMKeypair{
		DecapsulationKey: dk,
		EncapsulationKey: dk.EncapsulationKey(),
	}, nil
}

// EncapsulateMLKEM produces a shared key and ciphertext for peer's encapsulation key.
func EncapsulateMLKEM(encKeyBytes []byte) ([]byte, []byte, error) {
	if len(encKeyBytes) != MLKEM768EncapsulationKeySize {
		return nil, nil, fmt.Errorf("invalid ml-kem encapsulation key size: %d, expected %d", len(encKeyBytes), MLKEM768EncapsulationKeySize)
	}
	ek, err := mlkem.NewEncapsulationKey768(encKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ml-kem encapsulation key: %w", err)
	}
	sharedKey, ciphertext := ek.Encapsulate()
	return sharedKey, ciphertext, nil
}

// DecapsulateMLKEM extracts the shared key from ciphertext using decapsulation key.
func DecapsulateMLKEM(dk *mlkem.DecapsulationKey768, ciphertext []byte) ([]byte, error) {
	if dk == nil {
		return nil, errors.New("nil ml-kem decapsulation key")
	}
	if len(ciphertext) != MLKEM768CiphertextSize {
		return nil, fmt.Errorf("invalid ml-kem ciphertext size: %d, expected %d", len(ciphertext), MLKEM768CiphertextSize)
	}
	return dk.Decapsulate(ciphertext)
}

// DeriveHybridSecret combines X25519 and ML-KEM-768 shared secrets using Dual-PRF Combiner:
// SS_hybrid = HKDF-Extract(salt, SS_X25519 || SS_MLKEM)
func DeriveHybridSecret(ssX25519 []byte, ssMLKEM []byte, salt []byte) [KeySize]byte {
	ikm := make([]byte, len(ssX25519)+len(ssMLKEM))
	copy(ikm[:len(ssX25519)], ssX25519)
	copy(ikm[len(ssX25519):], ssMLKEM)

	if len(salt) == 0 {
		salt = []byte("obsidian_hybrid_x25519_mlkem768_v1")
	}
	prk := hkdf.Extract(sha256.New, ikm, salt)
	var out [KeySize]byte
	copy(out[:], prk)
	return out
}

func (kp *Keypair) Zero() {
	if kp == nil {
		return
	}
	for i := range kp.Private {
		kp.Private[i] = 0
	}
	for i := range kp.Public {
		kp.Public[i] = 0
	}
}

func GenerateKeypair() (*Keypair, error) {
	kp := &Keypair{}
	if _, err := io.ReadFull(rand.Reader, kp.Private[:]); err != nil {
		return nil, err
	}
	// Clamp per RFC 7748
	kp.Private[0] &= 248
	kp.Private[31] &= 127
	kp.Private[31] |= 64

	pub, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(kp.Public[:], pub)
	return kp, nil
}

func KeypairFromPrivate(private [KeySize]byte) (*Keypair, error) {
	kp := &Keypair{Private: private}
	// Clamp defensively so keys loaded from config are always valid X25519 scalars.
	kp.Private[0] &= 248
	kp.Private[31] &= 127
	kp.Private[31] |= 64

	pub, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(kp.Public[:], pub)
	return kp, nil
}

func DH(priv [KeySize]byte, peerPub [KeySize]byte) ([KeySize]byte, error) {
	shared, err := curve25519.X25519(priv[:], peerPub[:])
	if err != nil {
		return [KeySize]byte{}, err
	}
	var out [KeySize]byte
	copy(out[:], shared)
	return out, nil
}

// ── KDF (HKDF-SHA256) ────────────────────────────────────────────────────────

type SessionKeys struct {
	ClientKey [KeySize]byte
	ServerKey [KeySize]byte
	ClientIV  [NonceSize]byte
	ServerIV  [NonceSize]byte
	SessionID [SessionIDSize]byte
	// DynamicMagic — уникальный 16-байтовый magic производный от сессии.
	// Каждое соединение имеет свой magic — DPI не может написать универсальное правило.
	DynamicMagic [16]byte
}

func (sk *SessionKeys) Zero() {
	if sk == nil {
		return
	}
	for i := range sk.ClientKey {
		sk.ClientKey[i] = 0
	}
	for i := range sk.ServerKey {
		sk.ServerKey[i] = 0
	}
	for i := range sk.ClientIV {
		sk.ClientIV[i] = 0
	}
	for i := range sk.ServerIV {
		sk.ServerIV[i] = 0
	}
	for i := range sk.SessionID {
		sk.SessionID[i] = 0
	}
	for i := range sk.DynamicMagic {
		sk.DynamicMagic[i] = 0
	}
}

func DeriveKeys(sharedSecret [KeySize]byte, salt []byte, clientPub, serverPub [KeySize]byte) (*SessionKeys, error) {
	info := make([]byte, 0, 11+KeySize+KeySize)
	info = append(info, []byte("obsidian_v2")...)
	info = append(info, clientPub[:]...)
	info = append(info, serverPub[:]...)

	r := hkdf.New(sha256.New, sharedSecret[:], salt, info)

	// client_key(32) + server_key(32) + client_iv(12) + server_iv(12) + session_id(16) + dynamic_magic(16) = 120
	buf := make([]byte, 32+32+12+12+16+16)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	sk := &SessionKeys{}
	copy(sk.ClientKey[:], buf[0:32])
	copy(sk.ServerKey[:], buf[32:64])
	copy(sk.ClientIV[:], buf[64:76])
	copy(sk.ServerIV[:], buf[76:88])
	copy(sk.SessionID[:], buf[88:104])
	copy(sk.DynamicMagic[:], buf[104:120])
	return sk, nil
}

func DeriveTCPHeaderKeys(sk *SessionKeys) (clientHeaderKey, serverHeaderKey [KeySize]byte) {
	combined := make([]byte, 64)
	copy(combined[0:32], sk.ClientKey[:])
	copy(combined[32:64], sk.ServerKey[:])
	r := hkdf.New(sha256.New, combined, sk.SessionID[:], []byte("obsidian_tcp_header_v2"))
	_, _ = io.ReadFull(r, clientHeaderKey[:])
	_, _ = io.ReadFull(r, serverHeaderKey[:])
	return clientHeaderKey, serverHeaderKey
}

// ── AEAD (ChaCha20-Poly1305) ─────────────────────────────────────────────────

type Cipher struct {
	aead interface {
		Overhead() int
		NonceSize() int
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	}
	baseIV  [NonceSize]byte
	counter atomic.Uint64
}

func NewCipher(key [KeySize]byte, baseIV [NonceSize]byte) (*Cipher, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead, baseIV: baseIV}, nil
}

func (c *Cipher) nonce() [NonceSize]byte {
	var n [NonceSize]byte
	copy(n[:], c.baseIV[:])
	ctr := c.counter.Add(1) - 1
	var counter [8]byte
	binary.LittleEndian.PutUint64(counter[:], ctr)
	for i := 0; i < 8; i++ {
		n[i] ^= counter[i]
	}
	return n
}

func (c *Cipher) Encrypt(plaintext, aad []byte) []byte {
	n := c.nonce()
	return c.aead.Seal(nil, n[:], plaintext, aad)
}

func (c *Cipher) EncryptWithBuffer(dst, plaintext, aad []byte) []byte {
	n := c.nonce()
	return c.aead.Seal(dst[:0], n[:], plaintext, aad)
}

func (c *Cipher) Decrypt(ciphertext, aad []byte) ([]byte, error) {
	n := c.nonce()
	return c.aead.Open(nil, n[:], ciphertext, aad)
}

func (c *Cipher) DecryptWithBuffer(dst, ciphertext, aad []byte) ([]byte, error) {
	n := c.nonce()
	return c.aead.Open(dst[:0], n[:], ciphertext, aad)
}

// DeriveRouteTag derives a deterministic 4-byte pseudorandom tag for O(1) session routing.
func DeriveRouteTag(sessionID [SessionIDSize]byte, epoch uint64) [4]byte {
	var epochBuf [8]byte
	binary.BigEndian.PutUint64(epochBuf[:], epoch)
	mac := HmacSHA256(sessionID[:], append([]byte("obsidian_routetag_v2"), epochBuf[:]...))
	var tag [4]byte
	copy(tag[:], mac[:4])
	return tag
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// FastRandomBytes fills dst with pseudo-random bytes generated in userspace without syscall overhead.
func FastRandomBytes(dst []byte) {
	for len(dst) >= 8 {
		u := randv2.Uint64()
		binary.LittleEndian.PutUint64(dst[:8], u)
		dst = dst[8:]
	}
	if len(dst) > 0 {
		u := randv2.Uint64()
		for i := range dst {
			dst[i] = byte(u)
			u >>= 8
		}
	}
}

// FastRandomPaddingInplace fills dst with random padding bytes of length in range [min, max) and returns chosen length.
func FastRandomPaddingInplace(dst []byte, min, max int) int {
	if max <= min {
		if min > len(dst) {
			min = len(dst)
		}
		FastRandomBytes(dst[:min])
		return min
	}
	diff := max - min
	size := min + randv2.IntN(diff)
	if size > len(dst) {
		size = len(dst)
	}
	FastRandomBytes(dst[:size])
	return size
}

func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// RandomPadding возвращает случайный padding размером [min, max) байт.
// Использует быстрый генератор без системных вызовов в hot path.
func RandomPadding(min, max int) ([]byte, error) {
	if max <= min {
		b := make([]byte, min)
		FastRandomBytes(b)
		return b, nil
	}
	size := min + randv2.IntN(max-min)
	b := make([]byte, size)
	FastRandomBytes(b)
	return b, nil
}

func ConstantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func HmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

var errZeroShared = errors.New("DH produced all-zero shared secret (possible attack)")

func DHSafe(priv [KeySize]byte, peerPub [KeySize]byte) ([KeySize]byte, error) {
	shared, err := DH(priv, peerPub)
	if err != nil {
		return [KeySize]byte{}, err
	}
	var zero [KeySize]byte
	if subtle.ConstantTimeCompare(shared[:], zero[:]) == 1 {
		return [KeySize]byte{}, errZeroShared
	}
	return shared, nil
}

// ── In-Tunnel Key Ratchet & Enterprise Extensions ───────────────────────────

const (
	CookieSize          = 32
	DefaultCookieMaxAge = 30 * time.Second
)

// DeriveNextEpochKeys derives the next epoch session keys (In-Tunnel Key Ratchet)
// for forward-secure, seamless rekeying without interrupting in-flight streams.
func DeriveNextEpochKeys(currentKeys *SessionKeys, epoch uint64) (*SessionKeys, error) {
	if currentKeys == nil {
		return nil, errors.New("nil session keys")
	}
	ikm := make([]byte, 32+32+SessionIDSize)
	copy(ikm[0:32], currentKeys.ClientKey[:])
	copy(ikm[32:64], currentKeys.ServerKey[:])
	copy(ikm[64:], currentKeys.SessionID[:])

	var salt [8 + SessionIDSize]byte
	binary.BigEndian.PutUint64(salt[0:8], epoch)
	copy(salt[8:], currentKeys.SessionID[:])

	info := []byte("obsidian_epoch_ratchet_v2")
	r := hkdf.New(sha256.New, ikm, salt[:], info)

	buf := make([]byte, 32+32+12+12+16+16)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("epoch key expansion: %w", err)
	}

	sk := &SessionKeys{}
	copy(sk.ClientKey[:], buf[0:32])
	copy(sk.ServerKey[:], buf[32:64])
	copy(sk.ClientIV[:], buf[64:76])
	copy(sk.ServerIV[:], buf[76:88])
	copy(sk.SessionID[:], buf[88:104])
	copy(sk.DynamicMagic[:], buf[104:120])
	return sk, nil
}

// DeriveHoppingPort computes a deterministic pseudorandom port from the port pool
// based on the session secret and current epoch:
// Port_k = PortPool[HKDF(SessionSecret, Epoch) mod N]
func DeriveHoppingPort(sessionID [SessionIDSize]byte, epoch uint64, pool []int) (int, error) {
	if len(pool) == 0 {
		return 0, errors.New("empty port pool")
	}
	if len(pool) == 1 {
		return pool[0], nil
	}
	var epochBuf [8]byte
	binary.BigEndian.PutUint64(epochBuf[:], epoch)

	macData := make([]byte, 0, len("obsidian_port_hop_v1")+8)
	macData = append(macData, []byte("obsidian_port_hop_v1")...)
	macData = append(macData, epochBuf[:]...)

	mac := HmacSHA256(sessionID[:], macData)
	val := binary.BigEndian.Uint32(mac[:4])
	idx := int(val % uint32(len(pool)))
	return pool[idx], nil
}

// GenerateHandshakeCookie produces a 32-byte stateless challenge token:
// Cookie = Timestamp(8) || HMAC-SHA256(ServerSecret, ClientIP || ClientEphPub || Salt || Timestamp)[:24]
func GenerateHandshakeCookie(secret []byte, clientIP net.IP, clientEphPub [KeySize]byte, salt []byte, ts time.Time) []byte {
	var tsBytes [8]byte
	binary.BigEndian.PutUint64(tsBytes[:], uint64(ts.Unix()))

	ipBytes := clientIP
	if v4 := clientIP.To4(); v4 != nil {
		ipBytes = v4
	}

	input := make([]byte, 0, len(ipBytes)+KeySize+len(salt)+8)
	input = append(input, ipBytes...)
	input = append(input, clientEphPub[:]...)
	input = append(input, salt...)
	input = append(input, tsBytes[:]...)

	mac := HmacSHA256(secret, input)

	cookie := make([]byte, CookieSize)
	copy(cookie[:8], tsBytes[:])
	copy(cookie[8:], mac[:24])
	return cookie
}

// ValidateHandshakeCookie verifies a stateless challenge cookie using constant-time MAC comparison
// and enforces freshness within maxAge.
func ValidateHandshakeCookie(cookie, secret []byte, clientIP net.IP, clientEphPub [KeySize]byte, salt []byte, maxAge time.Duration) bool {
	if len(cookie) != CookieSize || len(secret) == 0 {
		return false
	}
	if maxAge <= 0 {
		maxAge = DefaultCookieMaxAge
	}

	tsSec := int64(binary.BigEndian.Uint64(cookie[:8]))
	now := time.Now().Unix()
	if tsSec > now+15 || now-tsSec > int64(maxAge.Seconds()) {
		return false
	}

	ipBytes := clientIP
	if v4 := clientIP.To4(); v4 != nil {
		ipBytes = v4
	}

	input := make([]byte, 0, len(ipBytes)+KeySize+len(salt)+8)
	input = append(input, ipBytes...)
	input = append(input, clientEphPub[:]...)
	input = append(input, salt...)
	input = append(input, cookie[:8]...)

	expectedMAC := HmacSHA256(secret, input)
	return subtle.ConstantTimeCompare(cookie[8:CookieSize], expectedMAC[:24]) == 1
}
