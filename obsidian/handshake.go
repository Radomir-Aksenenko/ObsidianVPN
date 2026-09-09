package obsidian

// ── Handshake (Noise_IK-like) ─────────────────────────────────────────────────
//
// Улучшения v2:
//   - DynamicMagic: magic производный от DH shared secret — уникален для каждой сессии,
//     DPI не может написать универсальное правило по фиксированным байтам
//   - Junk packet train: перед ClientHello отправляются Jc мусорных UDP-подобных пакетов
//     (идея из AmneziaWG) — ломает поведенческую сигнатуру установки соединения
//   - Настраиваемый padding S1–S4 для каждого типа сообщений handshake
//   - Pre-padding: случайные байты ДО ephemeral key в ClientHello — ломает
//     детерминированный offset первого поля
//
// Структура ClientHello v2:
//   [pre_pad_len: 1][pre_pad: pre_pad_len]
//   [junk_count: 1] — сколько junk пакетов было отправлено перед этим
//   [client_ephemeral_pub: 32]
//   [salt: 32]
//   [enc_identity_len: 2][enc_identity]   → Encrypt(DynMagic||client_static_pub||ts, aad=eph_pub)
//   [s1_pad_len: 2][s1_pad]
//
// Структура ServerHello v2:
//   [pre_pad_len: 1][pre_pad: pre_pad_len]
//   [server_ephemeral_pub: 32]
//   [enc_confirm_len: 2][enc_confirm]     → Encrypt(DynMagic||session_id||server_proof, aad=srv_eph_pub)
//   [s2_pad_len: 2][s2_pad]

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

const replayWindowSec = 30

const (
	helloNonceSize     = 16
	helloTagSize       = 8
	helloLenSize       = 4
	helloFrameOverhead = helloNonceSize + helloTagSize + helloLenSize
)

// ObfuscationConfig — полные параметры обфускации (S1–S4, Jc/Jmin/Jmax, H1–H4, i1–i5, MaxTrailer).
type ObfuscationConfig struct {
	// Junk packets перед handshake (Jc/Jmin/Jmax из AWG)
	JunkCount int
	JunkMin   int
	JunkMax   int

	// Padding в handshake сообщениях (S1/S2 из AWG)
	S1Min, S1Max int
	S2Min, S2Max int

	// Pre-padding (случайный префикс каждого сообщения)
	PrePadMax int

	// MaxTrailer (AmneziaWG 3.1) — динамический случайный хвост бакета
	MaxTrailer int

	// Signature packets i1–i5 (CPS строки, nil = не использовать)
	// Отправляются перед каждым junk train и handshake.
	// Wireshark будет видеть их как QUIC/DNS/SIP.
	Signatures []*CPSSignature

	// HeaderConfig — диапазоны H1–H4 для range-based заголовков пакетов
	Headers HeaderConfig
}

func DefaultObfuscationConfig() ObfuscationConfig {
	return ObfuscationConfig{
		JunkCount:  3,
		JunkMin:    64,
		JunkMax:    512,
		S1Min:      64,
		S1Max:      256,
		S2Min:      64,
		S2Max:      256,
		PrePadMax:  64,
		MaxTrailer: 32,
		Signatures: nil, // CPS signatures are transport-specific and configured explicitly
		Headers:    DefaultHeaderConfig(),
	}
}

// BuildSignatureTrain генерирует все signature packets (i1–i5) для отправки перед handshake.
// Каждый пакет оборачивается в length-prefix frame (как junk packets).
// Возвращает nil если сигнатур нет.
func BuildSignatureTrain(sigs []*CPSSignature) ([]byte, error) {
	if len(sigs) == 0 {
		return nil, nil
	}
	var out []byte
	for _, sig := range sigs {
		if sig == nil {
			continue
		}
		pkt, err := sig.Generate()
		if err != nil {
			return nil, fmt.Errorf("signature generate: %w", err)
		}
		frame := make([]byte, 4+len(pkt))
		binary.BigEndian.PutUint32(frame[:4], uint32(len(pkt)))
		copy(frame[4:], pkt)
		out = append(out, frame...)
	}
	return out, nil
}

// ── Junk packets ──────────────────────────────────────────────────────────────

// BuildJunkTrain строит серию мусорных пакетов для отправки перед handshake.
// Каждый пакет имеет случайный размер и случайное содержимое.
// Формат каждого junk пакета (length-prefixed как обычные фреймы):
//
//	[FRAME_LEN: 4][RANDOM_BYTES: FRAME_LEN]
func BuildJunkTrain(cfg ObfuscationConfig) ([]byte, int, error) {
	if cfg.JunkCount == 0 {
		return nil, 0, nil
	}
	rb, err := RandomBytes(1)
	if err != nil {
		return nil, 0, err
	}
	count := 1 + int(rb[0])%cfg.JunkCount
	var out []byte
	for i := 0; i < count; i++ {
		size, err := randomRangeInt(cfg.JunkMin, cfg.JunkMax)
		if err != nil {
			return nil, 0, err
		}
		payload, err := RandomBytes(size)
		if err != nil {
			return nil, 0, err
		}
		frame := make([]byte, 4+size)
		binary.BigEndian.PutUint32(frame[:4], uint32(size))
		copy(frame[4:], payload)
		out = append(out, frame...)
	}
	return out, count, nil
}

// BuildHelloFrame wraps a handshake message in a randomized, server-specific frame.
// Wire format:
//
//	nonce(16) || tag(8) || masked_len(4) || payload
const helloFrameLabel = "obsidian_hello_frame_v3"

// BuildHelloFrame wraps a handshake message in a randomized, server-specific frame.
// Wire format:
//
//	nonce(16) || tag(8) || masked_len(4) || payload
//
// tag and len mask are HMAC-derived from the server public key and nonce, so there is no stable sentinel.
func BuildHelloFrame(serverPub [KeySize]byte, payload []byte) ([]byte, error) {
	if len(payload) > 8192 {
		return nil, fmt.Errorf("hello payload too large: %d", len(payload))
	}
	nonce, err := RandomBytes(helloNonceSize)
	if err != nil {
		return nil, err
	}
	var macInput [helloNonceSize + len(helloFrameLabel)]byte
	copy(macInput[:helloNonceSize], nonce)
	copy(macInput[helloNonceSize:], helloFrameLabel)
	mac := HmacSHA256(serverPub[:], macInput[:])

	out := make([]byte, helloFrameOverhead+len(payload))
	copy(out[:helloNonceSize], nonce)
	copy(out[helloNonceSize:helloNonceSize+helloTagSize], mac[:helloTagSize])
	maskedLen := uint32(len(payload)) ^ binary.BigEndian.Uint32(mac[helloTagSize:helloTagSize+helloLenSize])
	binary.BigEndian.PutUint32(out[helloNonceSize+helloTagSize:helloFrameOverhead], maskedLen)
	copy(out[helloFrameOverhead:], payload)
	return out, nil
}

// ReadHelloFrame scans a stream for a randomized hello frame addressed to serverPub.
// It tolerates signature/junk bytes before the frame without relying on a fixed magic value.
// It is optimized for zero per-iteration allocations and protected against CPU DoS attacks.
func ReadHelloFrame(r io.Reader, serverPub [KeySize]byte, maxScan, maxPayload int) ([]byte, error) {
	if maxScan <= 0 {
		maxScan = 4096
	}
	if maxPayload <= 0 {
		maxPayload = 8192
	}
	buf := make([]byte, helloFrameOverhead)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	var macInput [helloNonceSize + len(helloFrameLabel)]byte
	copy(macInput[helloNonceSize:], helloFrameLabel)

	scanned := helloFrameOverhead
	for {
		copy(macInput[:helloNonceSize], buf[:helloNonceSize])
		mac := HmacSHA256(serverPub[:], macInput[:])
		if ConstantTimeEqual(buf[helloNonceSize:helloNonceSize+helloTagSize], mac[:helloTagSize]) {
			maskedLen := binary.BigEndian.Uint32(buf[helloNonceSize+helloTagSize : helloFrameOverhead])
			payloadLen := int(maskedLen ^ binary.BigEndian.Uint32(mac[helloTagSize:helloTagSize+helloLenSize]))
			if payloadLen < 0 || payloadLen > maxPayload {
				return nil, fmt.Errorf("hello payload too large: %d", payloadLen)
			}
			payload := make([]byte, payloadLen)
			if _, err := io.ReadFull(r, payload); err != nil {
				return nil, fmt.Errorf("read hello payload: %w", err)
			}
			return payload, nil
		}
		if scanned >= maxScan {
			return nil, fmt.Errorf("hello frame not found after %d bytes", scanned)
		}
		copy(buf, buf[1:])
		if _, err := io.ReadFull(r, buf[len(buf)-1:]); err != nil {
			return nil, err
		}
		scanned++
	}
}

// ── Client ────────────────────────────────────────────────────────────────────

type ClientHandshake struct {
	serverStaticPub  [KeySize]byte
	ephemeralKeypair *Keypair
	mlkemKeypair     *MLKEMKeypair
	staticKeypair    *Keypair
	salt             []byte
	SessionKeys      *SessionKeys
	ObfCfg           ObfuscationConfig
}

func NewClientHandshake(serverStaticPub [KeySize]byte) (*ClientHandshake, error) {
	return NewClientHandshakeWithConfig(serverStaticPub, DefaultObfuscationConfig())
}

func NewClientHandshakeWithConfig(serverStaticPub [KeySize]byte, cfg ObfuscationConfig) (*ClientHandshake, error) {
	static, err := GenerateKeypair()
	if err != nil {
		return nil, err
	}
	return NewClientHandshakeWithStaticKey(serverStaticPub, static, cfg)
}

func NewClientHandshakeWithStaticKey(serverStaticPub [KeySize]byte, static *Keypair, cfg ObfuscationConfig) (*ClientHandshake, error) {
	if static == nil {
		return nil, errors.New("client static keypair is nil")
	}
	eph, err := GenerateKeypair()
	if err != nil {
		return nil, err
	}
	mlkemKP, err := GenerateMLKEMKeypair()
	if err != nil {
		return nil, err
	}
	salt, err := RandomBytes(32)
	if err != nil {
		return nil, err
	}
	return &ClientHandshake{
		serverStaticPub:  serverStaticPub,
		ephemeralKeypair: eph,
		mlkemKeypair:     mlkemKP,
		staticKeypair:    static,
		salt:             salt,
		ObfCfg:           cfg,
	}, nil
}

func (c *ClientHandshake) ClientStaticPub() [KeySize]byte {
	return c.staticKeypair.Public
}

// BuildSignatureTrain возвращает signature packets (i1–i5) для отправки ПЕРВЫМИ.
func (c *ClientHandshake) BuildSignatureTrain() ([]byte, error) {
	return BuildSignatureTrain(c.ObfCfg.Signatures)
}

// BuildJunkTrain возвращает мусорные пакеты для отправки после signature packets.
func (c *ClientHandshake) BuildJunkTrain() ([]byte, error) {
	data, _, err := BuildJunkTrain(c.ObfCfg)
	return data, err
}

// BuildHello строит ClientHello с гибридным обменом ключами (X25519 + ML-KEM-768).
func (c *ClientHandshake) BuildHello() ([]byte, error) {
	// Временный DH для шифрования identity
	shared, err := DHSafe(c.ephemeralKeypair.Private, c.serverStaticPub)
	if err != nil {
		return nil, err
	}
	tmpKeys, err := DeriveKeys(shared, c.salt, c.ephemeralKeypair.Public, c.serverStaticPub)
	if err != nil {
		return nil, err
	}
	tmpCipher, err := NewCipher(tmpKeys.ClientKey, tmpKeys.ClientIV)
	if err != nil {
		return nil, err
	}

	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(time.Now().Unix()))

	mlkemEncPub := c.mlkemKeypair.EncapsulationKey.Bytes()

	// Static proof: только владелец client_static_private может вычислить DH(client_static, server_static).
	// Включаем mlkemEncPub в proofData для криптографической защиты от подмены ML-KEM ключа.
	staticShared, err := DHSafe(c.staticKeypair.Private, c.serverStaticPub)
	if err != nil {
		return nil, err
	}
	proofData := make([]byte, 0, 16+KeySize+len(mlkemEncPub)+32+8)
	proofData = append(proofData, tmpKeys.DynamicMagic[:]...)
	proofData = append(proofData, c.ephemeralKeypair.Public[:]...)
	proofData = append(proofData, mlkemEncPub...)
	proofData = append(proofData, c.salt...)
	proofData = append(proofData, ts...)
	clientProof := HmacSHA256(staticShared[:], proofData)

	identity := make([]byte, 0, 16+KeySize+8+32)
	identity = append(identity, tmpKeys.DynamicMagic[:]...)
	identity = append(identity, c.staticKeypair.Public[:]...)
	identity = append(identity, ts...)
	identity = append(identity, clientProof...)

	identityAAD := make([]byte, 0, KeySize+len(mlkemEncPub))
	identityAAD = append(identityAAD, c.ephemeralKeypair.Public[:]...)
	identityAAD = append(identityAAD, mlkemEncPub...)
	encIdentity := tmpCipher.Encrypt(identity, identityAAD)

	// S1 padding
	s1, err := RandomPadding(c.ObfCfg.S1Min, c.ObfCfg.S1Max)
	if err != nil {
		return nil, err
	}

	// Pre-padding (случайный offset перед первым полем)
	prePad, err := prePadding(c.ObfCfg.PrePadMax)
	if err != nil {
		return nil, err
	}

	var out []byte
	out = append(out, byte(len(prePad)))
	out = append(out, prePad...)
	out = append(out, c.ephemeralKeypair.Public[:]...)
	out = append(out, mlkemEncPub...)
	out = append(out, c.salt...)
	out = appendUint16(out, uint16(len(encIdentity)))
	out = append(out, encIdentity...)
	out = appendUint16(out, uint16(len(s1)))
	out = append(out, s1...)
	return out, nil
}

// ProcessServerHello обрабатывает ServerHello с гибридным постквантовым ответом.
func (c *ClientHandshake) ProcessServerHello(data []byte) (*StreamFramer, error) {
	if len(data) < 1 {
		return nil, errors.New("server hello too short")
	}
	offset := 0

	// Pre-padding
	prePadLen := int(data[offset])
	offset++
	if len(data) < offset+prePadLen+KeySize+MLKEM768CiphertextSize+2 {
		return nil, errors.New("server hello truncated at pre-pad")
	}
	offset += prePadLen // пропускаем

	var serverEphPub [KeySize]byte
	copy(serverEphPub[:], data[offset:offset+KeySize])
	offset += KeySize

	serverMLKEMCiphertext := data[offset : offset+MLKEM768CiphertextSize]
	offset += MLKEM768CiphertextSize

	if len(data) < offset+2 {
		return nil, errors.New("server hello truncated at conf_len")
	}
	confLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if len(data) < offset+confLen {
		return nil, errors.New("server hello truncated at confirm")
	}
	encConfirm := data[offset : offset+confLen]

	// Финальный DH X25519
	sharedX25519, err := DHSafe(c.ephemeralKeypair.Private, serverEphPub)
	if err != nil {
		return nil, err
	}

	// Декапсуляция ML-KEM-768
	sharedMLKEM, err := DecapsulateMLKEM(c.mlkemKeypair.DecapsulationKey, serverMLKEMCiphertext)
	if err != nil {
		return nil, fmt.Errorf("ml-kem decapsulate failed: %w", err)
	}

	// Dual-PRF Combiner: SS_hybrid = HKDF-Extract(salt, SS_X25519 || SS_MLKEM)
	hybridSecret := DeriveHybridSecret(sharedX25519[:], sharedMLKEM, c.salt)

	c.SessionKeys, err = DeriveKeys(hybridSecret, c.salt, c.ephemeralKeypair.Public, serverEphPub)
	if err != nil {
		return nil, err
	}

	// Расшифровываем confirm используя DynamicMagic из финальных ключей
	srvCipher, err := NewCipher(c.SessionKeys.ServerKey, c.SessionKeys.ServerIV)
	if err != nil {
		return nil, err
	}
	confirmAAD := make([]byte, 0, KeySize+len(serverMLKEMCiphertext))
	confirmAAD = append(confirmAAD, serverEphPub[:]...)
	confirmAAD = append(confirmAAD, serverMLKEMCiphertext...)
	confirm, err := srvCipher.Decrypt(encConfirm, confirmAAD)
	if err != nil {
		return nil, fmt.Errorf("handshake confirm decrypt failed: %w", err)
	}
	if len(confirm) != 16+SessionIDSize+32 {
		return nil, errors.New("confirm too short")
	}
	if !ConstantTimeEqual(confirm[:16], c.SessionKeys.DynamicMagic[:]) {
		return nil, errors.New("handshake magic mismatch — possible MITM or wrong server key")
	}
	if !ConstantTimeEqual(confirm[16:16+SessionIDSize], c.SessionKeys.SessionID[:]) {
		return nil, errors.New("handshake session ID mismatch")
	}
	staticShared, err := DHSafe(c.ephemeralKeypair.Private, c.serverStaticPub)
	if err != nil {
		return nil, fmt.Errorf("server static authentication: %w", err)
	}
	expectedProof := serverStaticProof(staticShared, c.ephemeralKeypair.Public, c.salt, serverEphPub, c.SessionKeys.SessionID)
	if !ConstantTimeEqual(confirm[16+SessionIDSize:], expectedProof) {
		return nil, errors.New("server static proof mismatch — possible MITM or wrong server key")
	}

	cliEnc, err := NewCipher(c.SessionKeys.ClientKey, c.SessionKeys.ClientIV)
	if err != nil {
		return nil, err
	}
	srvDec, err := NewCipher(c.SessionKeys.ServerKey, c.SessionKeys.ServerIV)
	if err != nil {
		return nil, err
	}
	clientHeaderKey, serverHeaderKey := DeriveTCPHeaderKeys(c.SessionKeys)
	framer := NewProtectedStreamFramer(cliEnc, srvDec, clientHeaderKey, serverHeaderKey)
	framer.HeaderCfg = c.ObfCfg.Headers
	c.ephemeralKeypair.Zero()
	return framer, nil
}

// ── Server ────────────────────────────────────────────────────────────────────

type ServerHandshake struct {
	staticPriv      [KeySize]byte
	staticPub       [KeySize]byte
	ephKeypair      *Keypair
	allowedClients  map[[KeySize]byte]struct{}
	clientStaticPub [KeySize]byte
	SessionKeys     *SessionKeys
	ObfCfg          ObfuscationConfig
}

// ClientStaticPub returns the authenticated client identity from the last
// successful ProcessClientHello call. It is used by the server policy layer for
// revocation checks before a session is accepted.
func (s *ServerHandshake) ClientStaticPub() [KeySize]byte {
	return s.clientStaticPub
}

func NewServerHandshake(staticPriv, staticPub [KeySize]byte, allowedClients [][KeySize]byte) (*ServerHandshake, error) {
	return NewServerHandshakeWithConfig(staticPriv, staticPub, allowedClients, DefaultObfuscationConfig())
}

func NewServerHandshakeWithConfig(staticPriv, staticPub [KeySize]byte, allowedClients [][KeySize]byte, cfg ObfuscationConfig) (*ServerHandshake, error) {
	eph, err := GenerateKeypair()
	if err != nil {
		return nil, err
	}
	sh := &ServerHandshake{
		staticPriv: staticPriv,
		staticPub:  staticPub,
		ephKeypair: eph,
		ObfCfg:     cfg,
	}
	if allowedClients != nil {
		sh.allowedClients = make(map[[KeySize]byte]struct{}, len(allowedClients))
		for _, k := range allowedClients {
			sh.allowedClients[k] = struct{}{}
		}
	}
	return sh, nil
}

// SkipJunkFrames читает и отбрасывает junkCount мусорных фреймов из потока данных.
// Вызывать до ProcessClientHello если клиент отправил junk train.
func SkipJunkFrames(buf []byte, maxCount int) ([]byte, error) {
	for i := 0; i < maxCount; i++ {
		if len(buf) < 4 {
			break
		}
		frameLen := int(binary.BigEndian.Uint32(buf[:4]))
		if frameLen > 1024 || len(buf) < 4+frameLen {
			break
		}
		buf = buf[4+frameLen:]
	}
	return buf, nil
}

// ProcessClientHello обрабатывает гибридный ClientHello (X25519 + ML-KEM-768).
func (s *ServerHandshake) ProcessClientHello(data []byte) ([]byte, *StreamFramer, error) {
	if len(data) < 1 {
		return nil, nil, errors.New("client hello too short")
	}
	offset := 0

	// Pre-padding
	prePadLen := int(data[offset])
	offset++
	if len(data) < offset+prePadLen+KeySize+MLKEM768EncapsulationKeySize+32+2 {
		return nil, nil, errors.New("client hello truncated at pre-pad")
	}
	offset += prePadLen

	var clientEphPub [KeySize]byte
	copy(clientEphPub[:], data[offset:offset+KeySize])
	offset += KeySize

	clientMLKEMPub := data[offset : offset+MLKEM768EncapsulationKeySize]
	offset += MLKEM768EncapsulationKeySize

	if len(data) < offset+32 {
		return nil, nil, errors.New("client hello truncated at salt")
	}
	salt := make([]byte, 32)
	copy(salt, data[offset:offset+32])
	offset += 32

	if len(data) < offset+2 {
		return nil, nil, errors.New("client hello truncated at enc_len")
	}
	encLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if len(data) < offset+encLen {
		return nil, nil, errors.New("client hello truncated at enc_identity")
	}
	encIdentity := data[offset : offset+encLen]

	// Временный DH для расшифровки identity
	shared, err := DHSafe(s.staticPriv, clientEphPub)
	if err != nil {
		return nil, nil, err
	}
	tmpKeys, err := DeriveKeys(shared, salt, clientEphPub, s.staticPub)
	if err != nil {
		return nil, nil, err
	}
	tmpCipher, err := NewCipher(tmpKeys.ClientKey, tmpKeys.ClientIV)
	if err != nil {
		return nil, nil, err
	}

	identityAAD := make([]byte, 0, KeySize+len(clientMLKEMPub))
	identityAAD = append(identityAAD, clientEphPub[:]...)
	identityAAD = append(identityAAD, clientMLKEMPub...)
	identity, err := tmpCipher.Decrypt(encIdentity, identityAAD)
	if err != nil {
		return nil, nil, fmt.Errorf("identity decrypt failed: %w", err)
	}

	// Проверяем DynamicMagic (constant-time)
	if len(identity) < 16+KeySize+8+32 {
		return nil, nil, errors.New("identity too short")
	}
	if !ConstantTimeEqual(identity[:16], tmpKeys.DynamicMagic[:]) {
		return nil, nil, errors.New("invalid dynamic magic — rejecting connection")
	}

	var clientStaticPub [KeySize]byte
	copy(clientStaticPub[:], identity[16:16+KeySize])
	s.clientStaticPub = clientStaticPub

	ts := int64(binary.BigEndian.Uint64(identity[16+KeySize : 16+KeySize+8]))
	now := time.Now().Unix()
	if abs64(now-ts) > replayWindowSec {
		return nil, nil, fmt.Errorf("replay/clock skew: delta=%ds", abs64(now-ts))
	}

	staticShared, err := DHSafe(s.staticPriv, clientStaticPub)
	if err != nil {
		return nil, nil, err
	}
	proofData := make([]byte, 0, 16+KeySize+len(clientMLKEMPub)+32+8)
	proofData = append(proofData, tmpKeys.DynamicMagic[:]...)
	proofData = append(proofData, clientEphPub[:]...)
	proofData = append(proofData, clientMLKEMPub...)
	proofData = append(proofData, salt...)
	proofData = append(proofData, identity[16+KeySize:16+KeySize+8]...)
	expectedProof := HmacSHA256(staticShared[:], proofData)
	if !ConstantTimeEqual(identity[16+KeySize+8:16+KeySize+8+32], expectedProof) {
		return nil, nil, errors.New("invalid client static proof")
	}

	if s.allowedClients != nil {
		if _, ok := s.allowedClients[clientStaticPub]; !ok {
			return nil, nil, errors.New("client public key not in allowlist")
		}
	}

	// ML-KEM-768 инкапсуляция
	sharedMLKEM, serverMLKEMCiphertext, err := EncapsulateMLKEM(clientMLKEMPub)
	if err != nil {
		return nil, nil, fmt.Errorf("ml-kem encapsulate failed: %w", err)
	}

	// Финальный DH X25519
	sharedFinal, err := DHSafe(s.ephKeypair.Private, clientEphPub)
	if err != nil {
		return nil, nil, err
	}

	// Dual-PRF Combiner: SS_hybrid = HKDF-Extract(salt, SS_X25519 || SS_MLKEM)
	hybridSecret := DeriveHybridSecret(sharedFinal[:], sharedMLKEM, salt)

	s.SessionKeys, err = DeriveKeys(hybridSecret, salt, clientEphPub, s.ephKeypair.Public)
	if err != nil {
		return nil, nil, err
	}

	// ServerHello — используем DynamicMagic из финальных ключей
	srvEnc, err := NewCipher(s.SessionKeys.ServerKey, s.SessionKeys.ServerIV)
	if err != nil {
		return nil, nil, err
	}
	serverProof := serverStaticProof(shared, clientEphPub, salt, s.ephKeypair.Public, s.SessionKeys.SessionID)
	confirmPlain := make([]byte, 0, 16+SessionIDSize+len(serverProof))
	confirmPlain = append(confirmPlain, s.SessionKeys.DynamicMagic[:]...)
	confirmPlain = append(confirmPlain, s.SessionKeys.SessionID[:]...)
	confirmPlain = append(confirmPlain, serverProof...)

	confirmAAD := make([]byte, 0, KeySize+len(serverMLKEMCiphertext))
	confirmAAD = append(confirmAAD, s.ephKeypair.Public[:]...)
	confirmAAD = append(confirmAAD, serverMLKEMCiphertext...)
	encConfirm := srvEnc.Encrypt(confirmPlain, confirmAAD)

	// S2 padding
	s2, err := RandomPadding(s.ObfCfg.S2Min, s.ObfCfg.S2Max)
	if err != nil {
		return nil, nil, err
	}

	// Pre-padding для ServerHello
	prePad, err := prePadding(s.ObfCfg.PrePadMax)
	if err != nil {
		return nil, nil, err
	}

	var hello []byte
	hello = append(hello, byte(len(prePad)))
	hello = append(hello, prePad...)
	hello = append(hello, s.ephKeypair.Public[:]...)
	hello = append(hello, serverMLKEMCiphertext...)
	hello = appendUint16(hello, uint16(len(encConfirm)))
	hello = append(hello, encConfirm...)
	hello = appendUint16(hello, uint16(len(s2)))
	hello = append(hello, s2...)

	cliDec, err := NewCipher(s.SessionKeys.ClientKey, s.SessionKeys.ClientIV)
	if err != nil {
		return nil, nil, err
	}
	srvEnc2, err := NewCipher(s.SessionKeys.ServerKey, s.SessionKeys.ServerIV)
	if err != nil {
		return nil, nil, err
	}
	clientHeaderKey, serverHeaderKey := DeriveTCPHeaderKeys(s.SessionKeys)
	framer := NewProtectedStreamFramer(srvEnc2, cliDec, serverHeaderKey, clientHeaderKey)
	framer.HeaderCfg = s.ObfCfg.Headers
	s.ephKeypair.Zero()
	return hello, framer, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func appendUint16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

func abs64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func prePadding(maxLen int) ([]byte, error) {
	if maxLen <= 0 {
		return nil, nil
	}
	rb, err := RandomBytes(1)
	if err != nil {
		return nil, err
	}
	size := int(rb[0]) % (maxLen + 1)
	if size == 0 {
		return nil, nil
	}
	return RandomBytes(size)
}

func randomRangeInt(min, max int) (int, error) {
	if max <= min {
		return min, nil
	}
	rb, err := RandomBytes(2)
	if err != nil {
		return 0, err
	}
	return min + int(binary.BigEndian.Uint16(rb))%(max-min), nil
}

// serverStaticProof binds the ephemeral session to the server's pinned X25519
// key.  Both peers can derive staticShared from client_ephemeral × server_static,
// while an on-path attacker cannot forge it without the server private key.
func serverStaticProof(staticShared [KeySize]byte, clientEph [KeySize]byte, salt []byte, serverEph [KeySize]byte, sessionID [SessionIDSize]byte) []byte {
	transcript := make([]byte, 0, 32+KeySize+len(salt)+KeySize+SessionIDSize)
	transcript = append(transcript, []byte("obsidian_server_auth_v1")...)
	transcript = append(transcript, clientEph[:]...)
	transcript = append(transcript, salt...)
	transcript = append(transcript, serverEph[:]...)
	transcript = append(transcript, sessionID[:]...)
	return HmacSHA256(staticShared[:], transcript)
}
