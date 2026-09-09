package obsidian

// ── Wire protocol v2 ──────────────────────────────────────────────────────────
//
// Range-based заголовки (идея из AmneziaWG 2.0):
//   Вместо фиксированного 1-байтового VER+TYPE используем 4-байтовый type-id
//   выбираемый случайно из настроенного диапазона [Min, Max].
//   Каждый тип пакета имеет свой диапазон — они не пересекаются.
//   DPI не может написать сигнатуру: у каждого пакета уникальный заголовок.
//
// Wire format пакета:
//   [TYPE_ID: 4 bytes big-endian]  ← случайное число из диапазона типа
//   [PAY_LEN: 2 bytes big-endian]
//   [PAD_LEN: 1 byte]
//   [VERSION: 1 byte]              ← всегда 0x02, внутри зашифровано
//   ChaCha20-Poly1305(payload || padding, aad=TYPE_ID||PAY_LEN||PAD_LEN||VERSION)
//
// TCP framing:
//   [FRAME_LEN: 4 big-endian][ENCRYPTED_PACKET: FRAME_LEN bytes]

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20"
)

type PacketType uint8

const (
	PacketData      PacketType = 0x01
	PacketKeepalive PacketType = 0x02
	PacketNoise     PacketType = 0x03
	PacketHandshake PacketType = 0x04
	PacketClose     PacketType = 0x05
)

const obsidianVersion = 0x02
const ProtocolVersion = obsidianVersion

const maxPayload = 65535
const maxFrameSize = maxPayload + 512
const packetHeaderSize = 8

// ── HeaderRange ───────────────────────────────────────────────────────────────

// HeaderRange — диапазон [Min, Max] для случайного type-id заголовка.
// Аналог H1–H4 в AmneziaWG 2.0.
type HeaderRange struct {
	Min uint32
	Max uint32
}

// Pick возвращает случайное значение из диапазона.
func (h HeaderRange) Pick() uint32 {
	if h.Max <= h.Min {
		return h.Min
	}
	return h.Min + rand.Uint32N(h.Max-h.Min+1)
}

// Contains проверяет попадание значения в диапазон.
func (h HeaderRange) Contains(v uint32) bool {
	return v >= h.Min && v <= h.Max
}

// HeaderConfig — набор диапазонов для всех типов пакетов.
// Диапазоны НЕ должны пересекаться — иначе тип пакета нельзя определить при получении.
type HeaderConfig struct {
	Data      HeaderRange // H4 аналог
	Keepalive HeaderRange // вспомогательный
	Noise     HeaderRange // вспомогательный
	Handshake HeaderRange // H1/H2 аналог (используется в handshake пакетах)
	Close     HeaderRange
}

// DefaultHeaderConfig — диапазоны по умолчанию (не пересекаются, широкие).
func DefaultHeaderConfig() HeaderConfig {
	return HeaderConfig{
		Data:      HeaderRange{0x10000000, 0x1FFFFFFF}, // 268M вариантов
		Keepalive: HeaderRange{0x20000000, 0x2FFFFFFF},
		Noise:     HeaderRange{0x30000000, 0x3FFFFFFF},
		Handshake: HeaderRange{0x40000000, 0x4FFFFFFF},
		Close:     HeaderRange{0x50000000, 0x5FFFFFFF},
	}
}

// Validate проверяет что диапазоны не пересекаются.
func (hc *HeaderConfig) Validate() error {
	ranges := []HeaderRange{hc.Data, hc.Keepalive, hc.Noise, hc.Handshake, hc.Close}
	names := []string{"Data", "Keepalive", "Noise", "Handshake", "Close"}
	for i := 0; i < len(ranges); i++ {
		for j := i + 1; j < len(ranges); j++ {
			a, b := ranges[i], ranges[j]
			if a.Min <= b.Max && b.Min <= a.Max {
				return fmt.Errorf("header ranges %s [%d,%d] and %s [%d,%d] overlap",
					names[i], a.Min, a.Max, names[j], b.Min, b.Max)
			}
		}
	}
	return nil
}

// typeIDToPacketType определяет тип пакета по type-id используя HeaderConfig.
func (hc *HeaderConfig) typeIDToPacketType(id uint32) (PacketType, error) {
	switch {
	case hc.Data.Contains(id):
		return PacketData, nil
	case hc.Keepalive.Contains(id):
		return PacketKeepalive, nil
	case hc.Noise.Contains(id):
		return PacketNoise, nil
	case hc.Handshake.Contains(id):
		return PacketHandshake, nil
	case hc.Close.Contains(id):
		return PacketClose, nil
	default:
		return 0, fmt.Errorf("unknown type-id: 0x%08x", id)
	}
}

func (hc *HeaderConfig) rangeFor(pt PacketType) HeaderRange {
	switch pt {
	case PacketData:
		return hc.Data
	case PacketKeepalive:
		return hc.Keepalive
	case PacketNoise:
		return hc.Noise
	case PacketHandshake:
		return hc.Handshake
	case PacketClose:
		return hc.Close
	default:
		return hc.Data
	}
}

// ── PaddingConfig ─────────────────────────────────────────────────────────────

type PaddingConfig struct {
	DataMin, DataMax           int
	NoiseMin, NoiseMax         int
	KeepaliveMin, KeepaliveMax int
	UseBucketPadding           bool
	BucketMTU                  int
	MaxTrailer                 int
}

func DefaultPaddingConfig() PaddingConfig {
	return PaddingConfig{
		DataMin:          0,
		DataMax:          32,
		NoiseMin:         16,
		NoiseMax:         128,
		KeepaliveMin:     8,
		KeepaliveMax:     64,
		UseBucketPadding: true,
		BucketMTU:        1360,
		MaxTrailer:       32,
	}
}

// ── Packet ────────────────────────────────────────────────────────────────────

type Packet struct {
	Type    PacketType
	Payload []byte
}

// ── Encode / Decode ───────────────────────────────────────────────────────────

func xorPacketHeader(header []byte, key *[KeySize]byte, sample []byte) error {
	if key == nil {
		return nil
	}
	if len(header) != packetHeaderSize {
		return fmt.Errorf("invalid packet header size: %d", len(header))
	}
	if len(sample) < 16 {
		return errors.New("packet header protection sample too short")
	}
	var nonce [chacha20.NonceSize]byte
	copy(nonce[:], sample[:chacha20.NonceSize])
	stream, err := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
	if err != nil {
		return err
	}
	var mask [packetHeaderSize]byte
	stream.XORKeyStream(mask[:], mask[:])
	for i := 0; i < packetHeaderSize; i++ {
		header[i] ^= mask[i]
	}
	return nil
}

// encodePacket кодирует пакет с range-based type-id и padding.
func encodePacket(c *Cipher, hc *HeaderConfig, ptype PacketType, payload []byte, padMin, padMax int) ([]byte, error) {
	return encodePacketWithHeaderProtection(c, nil, hc, ptype, payload, padMin, padMax)
}

func encodePacketWithHeaderProtection(c *Cipher, headerKey *[KeySize]byte, hc *HeaderConfig, ptype PacketType, payload []byte, padMin, padMax int) ([]byte, error) {
	if len(payload) > maxPayload {
		return nil, fmt.Errorf("payload too large: %d", len(payload))
	}
	maxPad := padMax
	if maxPad < padMin {
		maxPad = padMin
	}
	if maxPad > 255 {
		maxPad = 255
	}
	out := make([]byte, packetHeaderSize+len(payload)+maxPad+TagSize)
	n, err := encodePacketWithHeaderProtectionBuffer(out, c, headerKey, hc, ptype, payload, padMin, padMax)
	if err != nil {
		return nil, err
	}
	return out[:n], nil
}

// decodePacket декодирует пакет используя HeaderConfig для определения типа.
func decodePacket(c *Cipher, hc *HeaderConfig, data []byte) (*Packet, error) {
	return decodePacketWithHeaderProtection(c, nil, hc, data)
}

func decodePacketWithHeaderProtection(c *Cipher, headerKey *[KeySize]byte, hc *HeaderConfig, data []byte) (*Packet, error) {
	if len(data) < packetHeaderSize+TagSize {
		return nil, errors.New("packet too short")
	}

	aad := make([]byte, packetHeaderSize)
	copy(aad, data[:packetHeaderSize])
	ct := data[packetHeaderSize:]
	if err := xorPacketHeader(aad, headerKey, ct); err != nil {
		return nil, err
	}
	typeID := binary.BigEndian.Uint32(aad[0:4])
	payLen := int(binary.BigEndian.Uint16(aad[4:6]))
	padLen := int(aad[6])
	version := aad[7]

	if version != obsidianVersion {
		return nil, fmt.Errorf("unknown protocol version: %d", version)
	}

	ptype, err := hc.typeIDToPacketType(typeID)
	if err != nil {
		return nil, err
	}

	if len(ct) != payLen+padLen+TagSize {
		return nil, fmt.Errorf("length mismatch: got %d, want %d", len(ct), payLen+padLen+TagSize)
	}

	plaintext, err := c.Decrypt(ct, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return &Packet{Type: ptype, Payload: plaintext[:payLen]}, nil
}

// Публичные обёртки для тестов
func EncodePacket(c *Cipher, ptype PacketType, payload []byte) ([]byte, error) {
	hc := DefaultHeaderConfig()
	return encodePacket(c, &hc, ptype, payload, 16, 128)
}

func DecodePacket(c *Cipher, data []byte) (*Packet, error) {
	hc := DefaultHeaderConfig()
	return decodePacket(c, &hc, data)
}

// ── Packet constructors ───────────────────────────────────────────────────────

func NewDataPacket(payload []byte) *Packet {
	return &Packet{Type: PacketData, Payload: payload}
}

func NewNoisePacket() (*Packet, error) {
	size := 64 + rand.IntN(448)
	payload := make([]byte, size)
	FastRandomBytes(payload)
	return &Packet{Type: PacketNoise, Payload: payload}, nil
}

func NewKeepalivePacket() (*Packet, error) {
	noiseLen := 8 + rand.IntN(32)
	payload := make([]byte, 8+noiseLen)
	binary.BigEndian.PutUint64(payload[:8], uint64(time.Now().UnixMilli()))
	FastRandomBytes(payload[8:])
	return &Packet{Type: PacketKeepalive, Payload: payload}, nil
}

// ── StreamFramer ──────────────────────────────────────────────────────────────

type StreamFramer struct {
	EncCipher    *Cipher
	DecCipher    *Cipher
	HeaderCfg    HeaderConfig
	PaddingCfg   PaddingConfig
	EncHeaderKey *[KeySize]byte
	DecHeaderKey *[KeySize]byte
	EncFrameKey  *[KeySize]byte
	DecFrameKey  *[KeySize]byte
	encFrameCtr  uint64
	decFrameCtr  uint64
}

func NewStreamFramer(enc, dec *Cipher) *StreamFramer {
	return &StreamFramer{
		EncCipher:  enc,
		DecCipher:  dec,
		HeaderCfg:  DefaultHeaderConfig(),
		PaddingCfg: DefaultPaddingConfig(),
	}
}

func NewProtectedStreamFramer(enc, dec *Cipher, encHeaderKey, decHeaderKey [KeySize]byte) *StreamFramer {
	f := NewStreamFramer(enc, dec)
	f.EncHeaderKey = &encHeaderKey
	f.DecHeaderKey = &decHeaderKey
	f.EncFrameKey = &encHeaderKey
	f.DecFrameKey = &decHeaderKey
	return f
}

func fastHmacSHA256Stack(key, data []byte) [32]byte {
	var k [64]byte
	if len(key) > 64 {
		h := sha256.Sum256(key)
		copy(k[:32], h[:])
	} else {
		copy(k[:len(key)], key)
	}

	var innerBuf [64 + 128]byte
	var innerSlice []byte
	if 64+len(data) <= len(innerBuf) {
		innerSlice = innerBuf[:64+len(data)]
	} else {
		innerSlice = make([]byte, 64+len(data))
	}
	for i := 0; i < 64; i++ {
		innerSlice[i] = k[i] ^ 0x36
	}
	copy(innerSlice[64:], data)
	innerHash := sha256.Sum256(innerSlice)

	var outerBuf [64 + 32]byte
	for i := 0; i < 64; i++ {
		outerBuf[i] = k[i] ^ 0x5c
	}
	copy(outerBuf[64:], innerHash[:])
	return sha256.Sum256(outerBuf[:])
}

func maskFrameLen(key *[KeySize]byte, ctr uint64, n uint32) uint32 {
	if key == nil {
		return n
	}
	var msg [24]byte
	copy(msg[:16], []byte("obsidian_frame_v3"))
	binary.BigEndian.PutUint64(msg[16:24], ctr)
	mac := fastHmacSHA256Stack(key[:], msg[:])
	return n ^ binary.BigEndian.Uint32(mac[:4])
}

func (f *StreamFramer) Frame(ptype PacketType, payload []byte) ([]byte, error) {
	padMin, padMax := f.paddingFor(ptype)
	if ptype == PacketData && f.PaddingCfg.UseBucketPadding {
		padLen := CalculateBucketPaddingWithTrailer(len(payload), f.PaddingCfg.BucketMTU, f.PaddingCfg.MaxTrailer)
		padMin = padLen
		padMax = padLen
	}
	pkt, err := encodePacketWithHeaderProtection(f.EncCipher, f.EncHeaderKey, &f.HeaderCfg, ptype, payload, padMin, padMax)
	if err != nil {
		return nil, err
	}
	frame := make([]byte, 4+len(pkt))
	maskedLen := maskFrameLen(f.EncFrameKey, f.encFrameCtr, uint32(len(pkt)))
	f.encFrameCtr++
	binary.BigEndian.PutUint32(frame[:4], maskedLen)
	copy(frame[4:], pkt)
	return frame, nil
}

func (f *StreamFramer) FrameWithBuffer(dst []byte, ptype PacketType, payload []byte) (int, error) {
	padMin, padMax := f.paddingFor(ptype)
	if ptype == PacketData && f.PaddingCfg.UseBucketPadding {
		padLen := CalculateBucketPaddingWithTrailer(len(payload), f.PaddingCfg.BucketMTU, f.PaddingCfg.MaxTrailer)
		padMin = padLen
		padMax = padLen
	}
	if len(dst) < 4 {
		return 0, io.ErrShortBuffer
	}
	pktLen, err := encodePacketWithHeaderProtectionBuffer(dst[4:], f.EncCipher, f.EncHeaderKey, &f.HeaderCfg, ptype, payload, padMin, padMax)
	if err != nil {
		return 0, err
	}
	maskedLen := maskFrameLen(f.EncFrameKey, f.encFrameCtr, uint32(pktLen))
	f.encFrameCtr++
	binary.BigEndian.PutUint32(dst[:4], maskedLen)
	return 4 + pktLen, nil
}

var plainBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, 4096)
		return &b
	},
}

func getPlainBuf(size int) *[]byte {
	p := plainBufferPool.Get().(*[]byte)
	if cap(*p) >= size {
		*p = (*p)[:size]
		return p
	}
	plainBufferPool.Put(p)
	b := make([]byte, size)
	return &b
}

func putPlainBuf(p *[]byte) {
	if p != nil && cap(*p) >= 4096 && cap(*p) <= 8192 {
		*p = (*p)[:0]
		plainBufferPool.Put(p)
	}
}

func encodePacketWithHeaderProtectionBuffer(dst []byte, c *Cipher, headerKey *[KeySize]byte, hc *HeaderConfig, ptype PacketType, payload []byte, padMin, padMax int) (int, error) {
	if len(payload) > maxPayload {
		return 0, fmt.Errorf("payload too large: %d", len(payload))
	}
	maxPad := padMax
	if maxPad < padMin {
		maxPad = padMin
	}
	if maxPad > 255 {
		maxPad = 255
	}

	needCap := len(payload) + maxPad
	pBuf := getPlainBuf(needCap)
	defer putPlainBuf(pBuf)

	plaintext := *pBuf
	copy(plaintext[:len(payload)], payload)
	padLen := FastRandomPaddingInplace(plaintext[len(payload):needCap], padMin, padMax)
	plaintext = plaintext[:len(payload)+padLen]

	required := packetHeaderSize + len(plaintext) + TagSize
	if len(dst) < required {
		return 0, io.ErrShortBuffer
	}

	typeID := hc.rangeFor(ptype).Pick()

	aad := [8]byte{}
	binary.BigEndian.PutUint32(aad[0:4], typeID)
	binary.BigEndian.PutUint16(aad[4:6], uint16(len(payload)))
	aad[6] = byte(padLen)
	aad[7] = obsidianVersion

	copy(dst[:packetHeaderSize], aad[:])
	c.EncryptWithBuffer(dst[packetHeaderSize:], plaintext, aad[:])

	if err := xorPacketHeader(dst[:packetHeaderSize], headerKey, dst[packetHeaderSize:packetHeaderSize+TagSize]); err != nil {
		return 0, err
	}
	return required, nil
}

func (f *StreamFramer) FramePacket(p *Packet) ([]byte, error) {
	return f.Frame(p.Type, p.Payload)
}

func (f *StreamFramer) DecodeFrameLen(masked uint32) uint32 {
	plain := maskFrameLen(f.DecFrameKey, f.decFrameCtr, masked)
	f.decFrameCtr++
	return plain
}

func (f *StreamFramer) ParseFrame(raw []byte) (*Packet, error) {
	return decodePacketWithHeaderProtection(f.DecCipher, f.DecHeaderKey, &f.HeaderCfg, raw)
}

func (f *StreamFramer) ParseFrameInto(dst []byte, raw []byte) (PacketType, int, error) {
	if len(raw) < packetHeaderSize+TagSize {
		return 0, 0, errors.New("packet too short")
	}

	var aad [packetHeaderSize]byte
	copy(aad[:], raw[:packetHeaderSize])
	ct := raw[packetHeaderSize:]
	if err := xorPacketHeader(aad[:], f.DecHeaderKey, ct); err != nil {
		return 0, 0, err
	}
	typeID := binary.BigEndian.Uint32(aad[0:4])
	payLen := int(binary.BigEndian.Uint16(aad[4:6]))
	padLen := int(aad[6])
	version := aad[7]

	if version != obsidianVersion {
		return 0, 0, fmt.Errorf("unknown protocol version: %d", version)
	}

	ptype, err := f.HeaderCfg.typeIDToPacketType(typeID)
	if err != nil {
		return 0, 0, err
	}

	if len(ct) != payLen+padLen+TagSize {
		return 0, 0, fmt.Errorf("length mismatch: got %d, want %d", len(ct), payLen+padLen+TagSize)
	}

	if len(dst) < payLen+padLen {
		plaintext, err := f.DecCipher.Decrypt(ct, aad[:])
		if err != nil {
			return 0, 0, fmt.Errorf("decrypt: %w", err)
		}
		copy(dst, plaintext[:payLen])
		return ptype, payLen, nil
	}

	_, err = f.DecCipher.DecryptWithBuffer(dst, ct, aad[:])
	if err != nil {
		return 0, 0, fmt.Errorf("decrypt: %w", err)
	}

	return ptype, payLen, nil
}

func (f *StreamFramer) ParseFrameWithBuffer(dst []byte, raw []byte) (*Packet, error) {
	ptype, payLen, err := f.ParseFrameInto(dst, raw)
	if err != nil {
		return nil, err
	}
	return &Packet{Type: ptype, Payload: dst[:payLen]}, nil
}

func (f *StreamFramer) paddingFor(pt PacketType) (int, int) {
	switch pt {
	case PacketData:
		return f.PaddingCfg.DataMin, f.PaddingCfg.DataMax
	case PacketNoise:
		return f.PaddingCfg.NoiseMin, f.PaddingCfg.NoiseMax
	case PacketKeepalive:
		return f.PaddingCfg.KeepaliveMin, f.PaddingCfg.KeepaliveMax
	default:
		return 16, 64
	}
}
