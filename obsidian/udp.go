package obsidian

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	mathrand "math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// UDP packet format (with header protection, inspired by QUIC RFC 9001 §5.4):
//
//   [4 bytes: RouteTag]            ← session routing tag for O(1) demuxing
//   [8 bytes: PROTECTED Counter]   ← monotonic counter XOR AES-ECB(headerKey, sample)
//   [N bytes: Ciphertext]          ← ChaCha20-Poly1305(IP packet)
//   [16 bytes: AEAD tag]           ← Poly1305 authentication tag
//
//   Counter protection: mask = AES-ECB(headerKey, ciphertext[0:16])
//   DPI sees fully random bytes — RouteTag is pseudorandom per session/epoch.
//
// Total overhead: 28 bytes per packet (48 bytes with STUN encapsulation).
//
// Masked format (both ends on record-mode REALITY): no STUN header, and the RouteTag is XORed
// with AES(routeMaskKey, sample), derived from a private REALITY credential on production paths.
// The tag used to be the same 4 bytes at a fixed offset in every datagram of a session, an easy
// flow label for a classifier; masked, every byte of every datagram changes. The server still
// finds the session with one AES block and one map lookup.

var routeMaskLabel = []byte("obsidian_udp_route_mask_v1")

// RealityRouteMaskKey derives the server-wide route mask seed from the private REALITY
// credential. A public server key must not let an observer undo every routing tag mask.
func RealityRouteMaskKey(authKey []byte) [KeySize]byte {
	h := sha256.New()
	h.Write([]byte("obsidian_reality_v5_udp_route_key"))
	h.Write(authKey)
	var key [KeySize]byte
	copy(key[:], h.Sum(nil))
	return key
}

// newRouteMask derives the server-wide cipher that hides RouteTags.
func newRouteMask(serverPub [KeySize]byte) cipher.Block {
	h := sha256.New()
	h.Write(routeMaskLabel)
	h.Write(serverPub[:])
	sum := h.Sum(nil)
	b, err := aes.NewCipher(sum[:16])
	if err != nil {
		panic(err) // a 16-byte key cannot fail
	}
	return b
}

// maskRouteTag XORs tag in place with the mask for sample. mask is 16 bytes of scratch.
func maskRouteTag(rm cipher.Block, tag, sample, mask []byte) {
	rm.Encrypt(mask[:16], sample[:16])
	for i := 0; i < UDPTagSize; i++ {
		tag[i] ^= mask[i]
	}
}

const (
	UDPTagSize     = 4
	UDPCounterSize = 8
	UDPHeaderSize  = UDPTagSize + UDPCounterSize // 12
	UDPOverhead    = UDPHeaderSize + TagSize     // 28
	udpBufSize     = 65536 + 128
	udpBatchSize   = 32

	STUNMagicCookie    uint32 = 0x2112a442
	STUNHeaderSize            = 20
	SRTPHeaderSize            = 12
	RTPPayloadTypeOpus        = 111

	replayWindowSize    = 4096
	udpSessionQueueSize = 8192
	numSessionShards    = 32
)

var udpSendBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 2560)
		return &b
	},
}

func getUDPSendBuf(size int) *[]byte {
	p := udpSendBufPool.Get().(*[]byte)
	if cap(*p) >= size {
		*p = (*p)[:size]
		return p
	}
	udpSendBufPool.Put(p)
	b := make([]byte, size)
	return &b
}

func putUDPSendBuf(p *[]byte) {
	if p != nil && cap(*p) >= 2048 && cap(*p) <= 4096 {
		*p = (*p)[:0]
		udpSendBufPool.Put(p)
	}
}

var udpPlainBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 2048)
		return &b
	},
}

func getUDPPlainBuf() *[]byte {
	return udpPlainBufPool.Get().(*[]byte)
}

func putUDPPlainBuf(p *[]byte) {
	if p != nil && cap(*p) >= 2048 {
		udpPlainBufPool.Put(p)
	}
}

var ErrUDPClientAddrUnknown = errors.New("client address not yet known")

// IsSTUNHeader checks if a UDP datagram starts with a standard STUN/WebRTC header (RFC 5389).
func IsSTUNHeader(b []byte) bool {
	if len(b) < STUNHeaderSize {
		return false
	}
	// RFC 5389 §6: The most significant 2 bits of every STUN message MUST be zeroes (0x00..0x3F).
	return (b[0]&0xC0) == 0x00 && binary.BigEndian.Uint32(b[4:8]) == STUNMagicCookie
}

// IsSRTPHeader checks if a UDP datagram starts with an authentic RFC 7983 / RFC 3550 RTP/SRTP header.
func IsSRTPHeader(b []byte) bool {
	if len(b) < SRTPHeaderSize {
		return false
	}
	// V=2 (0x80), Payload Type in dynamic range 96..127 (e.g. 111 for Opus)
	return (b[0] == 0x80 || (b[0]&0xC0) == 0x80) && (b[1]&0x7F) >= 96 && (b[1]&0x7F) <= 127
}

// writeSTUNHeader writes a 20-byte RFC 5389 STUN header into dst[:20].
// It generates a 96-bit (12-byte) Transaction ID using fast lock-free PRNG to eliminate syscall overhead.
// By default, msgType is 0x0001 (Binding Request), or can be specified (e.g. 0x0101 Binding Success Response).
func writeSTUNHeader(dst []byte, msgLen uint16, msgType ...uint16) {
	t := uint16(0x0001) // STUN Binding Request
	if len(msgType) > 0 {
		t = msgType[0]
	}
	binary.BigEndian.PutUint16(dst[0:2], t)
	binary.BigEndian.PutUint16(dst[2:4], msgLen)          // Message Length (RFC 5389: multiple of 4)
	binary.BigEndian.PutUint32(dst[4:8], STUNMagicCookie) // Magic Cookie (0x2112A442)
	// 96-bit Transaction ID (RFC 5389 §6): cryptographically random 96-bit
	binary.BigEndian.PutUint64(dst[8:16], mathrand.Uint64())
	binary.BigEndian.PutUint32(dst[16:20], mathrand.Uint32())
}

// writeSRTPHeader writes a 12-byte RFC 3550 RTP/SRTP header into dst[:12].
func writeSRTPHeader(dst []byte, seq uint16, ts uint32, ssrc uint32) {
	dst[0] = 0x80               // V=2, P=0, X=0, CC=0
	dst[1] = RTPPayloadTypeOpus // M=0, PT=111 (Opus)
	binary.BigEndian.PutUint16(dst[2:4], seq)
	binary.BigEndian.PutUint32(dst[4:8], ts)
	binary.BigEndian.PutUint32(dst[8:12], ssrc)
}

// ── Key derivation ───────────────────────────────────────────────────────────

type UDPKeys struct {
	SendKey    [KeySize]byte
	RecvKey    [KeySize]byte
	HeaderKey  [16]byte // AES-128 for counter protection
	SessionTag [UDPTagSize]byte
}

// DeriveUDPKeys derives ChaCha20 keys + AES counter-protection key for UDP.
func DeriveUDPKeys(sk *SessionKeys, isClient bool) *UDPKeys {
	combined := make([]byte, 64)
	copy(combined[0:32], sk.ClientKey[:])
	copy(combined[32:64], sk.ServerKey[:])

	// 32 + 32 + 16 = 80 bytes from HKDF
	r := hkdf.New(sha256.New, combined, sk.SessionID[:], []byte("obsidian_udp_v2"))

	var clientKey, serverKey [KeySize]byte
	var headerKey [16]byte
	_, _ = io.ReadFull(r, clientKey[:])
	_, _ = io.ReadFull(r, serverKey[:])
	_, _ = io.ReadFull(r, headerKey[:])

	uk := &UDPKeys{HeaderKey: headerKey}
	copy(uk.SessionTag[:], sk.SessionID[:UDPTagSize])

	if isClient {
		uk.SendKey = clientKey
		uk.RecvKey = serverKey
	} else {
		uk.SendKey = serverKey
		uk.RecvKey = clientKey
	}
	return uk
}

func udpNonce(counter uint64) [NonceSize]byte {
	var nonce [NonceSize]byte
	binary.BigEndian.PutUint64(nonce[4:], counter)
	return nonce
}

// protectCounter XORs the 8-byte counter with AES-ECB(headerKey, sample).
// sample must be 16 bytes (first 16 bytes of ciphertext).
func protectCounter(hp cipher.Block, counterBuf, sample []byte) {
	var mask [16]byte
	protectCounterWith(hp, counterBuf, sample, mask[:])
}

// protectCounterWith is protectCounter with caller-owned space for the mask. Arrays handed to
// the cipher interfaces escape to the heap, so the hot paths keep this scratch in memory they
// already own instead of allocating it for every datagram.
func protectCounterWith(hp cipher.Block, counterBuf, sample, mask []byte) {
	hp.Encrypt(mask[:16], sample)
	for i := 0; i < UDPCounterSize; i++ {
		counterBuf[i] ^= mask[i]
	}
}

// udpScratchLen is the scratch one seal or open uses: nonce, counter mask, AAD and counter.
const udpScratchLen = NonceSize + 16 + UDPHeaderSize + UDPCounterSize

// udpScratch splits a udpScratchLen buffer into its parts.
func udpScratch(b []byte) (nonce, mask, aad, ctr []byte) {
	b = b[:udpScratchLen]
	return b[:NonceSize], b[NonceSize : NonceSize+16], b[NonceSize+16 : NonceSize+16+UDPHeaderSize], b[NonceSize+16+UDPHeaderSize:]
}

// putUDPNonce writes the nonce for counter into dst (NonceSize bytes) and returns it.
func putUDPNonce(dst []byte, counter uint64) []byte {
	n := dst[:NonceSize]
	clear(n[:NonceSize-8])
	binary.BigEndian.PutUint64(n[NonceSize-8:], counter)
	return n
}

// ── Sharded Session Table for O(1) UDP Routing ──────────────────────────────

type sessionShard struct {
	mu       sync.RWMutex
	sessions map[[UDPTagSize]byte]*UDPSession
}

type SessionTable struct {
	shards [numSessionShards]sessionShard
}

func newSessionTable() *SessionTable {
	st := &SessionTable{}
	for i := range st.shards {
		st.shards[i].sessions = make(map[[UDPTagSize]byte]*UDPSession)
	}
	return st
}

func (st *SessionTable) shardFor(tag [UDPTagSize]byte) *sessionShard {
	idx := (uint(tag[0]) ^ uint(tag[1])<<2 ^ uint(tag[2])<<4 ^ uint(tag[3])<<6) % numSessionShards
	return &st.shards[idx]
}

func (st *SessionTable) Get(tag [UDPTagSize]byte) *UDPSession {
	shard := st.shardFor(tag)
	shard.mu.RLock()
	s := shard.sessions[tag]
	shard.mu.RUnlock()
	return s
}

func (st *SessionTable) Set(tag [UDPTagSize]byte, s *UDPSession) {
	shard := st.shardFor(tag)
	shard.mu.Lock()
	shard.sessions[tag] = s
	shard.mu.Unlock()
}

func (st *SessionTable) Delete(tag [UDPTagSize]byte) {
	shard := st.shardFor(tag)
	shard.mu.Lock()
	delete(shard.sessions, tag)
	shard.mu.Unlock()
}

// ── Anti-replay window ───────────────────────────────────────────────────────

type replayWindow struct {
	mu     sync.Mutex
	maxSeq uint64
	bitmap [replayWindowSize / 64]uint64
}

func (w *replayWindow) Check(seq uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if seq > w.maxSeq {
		diff := seq - w.maxSeq
		if diff >= replayWindowSize {
			for i := range w.bitmap {
				w.bitmap[i] = 0
			}
		} else {
			for i := w.maxSeq + 1; i <= seq; i++ {
				idx := i % replayWindowSize
				w.bitmap[idx/64] &^= 1 << (idx % 64)
			}
		}
		w.maxSeq = seq
		idx := seq % replayWindowSize
		w.bitmap[idx/64] |= 1 << (idx % 64)
		return true
	}

	if w.maxSeq-seq >= replayWindowSize {
		return false
	}

	idx := seq % replayWindowSize
	bit := uint64(1) << (idx % 64)
	if w.bitmap[idx/64]&bit != 0 {
		return false
	}
	w.bitmap[idx/64] |= bit
	return true
}

// ── UDPChannel (client-side, connected socket) ───────────────────────────────

type UDPChannel struct {
	// TrafficPadding is enabled only after negotiating native REALITY. Set before use.
	TrafficPadding   bool
	conn             *net.UDPConn
	destAddr         atomic.Pointer[net.UDPAddr]
	encAEAD          cipher.AEAD
	decAEAD          cipher.AEAD
	prevDecAEAD      cipher.AEAD
	hp               cipher.Block // AES-128 for counter protection
	prevHp           cipher.Block
	tag              [UDPTagSize]byte
	prevTag          [UDPTagSize]byte
	sendCtr          atomic.Uint64
	replay           replayWindow
	lastAuthRecvNano atomic.Int64
	// emptyRecv counts authenticated empty datagrams: the server's echoes of our probes.
	emptyRecv        atomic.Uint64
	EnableSTUN       bool
	EnableSRTP       bool
	ssrc             uint32
	rtpSeq           atomic.Uint32
	rtpTS            atomic.Uint32
	UseBucketPadding bool
	BucketMTU        int
	MaxTrailer       int
	routeMask        cipher.Block
	recvMask         [16]byte

	sendMu  sync.RWMutex
	recvMu  sync.Mutex
	writeMu sync.Mutex
	sendBuf []byte
	recvBuf []byte
}

// UseMaskedFormat switches the channel to the masked datagram format. Only call it when the
// server is known to accept it, that is when the TCP side runs in REALITY record mode: an
// older server would misread about one session in sixteen as RTP and drop its packets.
// Incoming datagrams in the old format are still accepted.
func (ch *UDPChannel) UseMaskedFormat(serverPub [KeySize]byte) {
	rm := newRouteMask(serverPub)
	ch.sendMu.Lock()
	ch.recvMu.Lock()
	ch.routeMask = rm
	ch.EnableSTUN = false
	ch.recvMu.Unlock()
	ch.sendMu.Unlock()
}

func (ch *UDPChannel) writeProtected(buf []byte, n int) error {
	if target := ch.destAddr.Load(); target != nil {
		_, err := ch.conn.WriteToUDP(buf[:n], target)
		return err
	}
	_, err := ch.conn.Write(buf[:n])
	return err
}

// SwitchDestination updates the active remote destination for cryptographic port hopping.
func (ch *UDPChannel) SwitchDestination(addr *net.UDPAddr) {
	if addr != nil && ch.conn.RemoteAddr() == nil {
		ch.destAddr.Store(addr)
	}
}

// SetRemotePort updates the active destination port while preserving the host IP. A connected
// socket can only talk to the port it was dialed to, so it stays there: use DialHoppingUDP for
// a channel that changes ports.
func (ch *UDPChannel) SetRemotePort(port int) {
	if ch.conn.RemoteAddr() != nil {
		return
	}
	cur := ch.destAddr.Load()
	if cur != nil {
		newAddr := &net.UDPAddr{IP: cur.IP, Port: port, Zone: cur.Zone}
		ch.destAddr.Store(newAddr)
		return
	}
	if rem := ch.conn.RemoteAddr(); rem != nil {
		if udpRem, ok := rem.(*net.UDPAddr); ok {
			newAddr := &net.UDPAddr{IP: udpRem.IP, Port: port, Zone: udpRem.Zone}
			ch.destAddr.Store(newAddr)
		}
	}
}

// RatchetEpoch seamlessly updates encryption and decryption keys for in-tunnel rekeying.
func (ch *UDPChannel) RatchetEpoch(keys *UDPKeys) error {
	enc, err := chacha20poly1305.New(keys.SendKey[:])
	if err != nil {
		return err
	}
	dec, err := chacha20poly1305.New(keys.RecvKey[:])
	if err != nil {
		return err
	}
	hp, err := aes.NewCipher(keys.HeaderKey[:])
	if err != nil {
		return err
	}

	// Send and Recv both read hp and tag, so both locks are held for the whole switch (same order
	// as UseMaskedFormat). Recv never sees a new tag with the old decryption keys.
	ch.sendMu.Lock()
	ch.recvMu.Lock()
	ch.prevDecAEAD, ch.prevHp, ch.prevTag = ch.decAEAD, ch.hp, ch.tag
	ch.encAEAD, ch.decAEAD, ch.hp, ch.tag = enc, dec, hp, keys.SessionTag
	ch.recvMu.Unlock()
	ch.sendMu.Unlock()

	return nil
}

// DropPrevEpoch stops accepting datagrams of the epoch before the last RatchetEpoch.
func (ch *UDPChannel) DropPrevEpoch() {
	ch.recvMu.Lock()
	ch.prevDecAEAD, ch.prevHp, ch.prevTag = nil, nil, [UDPTagSize]byte{}
	ch.recvMu.Unlock()
}

func NewUDPChannel(conn *net.UDPConn, keys *UDPKeys) (*UDPChannel, error) {
	enc, err := chacha20poly1305.New(keys.SendKey[:])
	if err != nil {
		return nil, err
	}
	dec, err := chacha20poly1305.New(keys.RecvKey[:])
	if err != nil {
		return nil, err
	}
	hp, err := aes.NewCipher(keys.HeaderKey[:])
	if err != nil {
		return nil, err
	}
	ch := &UDPChannel{
		conn:             conn,
		encAEAD:          enc,
		decAEAD:          dec,
		hp:               hp,
		tag:              keys.SessionTag,
		EnableSTUN:       true,
		EnableSRTP:       true,
		ssrc:             mathrand.Uint32(),
		UseBucketPadding: false,
		BucketMTU:        1360,
		MaxTrailer:       0,
		sendBuf:          make([]byte, udpBufSize),
		recvBuf:          make([]byte, udpBufSize),
	}
	ch.rtpSeq.Store(uint32(mathrand.Uint32() & 0xFFFF))
	ch.rtpTS.Store(mathrand.Uint32())
	return ch, nil
}

// Send encrypts payload, protects counter, sends as one UDP datagram.
func (ch *UDPChannel) Send(payload []byte) error {
	required := STUNHeaderSize + UDPHeaderSize + len(payload) + TagSize + 192
	pBuf := getUDPSendBuf(required)
	defer putUDPSendBuf(pBuf)
	ch.sendMu.RLock()
	defer ch.sendMu.RUnlock()
	return ch.sendWithBuffer(payload, *pBuf)
}

// SendWithBuffer encrypts and sends payload using caller-owned scratch space.
func (ch *UDPChannel) SendWithBuffer(payload []byte, buf []byte) error {
	required := STUNHeaderSize + UDPHeaderSize + len(payload) + TagSize + 192
	if len(buf) < required {
		return io.ErrShortBuffer
	}
	ch.sendMu.RLock()
	defer ch.sendMu.RUnlock()
	return ch.sendWithBuffer(payload, buf)
}

func (ch *UDPChannel) sendWithBuffer(payload []byte, buf []byte) error {
	ctr := ch.sendCtr.Add(1) - 1

	plainPayload := payload
	var pBufHolder *[]byte
	if ch.TrafficPadding {
		plainPayload, pBufHolder = shapeUDPPayload(payload)
	} else if ch.UseBucketPadding && len(payload) > 0 {
		padLen := CalculateBucketPaddingWithTrailer(2+len(payload), ch.BucketMTU, ch.MaxTrailer)
		totalPlain := 2 + len(payload) + padLen
		pBufHolder = getUDPPlainBuf()
		pBuf := *pBufHolder
		if totalPlain <= cap(pBuf) {
			pBuf = pBuf[:totalPlain]
			binary.BigEndian.PutUint16(pBuf[0:2], uint16(len(payload)))
			copy(pBuf[2:2+len(payload)], payload)
			FastRandomBytes(pBuf[2+len(payload) : totalPlain])
			plainPayload = pBuf
		}
	}
	if pBufHolder != nil {
		defer putUDPPlainBuf(pBufHolder)
	}

	headerOffset := 0
	if ch.EnableSTUN {
		headerOffset = STUNHeaderSize
	}

	// 1. Plaintext header (RouteTag 4B + Counter 8B)
	copy(buf[headerOffset:headerOffset+UDPTagSize], ch.tag[:])
	binary.BigEndian.PutUint64(buf[headerOffset+UDPTagSize:headerOffset+UDPHeaderSize], ctr)

	// 2. Encrypt payload with AAD = plaintext header
	nonce := udpNonce(ctr)
	sealed := ch.encAEAD.Seal(buf[headerOffset+UDPHeaderSize:headerOffset+UDPHeaderSize], nonce[:], plainPayload, buf[headerOffset:headerOffset+UDPHeaderSize])

	// 3. Counter protection: XOR 8-byte counter with AES(first 16 bytes of ciphertext)
	protectCounter(ch.hp, buf[headerOffset+UDPTagSize:headerOffset+UDPHeaderSize], buf[headerOffset+UDPHeaderSize:headerOffset+UDPHeaderSize+16])
	if ch.routeMask != nil {
		var mask [16]byte
		maskRouteTag(ch.routeMask, buf[headerOffset:headerOffset+UDPTagSize], buf[headerOffset+UDPHeaderSize:headerOffset+UDPHeaderSize+16], mask[:])
	}

	if ch.EnableSTUN {
		bodyLen := uint16(UDPHeaderSize + len(sealed))
		writeSTUNHeader(buf[:STUNHeaderSize], bodyLen, 0x0001) // STUN Binding Request
		return ch.writeProtected(buf, STUNHeaderSize+int(bodyLen))
	}

	return ch.writeProtected(buf, UDPHeaderSize+len(sealed))
}

// Recv reads one UDP datagram, removes counter protection, decrypts into dst.
func (ch *UDPChannel) Recv(dst []byte) (int, error) {
	for {
		n, err := ch.conn.Read(ch.recvBuf[:])
		if err != nil {
			return 0, err
		}
		var tag [UDPTagSize]byte
		offset := -1
		ch.recvMu.Lock()
		if ch.routeMask != nil && n >= UDPHeaderSize+TagSize {
			copy(tag[:], ch.recvBuf[:UDPTagSize])
			maskRouteTag(ch.routeMask, tag[:], ch.recvBuf[UDPHeaderSize:UDPHeaderSize+16], ch.recvMask[:])
			if tag == ch.tag || (ch.prevDecAEAD != nil && tag == ch.prevTag) {
				offset = 0
			}
		}
		ch.recvMu.Unlock()
		if offset < 0 {
			offset = 0
			if IsSTUNHeader(ch.recvBuf[:n]) {
				offset = STUNHeaderSize
			} else if IsSRTPHeader(ch.recvBuf[:n]) {
				offset = SRTPHeaderSize
			}
			if n-offset < UDPHeaderSize+TagSize {
				continue
			}
			copy(tag[:], ch.recvBuf[offset:offset+UDPTagSize])
		}

		packetData := ch.recvBuf[offset:n]
		sample := packetData[UDPHeaderSize : UDPHeaderSize+16]

		ch.recvMu.Lock()
		isCurrent := ConstantTimeEqual(tag[:], ch.tag[:])
		isPrev := (!isCurrent && ch.prevDecAEAD != nil && ConstantTimeEqual(tag[:], ch.prevTag[:]))
		dec := ch.decAEAD
		hp := ch.hp
		if isPrev {
			dec = ch.prevDecAEAD
			if ch.prevHp != nil {
				hp = ch.prevHp
			}
		}
		ch.recvMu.Unlock()

		if !isCurrent && !isPrev {
			continue
		}

		// 1. Remove counter protection
		var ctrBuf [UDPCounterSize]byte
		copy(ctrBuf[:], packetData[UDPTagSize:UDPHeaderSize])
		protectCounter(hp, ctrBuf[:], sample)
		ctr := binary.BigEndian.Uint64(ctrBuf[:])

		// 2. Decrypt with AAD = recovered plaintext header (tag || ctr)
		var aad [UDPHeaderSize]byte
		copy(aad[:UDPTagSize], tag[:])
		copy(aad[UDPTagSize:], ctrBuf[:])

		nonce := udpNonce(ctr)
		plain, err := dec.Open(dst[:0], nonce[:], packetData[UDPHeaderSize:], aad[:])
		if err != nil {
			continue
		}
		if !ch.replay.Check(ctr) {
			continue
		}
		ch.lastAuthRecvNano.Store(time.Now().UnixNano())
		if ch.TrafficPadding {
			actual, ok := unshapeUDPPayload(plain)
			if !ok {
				continue
			}
			if len(actual) == 0 {
				ch.emptyRecv.Add(1)
				continue
			}
			copy(dst, actual)
			return len(actual), nil
		}

		// Unframe Bucket Padding length if present
		if ch.UseBucketPadding && len(plain) >= 2 {
			origLen := int(binary.BigEndian.Uint16(plain[:2]))
			if origLen > 0 && origLen <= len(plain)-2 {
				copy(dst, plain[2:2+origLen])
				return origLen, nil
			}
		}

		if len(plain) == 0 {
			ch.emptyRecv.Add(1)
			continue
		}

		return len(plain), nil
	}
}

func (ch *UDPChannel) Close() error {
	return ch.conn.Close()
}

// LastAuthRecvNano returns the arrival time (UnixNano) of the last authenticated datagram,
// including empty keepalive echoes that Recv does not return. 0 if none arrived yet.
func (ch *UDPChannel) LastAuthRecvNano() int64 {
	return ch.lastAuthRecvNano.Load()
}

// EchoCount returns how many authenticated empty datagrams arrived. The server sends one for
// every empty probe it receives, so probes sent against echoes back measure round-trip loss.
func (ch *UDPChannel) EchoCount() uint64 {
	return ch.emptyRecv.Load()
}

// ── UDPMux (server-side, one shared socket, many sessions) ───────────────────

type UDPMux struct {
	conn       *net.UDPConn
	listeners  atomic.Pointer[[]*net.UDPConn]
	listMu     sync.Mutex
	table      *SessionTable
	mruSession atomic.Pointer[UDPSession]
	// routeMask unmasks RouteTags of the masked format; nil until SetRouteMaskKey.
	routeMask cipher.Block
}

// SetRouteMaskKey enables the masked datagram format (see UDPChannel.UseMaskedFormat). Call it
// before Run with RealityRouteMaskKey(authKey), never with a public server key.
func (m *UDPMux) SetRouteMaskKey(serverPub [KeySize]byte) {
	m.routeMask = newRouteMask(serverPub)
}

// findSession resolves a plaintext RouteTag, current or previous epoch.
// It returns the receive keys the tag matched, taken from one snapshot, so a concurrent epoch
// change cannot mix the keys of two epochs for one datagram.
func (m *UDPMux) findSession(tag [UDPTagSize]byte) (*UDPSession, cipher.AEAD, cipher.Block) {
	if mru := m.mruSession.Load(); mru != nil {
		if dec, hp := mru.recv.Load().match(tag); dec != nil {
			return mru, dec, hp
		}
	}
	if sess := m.table.Get(tag); sess != nil {
		if dec, hp := sess.recv.Load().match(tag); dec != nil {
			m.mruSession.Store(sess)
			return sess, dec, hp
		}
	}
	return nil, nil, nil
}

// lookupDatagram finds the session a datagram belongs to, whatever its format, and returns the
// plaintext tag and where the Obsidian header starts. Junk costs at most one AES block and a
// few map lookups, no AEAD work.
func (m *UDPMux) lookupDatagram(pkt, mask []byte) (sess *UDPSession, dec cipher.AEAD, hp cipher.Block, tag [UDPTagSize]byte, offset int) {
	n := len(pkt)
	try := func(off int, masked bool) bool {
		if n-off < UDPHeaderSize+TagSize {
			return false
		}
		copy(tag[:], pkt[off:off+UDPTagSize])
		if masked {
			maskRouteTag(m.routeMask, tag[:], pkt[off+UDPHeaderSize:off+UDPHeaderSize+16], mask)
		}
		sess, dec, hp = m.findSession(tag)
		offset = off
		return sess != nil
	}
	if IsSTUNHeader(pkt) && try(STUNHeaderSize, false) {
		return
	}
	if m.routeMask != nil && try(0, true) {
		return
	}
	if IsSRTPHeader(pkt) && try(SRTPHeaderSize, false) {
		return
	}
	if try(0, false) {
		return
	}
	return nil, nil, nil, tag, 0
}

// udpRecvKeys is the immutable receive state of a server session: the current epoch and, during
// a rekey, the previous one. It is swapped whole, so the lock-free lookup never sees half of it.
type udpRecvKeys struct {
	tag, prevTag [UDPTagSize]byte
	dec, prevDec cipher.AEAD
	hp, prevHp   cipher.Block
}

func (k *udpRecvKeys) match(tag [UDPTagSize]byte) (cipher.AEAD, cipher.Block) {
	if k.tag == tag {
		return k.dec, k.hp
	}
	if k.prevDec != nil && k.prevTag == tag {
		return k.prevDec, k.prevHp
	}
	return nil, nil
}

type UDPSession struct {
	TrafficPadding bool
	mux            *UDPMux
	// Send side, guarded by sendMu. It moves to a new epoch later than the receive side (see
	// AcceptEpoch and CommitSendEpoch).
	encAEAD   cipher.AEAD
	sendHp    cipher.Block
	sendTag   [UDPTagSize]byte
	recv      atomic.Pointer[udpRecvKeys]
	epochMu   sync.Mutex // serializes epoch changes and the table entries they own
	maskRoute bool

	clientAddr       atomic.Pointer[net.UDPAddr]
	activeConn       atomic.Pointer[net.UDPConn]
	sendCtr          atomic.Uint64
	replay           replayWindow
	EnableSTUN       bool
	EnableSRTP       bool
	ssrc             uint32
	rtpSeq           atomic.Uint32
	rtpTS            atomic.Uint32
	UseBucketPadding bool
	BucketMTU        int
	MaxTrailer       int

	sendMu  sync.RWMutex
	recvMu  sync.Mutex
	batchMu sync.Mutex
	// sendBuf is SendBatch's scratch space, guarded by batchMu.
	sendBuf   []byte
	dataIn    chan []byte
	done      chan struct{}
	closeOnce sync.Once
}

func NewUDPMux(conn *net.UDPConn) *UDPMux {
	m := &UDPMux{
		conn:  conn,
		table: newSessionTable(),
	}
	initListeners := []*net.UDPConn{conn}
	m.listeners.Store(&initListeners)
	return m
}

// AddListener registers an additional UDP listening socket (e.g. from PortPool)
// to multiplex across multiple ports simultaneously.
func (m *UDPMux) AddListener(conn *net.UDPConn) {
	if conn == nil {
		return
	}
	m.listMu.Lock()
	defer m.listMu.Unlock()
	old := m.listeners.Load()
	updated := make([]*net.UDPConn, len(*old)+1)
	copy(updated, *old)
	updated[len(*old)] = conn
	m.listeners.Store(&updated)
}

// UDPSessionOptions are applied before publishing the session to the receiving
// mux. A first uplink must not race with setup of its negotiated wire format.
type UDPSessionOptions struct {
	Masked, TrafficPadding, UseBucketPadding bool
	BucketMTU, MaxTrailer                    int
}

func (m *UDPMux) RegisterSession(keys *UDPKeys, options ...UDPSessionOptions) (*UDPSession, error) {
	enc, err := chacha20poly1305.New(keys.SendKey[:])
	if err != nil {
		return nil, err
	}
	dec, err := chacha20poly1305.New(keys.RecvKey[:])
	if err != nil {
		return nil, err
	}
	hp, err := aes.NewCipher(keys.HeaderKey[:])
	if err != nil {
		return nil, err
	}

	s := &UDPSession{
		mux:              m,
		encAEAD:          enc,
		sendHp:           hp,
		sendTag:          keys.SessionTag,
		EnableSTUN:       true,
		EnableSRTP:       true,
		ssrc:             mathrand.Uint32(),
		UseBucketPadding: false,
		BucketMTU:        1360,
		MaxTrailer:       0,
		sendBuf:          make([]byte, udpBufSize),
		dataIn:           make(chan []byte, udpSessionQueueSize),
		done:             make(chan struct{}),
	}
	s.recv.Store(&udpRecvKeys{tag: keys.SessionTag, dec: dec, hp: hp})
	s.rtpSeq.Store(uint32(mathrand.Uint32() & 0xFFFF))
	s.rtpTS.Store(mathrand.Uint32())
	s.activeConn.Store(m.conn)
	if len(options) > 0 {
		o := options[0]
		s.TrafficPadding = o.TrafficPadding
		s.UseBucketPadding = o.UseBucketPadding
		if o.BucketMTU > 0 {
			s.BucketMTU = o.BucketMTU
		}
		s.MaxTrailer = o.MaxTrailer
		if o.Masked {
			if m.routeMask == nil {
				return nil, errors.New("masked UDP requires a route mask key")
			}
			s.maskRoute, s.EnableSTUN = true, false
		}
	}

	m.table.Set(keys.SessionTag, s)
	m.mruSession.Store(s)
	return s, nil
}

// UseMaskedFormat makes the session send the masked datagram format. Only call it for a client
// that is known to accept it (REALITY record mode). It reports false when the mux has no
// route mask key, and the session keeps the old format.
func (s *UDPSession) UseMaskedFormat() bool {
	if s.mux.routeMask == nil {
		return false
	}
	s.sendMu.Lock()
	s.EnableSTUN = false
	s.maskRoute = true
	s.sendMu.Unlock()
	return true
}

func (m *UDPMux) UnregisterSession(tag [UDPTagSize]byte) {
	m.table.Delete(tag)
	if mru := m.mruSession.Load(); mru != nil {
		if rk := mru.recv.Load(); rk.tag == tag || rk.prevTag == tag {
			m.mruSession.Store(nil)
		}
	}
}

// unregisterOwn removes tag from the table only while it still points at s.
func (m *UDPMux) unregisterOwn(tag [UDPTagSize]byte, s *UDPSession) {
	if tag == ([UDPTagSize]byte{}) {
		return
	}
	if m.table.Get(tag) == s {
		m.table.Delete(tag)
	}
}

// AcceptEpoch starts accepting datagrams of a new epoch while still accepting the current one,
// which becomes the previous epoch. Sending is unchanged until CommitSendEpoch, so a client that
// has not switched yet keeps getting datagrams it can open. An older previous epoch is dropped.
func (s *UDPSession) AcceptEpoch(keys *UDPKeys) error {
	dec, err := chacha20poly1305.New(keys.RecvKey[:])
	if err != nil {
		return err
	}
	hp, err := aes.NewCipher(keys.HeaderKey[:])
	if err != nil {
		return err
	}
	s.epochMu.Lock()
	defer s.epochMu.Unlock()
	cur := s.recv.Load()
	if cur.prevDec != nil && cur.prevTag != cur.tag {
		s.mux.unregisterOwn(cur.prevTag, s)
	}
	s.recv.Store(&udpRecvKeys{
		tag: keys.SessionTag, dec: dec, hp: hp,
		prevTag: cur.tag, prevDec: cur.dec, prevHp: cur.hp,
	})
	s.mux.table.Set(keys.SessionTag, s)
	return nil
}

// CommitSendEpoch makes the session send with the new epoch's keys and tag.
func (s *UDPSession) CommitSendEpoch(keys *UDPKeys) error {
	enc, err := chacha20poly1305.New(keys.SendKey[:])
	if err != nil {
		return err
	}
	hp, err := aes.NewCipher(keys.HeaderKey[:])
	if err != nil {
		return err
	}
	s.sendMu.Lock()
	s.encAEAD, s.sendHp, s.sendTag = enc, hp, keys.SessionTag
	s.sendMu.Unlock()
	return nil
}

// DropPrevEpoch stops accepting the previous epoch once datagrams in flight have arrived, so
// keys from before a rekey cannot be used to inject datagrams later.
func (s *UDPSession) DropPrevEpoch() {
	s.epochMu.Lock()
	defer s.epochMu.Unlock()
	cur := s.recv.Load()
	if cur.prevDec == nil {
		return
	}
	if cur.prevTag != cur.tag {
		s.mux.unregisterOwn(cur.prevTag, s)
	}
	s.recv.Store(&udpRecvKeys{tag: cur.tag, dec: cur.dec, hp: cur.hp})
}

// RatchetEpoch switches receiving and sending to new keys at once, keeping the previous epoch
// acceptable until DropPrevEpoch.
func (s *UDPSession) RatchetEpoch(keys *UDPKeys) error {
	if err := s.AcceptEpoch(keys); err != nil {
		return err
	}
	return s.CommitSendEpoch(keys)
}

// pktPool reduces GC pressure — each decrypted packet is pooled.
var pktPool = sync.Pool{
	New: func() any {
		b := make([]byte, 2048)
		return &b
	},
}

func getPkt(size int) []byte {
	p := pktPool.Get().(*[]byte)
	if cap(*p) >= size {
		return (*p)[:size]
	}
	pktPool.Put(p)
	return make([]byte, size)
}

// PutPacket returns a packet buffer to the pool. Call after writing to TUN.
func PutPacket(b []byte) {
	if cap(b) >= 1500 && cap(b) <= 4096 {
		b = b[:0]
		pktPool.Put(&b)
	}
}

// Run reads all incoming UDP packets across all registered listeners and dispatches to sessions.
// O(1) SessionTable routing provides instant session resolution with zero allocations.
func (m *UDPMux) Run() {
	listeners := *m.listeners.Load()
	if len(listeners) == 1 {
		m.runOnConn(listeners[0])
		return
	}
	var wg sync.WaitGroup
	for _, conn := range listeners {
		wg.Add(1)
		go func(c *net.UDPConn) {
			defer wg.Done()
			m.runOnConn(c)
		}(conn)
	}
	wg.Wait()
}

func (m *UDPMux) runOnConn(conn *net.UDPConn) {
	buf := make([]byte, udpBufSize)
	nonceBuf, mask, aad, ctrBuf := udpScratch(make([]byte, udpScratchLen))

	for {
		n, addr, err := conn.ReadFromUDPAddrPort(buf[:])
		if err != nil {
			return
		}
		// O(1) session lookup; unknown datagrams are dropped without any AEAD work.
		foundSess, dec, hp, tag, offset := m.lookupDatagram(buf[:n], mask)
		if foundSess == nil || dec == nil || hp == nil {
			continue
		}
		packetData := buf[offset:n]
		sample := packetData[UDPHeaderSize : UDPHeaderSize+16]

		// 3. Unmask counter: XOR 8-byte counter with AES(ciphertext sample)
		copy(ctrBuf, packetData[UDPTagSize:UDPHeaderSize])
		protectCounterWith(hp, ctrBuf, sample, mask)
		ctr := binary.BigEndian.Uint64(ctrBuf)

		// 4. Decrypt with AAD = plaintext header (tag || ctrBuf)
		copy(aad[:UDPTagSize], tag[:])
		copy(aad[UDPTagSize:], ctrBuf)

		nonce := putUDPNonce(nonceBuf, ctr)
		pkt := getPkt(len(packetData) - UDPHeaderSize)
		plain, err := dec.Open(pkt[:0], nonce, packetData[UDPHeaderSize:], aad)
		if err != nil {
			PutPacket(pkt)
			continue
		}

		// 5. Anti-Replay Check
		if !foundSess.replay.Check(ctr) {
			PutPacket(plain)
			continue
		}

		// 6. Seamless NAT Rebinding / Roaming update
		foundSess.noteClientAddr(addr, conn)

		// 7. Unframe Bucket Padding length if enabled
		actual := plain
		if foundSess.TrafficPadding {
			var ok bool
			actual, ok = unshapeUDPPayload(plain)
			if !ok {
				PutPacket(plain)
				continue
			}
		} else if foundSess.UseBucketPadding && len(plain) >= 2 {
			origLen := int(binary.BigEndian.Uint16(plain[:2]))
			if origLen > 0 && origLen <= len(plain)-2 {
				actual = plain[2 : 2+origLen]
			}
		}

		if len(actual) == 0 {
			// Echo keepalive probe back to client
			_ = foundSess.Send(nil)
			PutPacket(plain)
			continue
		}

		select {
		case foundSess.dataIn <- actual:
		default:
			PutPacket(plain)
		}
	}
}

// noteClientAddr records where the last authenticated datagram came from. The address only
// changes on NAT rebinding or roaming, so it is stored (and allocated) only then.
func (s *UDPSession) noteClientAddr(ap netip.AddrPort, conn *net.UDPConn) {
	ap = unmapAddrPort(ap)
	if cur := s.clientAddr.Load(); cur == nil || unmapAddrPort(cur.AddrPort()) != ap {
		s.clientAddr.Store(net.UDPAddrFromAddrPort(ap))
	}
	if s.activeConn.Load() != conn {
		s.activeConn.Store(conn)
	}
}

func unmapAddrPort(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// Send encrypts payload, protects counter, sends to client via active socket.
func (s *UDPSession) Send(payload []byte) error {
	select {
	case <-s.done:
		return io.ErrClosedPipe
	default:
	}

	addr := s.clientAddr.Load()
	if addr == nil {
		return ErrUDPClientAddrUnknown
	}

	pBuf := getUDPSendBuf(maxSessionDatagram(len(payload)))
	defer putUDPSendBuf(pBuf)
	s.sendMu.RLock()
	n := s.sealDatagram(*pBuf, payload)
	s.sendMu.RUnlock()
	_, err := s.outConn().WriteToUDP((*pBuf)[:n], addr)
	return err
}

// maxSessionDatagram is the buffer sealDatagram needs for a payload: the largest datagram
// (bucket padding only applies while the padded plaintext fits a 2048-byte buffer) plus the
// crypto scratch it keeps at the end of the buffer.
func maxSessionDatagram(payloadLen int) int {
	return STUNHeaderSize + UDPHeaderSize + max(payloadLen, 2048) + TagSize + udpScratchLen
}

func (s *UDPSession) outConn() *net.UDPConn {
	if c := s.activeConn.Load(); c != nil {
		return c
	}
	return s.mux.conn
}

// sealDatagram writes the complete datagram for payload into buf, exactly as it goes on the
// wire, and returns its length. The caller holds s.sendMu for reading and sizes buf with
// maxSessionDatagram.
func (s *UDPSession) sealDatagram(buf, payload []byte) int {
	ctr := s.sendCtr.Add(1) - 1

	plainPayload := payload
	var padBufHolder *[]byte
	if s.TrafficPadding {
		plainPayload, padBufHolder = shapeUDPPayload(payload)
	} else if s.UseBucketPadding && len(payload) > 0 {
		padLen := CalculateBucketPaddingWithTrailer(2+len(payload), s.BucketMTU, s.MaxTrailer)
		totalPlain := 2 + len(payload) + padLen
		padBufHolder = getUDPPlainBuf()
		padBuf := *padBufHolder
		if totalPlain <= cap(padBuf) {
			padBuf = padBuf[:totalPlain]
			binary.BigEndian.PutUint16(padBuf[0:2], uint16(len(payload)))
			copy(padBuf[2:2+len(payload)], payload)
			FastRandomBytes(padBuf[2+len(payload) : totalPlain])
			plainPayload = padBuf
		}
	}
	if padBufHolder != nil {
		defer putUDPPlainBuf(padBufHolder)
	}

	headerOffset := 0
	if s.EnableSTUN {
		headerOffset = STUNHeaderSize
	}

	// 1. Plaintext header (RouteTag 4B + Counter 8B)
	copy(buf[headerOffset:headerOffset+UDPTagSize], s.sendTag[:])
	binary.BigEndian.PutUint64(buf[headerOffset+UDPTagSize:headerOffset+UDPHeaderSize], ctr)

	// The datagram never reaches the last udpScratchLen bytes of buf (see maxSessionDatagram).
	nonceBuf, mask, _, _ := udpScratch(buf[len(buf)-udpScratchLen:])

	// 2. Encrypt with AAD = plaintext header
	nonce := putUDPNonce(nonceBuf, ctr)
	sealed := s.encAEAD.Seal(buf[headerOffset+UDPHeaderSize:headerOffset+UDPHeaderSize], nonce, plainPayload, buf[headerOffset:headerOffset+UDPHeaderSize])

	// 3. Counter protection: XOR counter with AES(ciphertext sample)
	protectCounterWith(s.sendHp, buf[headerOffset+UDPTagSize:headerOffset+UDPHeaderSize], buf[headerOffset+UDPHeaderSize:headerOffset+UDPHeaderSize+16], mask)
	if s.maskRoute {
		maskRouteTag(s.mux.routeMask, buf[headerOffset:headerOffset+UDPTagSize], buf[headerOffset+UDPHeaderSize:headerOffset+UDPHeaderSize+16], mask)
	}

	if s.EnableSTUN {
		bodyLen := uint16(UDPHeaderSize + len(sealed))
		writeSTUNHeader(buf[:STUNHeaderSize], bodyLen, 0x0101) // STUN Binding Success Response
		return STUNHeaderSize + int(bodyLen)
	}
	return UDPHeaderSize + len(sealed)
}

const (
	// gsoMaxSegments and gsoMaxBytes keep one UDP_SEGMENT send inside the kernel limits
	// (64 segments, 64 KiB of UDP payload) with room to spare.
	gsoMaxSegments = 64
	gsoMaxBytes    = 60000
	udpBatchBufLen = 64 * 1024
)

// SendBatch sends payloads in order as exactly the datagrams Send would produce. Where the
// kernel supports UDP GSO, each run of equal-size datagrams (the last one may be shorter) goes
// down in one sendmsg and the kernel cuts it back into separate datagrams, so the wire and the
// client see no difference. It returns how many payloads were handed to the kernel.
func (s *UDPSession) SendBatch(payloads [][]byte) (int, error) {
	select {
	case <-s.done:
		return 0, io.ErrClosedPipe
	default:
	}
	addr := s.clientAddr.Load()
	if addr == nil {
		return 0, ErrUDPClientAddrUnknown
	}
	conn := s.outConn()
	if len(payloads) < 2 || !gsoAvailable(conn) {
		for i, p := range payloads {
			if err := s.Send(p); err != nil {
				return i, err
			}
		}
		return len(payloads), nil
	}

	s.batchMu.Lock()
	defer s.batchMu.Unlock()
	if len(s.sendBuf) < udpBatchBufLen {
		s.sendBuf = make([]byte, udpBatchBufLen)
	}
	buf := s.sendBuf

	var off, groupStart, segSize, segs, sent int
	short := false
	flush := func() error {
		if segs == 0 {
			return nil
		}
		if err := writeSegments(conn, buf[groupStart:off], segSize, addr); err != nil {
			return err
		}
		sent += segs
		groupStart, segs = off, 0
		return nil
	}

	s.sendMu.RLock()
	defer s.sendMu.RUnlock()
	for _, p := range payloads {
		need := maxSessionDatagram(len(p))
		if need > len(buf) {
			// Larger than any tunnel MTU; send it on its own rather than grow the buffer.
			if err := flush(); err != nil {
				return sent, err
			}
			off, groupStart = 0, 0
			one := make([]byte, need)
			n := s.sealDatagram(one, p)
			if _, err := conn.WriteToUDP(one[:n], addr); err != nil {
				return sent, err
			}
			sent++
			continue
		}
		if len(buf)-off < need {
			if err := flush(); err != nil {
				return sent, err
			}
			off, groupStart = 0, 0
		}
		n := s.sealDatagram(buf[off:], p)
		if segs > 0 && (n > segSize || short || segs >= gsoMaxSegments || off+n-groupStart > gsoMaxBytes) {
			if err := flush(); err != nil {
				return sent, err
			}
		}
		if segs == 0 {
			segSize, short = n, false
		} else if n < segSize {
			short = true
		}
		off += n
		segs++
	}
	if err := flush(); err != nil {
		return sent, err
	}
	return sent, nil
}

// writeEach sends b as consecutive datagrams of segSize bytes (the last may be shorter).
func writeEach(conn *net.UDPConn, b []byte, segSize int, addr *net.UDPAddr) error {
	for len(b) > 0 {
		n := min(segSize, len(b))
		if _, err := conn.WriteToUDP(b[:n], addr); err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

// Recv blocks until a decrypted data packet is available.
func (s *UDPSession) Recv() ([]byte, error) {
	select {
	case data, ok := <-s.dataIn:
		if !ok {
			return nil, io.EOF
		}
		return data, nil
	case <-s.done:
		return nil, io.EOF
	}
}

type UDPPacket struct {
	Payload []byte
}

// Release returns the packet buffer to the internal pool. Call after processing.
func (p UDPPacket) Release() {
	if p.Payload != nil {
		PutPacket(p.Payload)
	}
}

// RecvBatch receives up to len(dst) decrypted packets. It blocks until at least
// one packet is available, then drains any immediately queued packets without
// waiting. This amortizes scheduler/channel overhead under load without changing
// the encrypted UDP wire format.
func (s *UDPSession) RecvBatch(dst []UDPPacket) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	data, err := s.Recv()
	if err != nil {
		return 0, err
	}
	dst[0] = UDPPacket{Payload: data}
	n := 1
	for n < len(dst) {
		select {
		case data, ok := <-s.dataIn:
			if !ok {
				return n, nil
			}
			dst[n] = UDPPacket{Payload: data}
			n++
		case <-s.done:
			return n, nil
		default:
			return n, nil
		}
	}
	return n, nil
}

func (s *UDPSession) Close() {
	s.closeOnce.Do(func() {
		s.epochMu.Lock()
		rk := s.recv.Load()
		s.mux.UnregisterSession(rk.tag)
		if rk.prevDec != nil {
			s.mux.UnregisterSession(rk.prevTag)
		}
		s.epochMu.Unlock()
		select {
		case <-s.done:
		default:
			close(s.done)
		}
	})
}

// DialHoppingUDP creates an unconnected *net.UDPConn for port hopping and resolves its first
// destination, which the caller passes to SwitchDestination. Replies come back from whichever
// port the client last used, so the socket cannot be connected to a single one.
func DialHoppingUDP(network, remoteAddr string, protector SocketProtector) (*net.UDPConn, *net.UDPAddr, error) {
	raddr, err := net.ResolveUDPAddr(network, remoteAddr)
	if err != nil {
		return nil, nil, err
	}
	var lc net.ListenConfig
	if protector != nil {
		lc.Control = func(_, _ string, c syscall.RawConn) error {
			var protectErr error
			if err := c.Control(func(fd uintptr) { protectErr = protector(int(fd)) }); err != nil {
				return err
			}
			return protectErr
		}
	}
	pc, err := lc.ListenPacket(context.Background(), network, ":0")
	if err != nil {
		return nil, nil, err
	}
	conn, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		return nil, nil, errors.New("expected *net.UDPConn from listen")
	}
	return conn, raddr, nil
}

// DialProtectedUDP creates a connected *net.UDPConn to the specified address.
// If protector is non-nil, it is called on the underlying socket descriptor
// before connection is finalized (essential for mobile/Android VpnService.protect).
func DialProtectedUDP(network, remoteAddr string, protector SocketProtector) (*net.UDPConn, error) {
	if protector == nil {
		rAddr, err := net.ResolveUDPAddr(network, remoteAddr)
		if err != nil {
			return nil, err
		}
		return net.DialUDP(network, nil, rAddr)
	}

	dialer := &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			var protectErr error
			err := c.Control(func(fd uintptr) {
				protectErr = protector(int(fd))
			})
			if err != nil {
				return err
			}
			return protectErr
		},
	}

	conn, err := dialer.Dial(network, remoteAddr)
	if err != nil {
		return nil, err
	}
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		conn.Close()
		return nil, errors.New("expected *net.UDPConn from dial")
	}
	return udpConn, nil
}
