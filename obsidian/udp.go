package obsidian

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	mathrand "math/rand/v2"
	"net"
	"sync"
	"sync/atomic"

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

const (
	UDPTagSize     = 4
	UDPCounterSize = 8
	UDPHeaderSize  = UDPTagSize + UDPCounterSize // 12
	UDPOverhead    = UDPHeaderSize + TagSize     // 28
	udpBufSize     = 65536 + 128
	udpBatchSize   = 32

	STUNMagicCookie uint32 = 0x2112a442
	STUNHeaderSize         = 20
	SRTPHeaderSize         = 12
	RTPPayloadTypeOpus     = 111

	replayWindowSize    = 4096
	udpSessionQueueSize = 8192
	numSessionShards    = 32
)

var udpSendBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 2048)
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
	hp.Encrypt(mask[:], sample)
	for i := 0; i < UDPCounterSize; i++ {
		counterBuf[i] ^= mask[i]
	}
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
	writeMu sync.Mutex
	sendBuf []byte
	recvBuf []byte
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
	if addr != nil {
		ch.destAddr.Store(addr)
	}
}

// SetRemotePort updates the active destination port while preserving the host IP.
func (ch *UDPChannel) SetRemotePort(port int) {
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

	ch.sendMu.Lock()
	ch.encAEAD = enc
	oldHp := ch.hp
	ch.hp = hp
	oldTag := ch.tag
	ch.tag = keys.SessionTag
	ch.sendMu.Unlock()

	ch.recvMu.Lock()
	ch.prevDecAEAD = ch.decAEAD
	ch.decAEAD = dec
	ch.prevHp = oldHp
	ch.prevTag = oldTag
	ch.recvMu.Unlock()

	return nil
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
	required := STUNHeaderSize + UDPHeaderSize + len(payload) + TagSize + 64
	pBuf := getUDPSendBuf(required)
	defer putUDPSendBuf(pBuf)
	ch.sendMu.RLock()
	defer ch.sendMu.RUnlock()
	return ch.sendWithBuffer(payload, *pBuf)
}

// SendWithBuffer encrypts and sends payload using caller-owned scratch space.
func (ch *UDPChannel) SendWithBuffer(payload []byte, buf []byte) error {
	required := STUNHeaderSize + UDPHeaderSize + len(payload) + TagSize + 64
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
	if ch.UseBucketPadding && len(payload) > 0 {
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
		offset := 0
		if IsSTUNHeader(ch.recvBuf[:n]) {
			offset = STUNHeaderSize
		} else if IsSRTPHeader(ch.recvBuf[:n]) {
			offset = SRTPHeaderSize
		}
		if n-offset < UDPHeaderSize+TagSize {
			continue
		}

		packetData := ch.recvBuf[offset:n]
		sample := packetData[UDPHeaderSize : UDPHeaderSize+16]

		var tag [UDPTagSize]byte
		copy(tag[:], packetData[:UDPTagSize])

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

		// Unframe Bucket Padding length if present
		if ch.UseBucketPadding && len(plain) >= 2 {
			origLen := int(binary.BigEndian.Uint16(plain[:2]))
			if origLen > 0 && origLen <= len(plain)-2 {
				copy(dst, plain[2:2+origLen])
				return origLen, nil
			}
		}

		if len(plain) == 0 {
			continue
		}

		return len(plain), nil
	}
}

func (ch *UDPChannel) Close() error {
	return ch.conn.Close()
}

// ── UDPMux (server-side, one shared socket, many sessions) ───────────────────

type UDPMux struct {
	conn       *net.UDPConn
	listeners  atomic.Pointer[[]*net.UDPConn]
	listMu     sync.Mutex
	table      *SessionTable
	mruSession atomic.Pointer[UDPSession]
}

type UDPSession struct {
	mux         *UDPMux
	encAEAD     cipher.AEAD
	decAEAD     cipher.AEAD
	prevDecAEAD cipher.AEAD
	hp          cipher.Block
	prevHp      cipher.Block
	tag         [UDPTagSize]byte
	prevTag     [UDPTagSize]byte

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

	sendMu    sync.RWMutex
	recvMu    sync.Mutex
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

func (m *UDPMux) RegisterSession(keys *UDPKeys) (*UDPSession, error) {
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
		dataIn:           make(chan []byte, udpSessionQueueSize),
		done:             make(chan struct{}),
	}
	s.rtpSeq.Store(uint32(mathrand.Uint32() & 0xFFFF))
	s.rtpTS.Store(mathrand.Uint32())
	s.activeConn.Store(m.conn)

	m.table.Set(s.tag, s)
	m.mruSession.Store(s)
	return s, nil
}

func (m *UDPMux) UnregisterSession(tag [UDPTagSize]byte) {
	m.table.Delete(tag)
	if mru := m.mruSession.Load(); mru != nil && mru.tag == tag {
		m.mruSession.Store(nil)
	}
}

// RatchetEpoch seamlessly updates session keys for in-tunnel epoch rekeying.
func (s *UDPSession) RatchetEpoch(keys *UDPKeys) error {
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

	s.sendMu.Lock()
	s.encAEAD = enc
	oldHp := s.hp
	s.hp = hp
	oldTag := s.tag
	s.tag = keys.SessionTag
	s.sendMu.Unlock()

	s.recvMu.Lock()
	s.prevDecAEAD = s.decAEAD
	s.decAEAD = dec
	s.prevHp = oldHp
	s.prevTag = oldTag
	s.recvMu.Unlock()

	// Register new tag in session table while preserving old tag for transition window
	s.mux.table.Set(s.tag, s)
	return nil
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

	for {
		n, addr, err := conn.ReadFromUDP(buf[:])
		if err != nil {
			return
		}
		offset := 0
		if IsSTUNHeader(buf[:n]) {
			offset = STUNHeaderSize
		} else if IsSRTPHeader(buf[:n]) {
			offset = SRTPHeaderSize
		}
		if n-offset < UDPHeaderSize+TagSize {
			continue
		}

		packetData := buf[offset:n]
		sample := packetData[UDPHeaderSize : UDPHeaderSize+16]

		var tag [UDPTagSize]byte
		copy(tag[:], packetData[:UDPTagSize])

		var foundSess *UDPSession
		var isPrevTag bool

		// 1. Fast-path: check most recently used (MRU) session
		if mru := m.mruSession.Load(); mru != nil {
			if mru.tag == tag {
				foundSess = mru
			} else if mru.prevDecAEAD != nil && mru.prevTag == tag {
				foundSess = mru
				isPrevTag = true
			}
		}

		// 2. O(1) Sharded Table Lookup: instant session resolution
		if foundSess == nil {
			sess := m.table.Get(tag)
			if sess != nil {
				foundSess = sess
				isPrevTag = (sess.tag != tag && sess.prevTag == tag)
				m.mruSession.Store(sess)
			}
		}

		// Instant O(1) drop for unauthorized/invalid packets — 0 crypto operations, 0 DoS!
		if foundSess == nil {
			continue
		}

		// Select cipher and counter protection key based on epoch
		foundSess.recvMu.Lock()
		dec := foundSess.decAEAD
		hp := foundSess.hp
		if isPrevTag {
			if foundSess.prevDecAEAD != nil {
				dec = foundSess.prevDecAEAD
			}
			if foundSess.prevHp != nil {
				hp = foundSess.prevHp
			}
		}
		foundSess.recvMu.Unlock()

		if dec == nil || hp == nil {
			continue
		}

		// 3. Unmask counter: XOR 8-byte counter with AES(ciphertext sample)
		var ctrBuf [UDPCounterSize]byte
		copy(ctrBuf[:], packetData[UDPTagSize:UDPHeaderSize])
		protectCounter(hp, ctrBuf[:], sample)
		ctr := binary.BigEndian.Uint64(ctrBuf[:])

		// 4. Decrypt with AAD = plaintext header (tag || ctrBuf)
		var aad [UDPHeaderSize]byte
		copy(aad[:UDPTagSize], tag[:])
		copy(aad[UDPTagSize:], ctrBuf[:])

		nonce := udpNonce(ctr)
		pkt := getPkt(len(packetData) - UDPHeaderSize)
		plain, err := dec.Open(pkt[:0], nonce[:], packetData[UDPHeaderSize:], aad[:])
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
		foundSess.clientAddr.Store(addr)
		foundSess.activeConn.Store(conn)

		// 7. Unframe Bucket Padding length if enabled
		actual := plain
		if foundSess.UseBucketPadding && len(plain) >= 2 {
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

	ctr := s.sendCtr.Add(1) - 1

	plainPayload := payload
	var padBufHolder *[]byte
	if s.UseBucketPadding && len(payload) > 0 {
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

	needed := headerOffset + UDPHeaderSize + len(plainPayload) + TagSize + 64
	pBuf := getUDPSendBuf(needed)
	defer putUDPSendBuf(pBuf)
	buf := *pBuf

	// 1. Plaintext header (RouteTag 4B + Counter 8B)
	copy(buf[headerOffset:headerOffset+UDPTagSize], s.tag[:])
	binary.BigEndian.PutUint64(buf[headerOffset+UDPTagSize:headerOffset+UDPHeaderSize], ctr)

	// 2. Encrypt with AAD = plaintext header
	nonce := udpNonce(ctr)
	sealed := s.encAEAD.Seal(buf[headerOffset+UDPHeaderSize:headerOffset+UDPHeaderSize], nonce[:], plainPayload, buf[headerOffset:headerOffset+UDPHeaderSize])

	// 3. Counter protection: XOR counter with AES(ciphertext sample)
	protectCounter(s.hp, buf[headerOffset+UDPTagSize:headerOffset+UDPHeaderSize], buf[headerOffset+UDPHeaderSize:headerOffset+UDPHeaderSize+16])

	outConn := s.activeConn.Load()
	if outConn == nil {
		outConn = s.mux.conn
	}

	if s.EnableSTUN {
		bodyLen := uint16(UDPHeaderSize + len(sealed))
		writeSTUNHeader(buf[:STUNHeaderSize], bodyLen, 0x0101) // STUN Binding Success Response
		_, err := outConn.WriteToUDP(buf[:STUNHeaderSize+int(bodyLen)], addr)
		return err
	}

	_, err := outConn.WriteToUDP(buf[:UDPHeaderSize+len(sealed)], addr)
	return err
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
		s.mux.UnregisterSession(s.tag)
		if s.prevTag != [UDPTagSize]byte{} {
			s.mux.UnregisterSession(s.prevTag)
		}
		select {
		case <-s.done:
		default:
			close(s.done)
		}
	})
}
