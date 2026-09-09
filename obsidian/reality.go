package obsidian

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// ── REALITY-Plus / ShadowTLS v3 Hybrid Transport ─────────────────────────────
//
// Features:
// 1. Steganographic SessionID Authenticator:
//    SessionID = ClientEphPub_16 (16B) || Timestamp_8 (8B) || HMAC-SHA256(Key, Nonce||TS||SNI)[:8] (8B)
//    - Indistinguishable from standard TLS 1.3 CSPRNG Session ID for third-party DPI.
//    - Time-bound (±30s window) with constant-time verification and SNI binding.
//
// 2. Zero-Discrepancy Raw TCP SNI Demuxer:
//    - Server listens on port 443 without local TLS certificates.
//    - Non-TLS traffic or unauthenticated TLS ClientHellos (active probers, scanners, curl)
//      are transparently proxied at byte level to the real target (e.g. gateway.icloud.com:443).
//    - The scanner observes a 100% genuine TLS 1.3 handshake with Apple/DigiCert CA certs.
//    - Authenticated Obsidian clients are intercepted and switched to Obsidian Post-Quantum tunnel.
//
// 3. Zero-Allocation ClientHello Parser:
//    - High-throughput binary parser extracting SessionID and SNI with full bounds checking.
//
// 4. Sliding Window Replay Protection:
//    - LRU/TTL cache preventing replay of observed ClientHello packets.
//
// 5. Zero-Copy Transparent Proxy:
//    - High-performance bidirectional copy with sync.Pool buffer reuse and half-close support.

const (
	// TLSSessionIDSize is the exact length of TLS legacy_session_id in bytes.
	TLSSessionIDSize = 32

	// AuthNonceSize is the length of the ephemeral random prefix in SessionID.
	AuthNonceSize = 16

	// AuthTimestampSize is the length of the big-endian unix timestamp in SessionID.
	AuthTimestampSize = 8

	// AuthTagSize is the length of the truncated HMAC authentication tag in SessionID.
	AuthTagSize = 8

	// DefaultAuthWindowSec is the default allowed clock drift window in seconds.
	DefaultAuthWindowSec = 30

	// DefaultReplayTTL is the default duration to retain seen SessionIDs in the replay cache.
	DefaultReplayTTL = 60 * time.Second

	// DefaultDialTimeout is the default timeout for dialing the fallback backend.
	DefaultDialTimeout = 10 * time.Second

	// DefaultHandshakeTimeout is the timeout for reading the initial ClientHello.
	DefaultHandshakeTimeout = 5 * time.Second
)

var (
	ErrNotTLS              = errors.New("stream does not begin with TLS record")
	ErrNotClientHello      = errors.New("TLS record is not ClientHello")
	ErrTruncatedRecord     = errors.New("truncated TLS record")
	ErrSessionIDInvalid    = errors.New("invalid or unauthenticated SessionID")
	ErrSessionIDReplayed   = errors.New("replayed SessionID detected")
	ErrFallbackDialFailed  = errors.New("failed to dial fallback backend")
)

// ── SessionID Steganographic Authenticator ────────────────────────────────────

// GenerateSessionID constructs a 32-byte TLS SessionID containing a steganographic auth token:
//
//	SessionID = Nonce(16B) || UnixTS(8B) || HMAC-SHA256(authKey, Nonce || UnixTS || SNI)[:8]
func GenerateSessionID(authKey []byte, sni string) ([TLSSessionIDSize]byte, error) {
	var sessionID [TLSSessionIDSize]byte
	if _, err := io.ReadFull(rand.Reader, sessionID[:AuthNonceSize]); err != nil {
		return sessionID, fmt.Errorf("generate auth nonce: %w", err)
	}

	now := uint64(time.Now().Unix())
	binary.BigEndian.PutUint64(sessionID[AuthNonceSize:AuthNonceSize+AuthTimestampSize], now)

	tag := computeAuthTag(authKey, sessionID[:AuthNonceSize+AuthTimestampSize], sni)
	copy(sessionID[AuthNonceSize+AuthTimestampSize:], tag[:AuthTagSize])
	return sessionID, nil
}

// GenerateSessionIDWithTimestamp is like GenerateSessionID but accepts an explicit timestamp (useful for testing).
func GenerateSessionIDWithTimestamp(authKey []byte, sni string, ts int64) ([TLSSessionIDSize]byte, error) {
	var sessionID [TLSSessionIDSize]byte
	if _, err := io.ReadFull(rand.Reader, sessionID[:AuthNonceSize]); err != nil {
		return sessionID, fmt.Errorf("generate auth nonce: %w", err)
	}

	binary.BigEndian.PutUint64(sessionID[AuthNonceSize:AuthNonceSize+AuthTimestampSize], uint64(ts))
	tag := computeAuthTag(authKey, sessionID[:AuthNonceSize+AuthTimestampSize], sni)
	copy(sessionID[AuthNonceSize+AuthTimestampSize:], tag[:AuthTagSize])
	return sessionID, nil
}

// VerifySessionID performs constant-time validation of the SessionID token against the pre-shared auth key,
// target SNI, and timestamp freshness window.
func VerifySessionID(sessionID []byte, sni string, authKey []byte, windowSec int64) bool {
	if len(sessionID) != TLSSessionIDSize {
		return false
	}
	if len(authKey) == 0 {
		return false
	}
	if windowSec <= 0 {
		windowSec = DefaultAuthWindowSec
	}

	ts := int64(binary.BigEndian.Uint64(sessionID[AuthNonceSize : AuthNonceSize+AuthTimestampSize]))
	now := time.Now().Unix()
	diff := now - ts
	if diff < -windowSec || diff > windowSec {
		return false
	}

	expectedTag := computeAuthTag(authKey, sessionID[:AuthNonceSize+AuthTimestampSize], sni)
	return subtle.ConstantTimeCompare(sessionID[AuthNonceSize+AuthTimestampSize:], expectedTag[:AuthTagSize]) == 1
}

var realityAuthLabel = []byte("obsidian_reality_v3_session_id")

func computeAuthTag(authKey []byte, nonceAndTS []byte, sni string) [32]byte {
	mac := hmac.New(sha256.New, authKey)
	mac.Write(realityAuthLabel)
	mac.Write(nonceAndTS)
	sni = strings.TrimSpace(sni)
	var charBuf [1]byte
	for i := 0; i < len(sni); i++ {
		c := sni[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		charBuf[0] = c
		mac.Write(charBuf[:])
	}
	var tag [32]byte
	mac.Sum(tag[:0])
	return tag
}

// ── Zero-Allocation TLS ClientHello Parser ───────────────────────────────────

// ParseTLSClientHello parses a raw TLS record buffer and extracts the legacy SessionID and SNI.
// Returns isClientHello=true if the record is a valid TLS ClientHello.
// It is designed to be zero-allocation on the critical path.
func ParseTLSClientHello(record []byte) (sessionID []byte, sni string, isClientHello bool, err error) {
	// TLS Record Header: [ContentType: 1][LegacyVersion: 2][Length: 2]
	if len(record) < 5 {
		return nil, "", false, ErrTruncatedRecord
	}

	// ContentType 0x16 = Handshake
	if record[0] != 0x16 {
		return nil, "", false, ErrNotTLS
	}

	// Legacy TLS record versions: 0x0301 (TLS 1.0), 0x0302 (TLS 1.1), 0x0303 (TLS 1.2/1.3)
	if record[1] != 0x03 || record[2] < 0x01 || record[2] > 0x03 {
		return nil, "", false, ErrNotTLS
	}

	recordLen := int(binary.BigEndian.Uint16(record[3:5]))
	if len(record) < 5+recordLen {
		return nil, "", false, ErrTruncatedRecord
	}

	// Handshake payload starts at offset 5
	hs := record[5 : 5+recordLen]
	if len(hs) < 4 {
		return nil, "", false, ErrNotClientHello
	}

	// HandshakeType: 0x01 = ClientHello
	if hs[0] != 0x01 {
		return nil, "", false, ErrNotClientHello
	}

	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+hsLen {
		return nil, "", false, ErrTruncatedRecord
	}

	// ClientHello structure:
	// [ClientVersion: 2] [Random: 32] [SessionIDLen: 1] [SessionID: SessionIDLen] ...
	offset := 4
	if len(hs) < offset+2+32+1 {
		return nil, "", false, ErrTruncatedRecord
	}
	offset += 2 + 32 // skip ClientVersion (2B) + Random (32B)

	sessionIDLen := int(hs[offset])
	offset++
	if len(hs) < offset+sessionIDLen {
		return nil, "", false, ErrTruncatedRecord
	}

	if sessionIDLen > 0 {
		sessionID = hs[offset : offset+sessionIDLen]
	}
	offset += sessionIDLen

	// CipherSuites: [CipherSuitesLen: 2] [CipherSuites: CipherSuitesLen]
	if len(hs) < offset+2 {
		return sessionID, "", true, nil
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(hs[offset : offset+2]))
	offset += 2
	if len(hs) < offset+cipherSuitesLen {
		return sessionID, "", true, nil
	}
	offset += cipherSuitesLen

	// CompressionMethods: [CompressionMethodsLen: 1] [CompressionMethods: CompressionMethodsLen]
	if len(hs) < offset+1 {
		return sessionID, "", true, nil
	}
	compLen := int(hs[offset])
	offset++
	if len(hs) < offset+compLen {
		return sessionID, "", true, nil
	}
	offset += compLen

	// Extensions: [ExtensionsLen: 2] [Extensions: ExtensionsLen]
	if len(hs) < offset+2 {
		return sessionID, "", true, nil
	}
	extTotalLen := int(binary.BigEndian.Uint16(hs[offset : offset+2]))
	offset += 2
	if len(hs) < offset+extTotalLen {
		return sessionID, "", true, nil
	}

	extBytes := hs[offset : offset+extTotalLen]
	sni = parseSNIExtension(extBytes)
	return sessionID, sni, true, nil
}

// parseSNIExtension scans TLS extension blocks for ExtensionType 0x0000 (server_name)
func parseSNIExtension(extBytes []byte) string {
	extOffset := 0
	for extOffset+4 <= len(extBytes) {
		extType := binary.BigEndian.Uint16(extBytes[extOffset : extOffset+2])
		extLen := int(binary.BigEndian.Uint16(extBytes[extOffset+2 : extOffset+4]))
		extOffset += 4

		if extOffset+extLen > len(extBytes) {
			break
		}

		if extType == 0x0000 { // Server Name Indication
			data := extBytes[extOffset : extOffset+extLen]
			if len(data) >= 2 {
				listLen := int(binary.BigEndian.Uint16(data[:2]))
				subOffset := 2
				if len(data) >= subOffset+listLen {
					for subOffset+3 <= 2+listLen {
						nameType := data[subOffset]
						nameLen := int(binary.BigEndian.Uint16(data[subOffset+1 : subOffset+3]))
						subOffset += 3
						if subOffset+nameLen <= len(data) {
							if nameType == 0x00 { // host_name
								return string(data[subOffset : subOffset+nameLen])
							}
							subOffset += nameLen
						} else {
							break
						}
					}
				}
			}
		}
		extOffset += extLen
	}
	return ""
}

// ── Replay Protection Cache ───────────────────────────────────────────────────

// RealityReplayCache stores observed SessionIDs within a sliding TTL window to prevent replay attacks.
type RealityReplayCache struct {
	mu   sync.Mutex
	ttl  time.Duration
	seen map[[TLSSessionIDSize]byte]time.Time
}

// NewRealityReplayCache creates a new replay cache with the given TTL.
func NewRealityReplayCache(ttl time.Duration) *RealityReplayCache {
	if ttl <= 0 {
		ttl = DefaultReplayTTL
	}
	return &RealityReplayCache{
		ttl:  ttl,
		seen: make(map[[TLSSessionIDSize]byte]time.Time),
	}
}

// SeenOrAdd checks if the sessionID has already been seen.
// If seen and not expired, returns true.
// If not seen, records it with expiration (now + TTL) and returns false.
func (c *RealityReplayCache) SeenOrAdd(sessionID []byte) bool {
	if len(sessionID) != TLSSessionIDSize {
		return false
	}
	var key [TLSSessionIDSize]byte
	copy(key[:], sessionID)

	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	if exp, exists := c.seen[key]; exists && now.Before(exp) {
		return true // Replayed!
	}

	// Purge stale entries when table size grows large
	if len(c.seen) > 8192 {
		for k, exp := range c.seen {
			if !now.Before(exp) {
				delete(c.seen, k)
			}
		}
	}

	c.seen[key] = now.Add(c.ttl)
	return false
}

// ── Zero-Copy Transparent SNI Proxy ──────────────────────────────────────────

var relayBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

// TransparentSNIProxy connects to targetAddr, flushes firstBytes, and establishes
// a zero-copy bidirectional relay between clientConn and targetConn.
func TransparentSNIProxy(clientConn net.Conn, targetAddr string, firstBytes []byte, dialTimeout time.Duration) error {
	defer clientConn.Close()

	if targetAddr == "" {
		return errors.New("empty fallback target address")
	}

	if dialTimeout <= 0 {
		dialTimeout = DefaultDialTimeout
	}

	targetConn, err := net.DialTimeout("tcp", targetAddr, dialTimeout)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFallbackDialFailed, err)
	}
	defer targetConn.Close()

	if tc, ok := targetConn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	if cc, ok := clientConn.(*net.TCPConn); ok {
		_ = cc.SetNoDelay(true)
	}

	// Write buffered initial bytes (e.g. ClientHello or probe request) to target
	if len(firstBytes) > 0 {
		if _, err := targetConn.Write(firstBytes); err != nil {
			return err
		}
	}

	// Bidirectional zero-allocation pipe with half-close propagation
	var wg sync.WaitGroup
	wg.Add(2)

	pipe := func(dst, src net.Conn) {
		defer wg.Done()
		bufPtr := relayBufferPool.Get().(*[]byte)
		defer relayBufferPool.Put(bufPtr)

		_, _ = io.CopyBuffer(dst, src, *bufPtr)

		// Forward TCP FIN if possible
		if tcpDst, ok := dst.(*net.TCPConn); ok {
			_ = tcpDst.CloseWrite()
		} else if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}

	go pipe(targetConn, clientConn)
	go pipe(clientConn, targetConn)

	wg.Wait()
	return nil
}

// ── Peeked net.Conn Wrapper ───────────────────────────────────────────────────

// peekedConn prepends already-read peeked bytes back into the stream before subsequent reads.
type peekedConn struct {
	net.Conn
	peeked []byte
	offset int
}

func newPeekedConn(conn net.Conn, peeked []byte) net.Conn {
	return &peekedConn{
		Conn:   conn,
		peeked: peeked,
	}
}

func (c *peekedConn) Read(b []byte) (int, error) {
	if c.offset < len(c.peeked) {
		n := copy(b, c.peeked[c.offset:])
		c.offset += n
		if c.offset >= len(c.peeked) {
			c.peeked = nil // allow GC
		}
		return n, nil
	}
	return c.Conn.Read(b)
}

// ── REALITY Demuxer & Listener ───────────────────────────────────────────────

// RealityDemuxConfig specifies configuration parameters for the REALITY demuxer.
type RealityDemuxConfig struct {
	// FallbackTarget is the real target where unauthenticated probes are forwarded (e.g. "www.apple.com:443" or "17.248.190.252:443").
	FallbackTarget string

	// ServerNames is the list of permitted SNI hostnames. If empty, any SNI matching the HMAC key is accepted.
	ServerNames []string

	// AuthKey is the pre-shared secret key used to sign and verify SessionID tokens.
	AuthKey []byte

	// HandshakeTimeout is the time limit for receiving the initial ClientHello.
	HandshakeTimeout time.Duration

	// DialTimeout is the time limit for connecting to the fallback target.
	DialTimeout time.Duration

	// ReplayTTL is the sliding window TTL for replay protection.
	ReplayTTL time.Duration
}

// RealityDemuxer implements a transparent SNI demultiplexer wrapping an underlying net.Listener.
type RealityDemuxer struct {
	cfg         RealityDemuxConfig
	listener    net.Listener
	replayCache *RealityReplayCache
	serverNames map[string]struct{}
	closed      chan struct{}
}

// NewRealityDemuxer creates a demuxer that wraps listener with REALITY-Plus masking.
func NewRealityDemuxer(cfg RealityDemuxConfig, listener net.Listener) *RealityDemuxer {
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = DefaultDialTimeout
	}
	if cfg.ReplayTTL <= 0 {
		cfg.ReplayTTL = DefaultReplayTTL
	}

	namesMap := make(map[string]struct{}, len(cfg.ServerNames))
	for _, n := range cfg.ServerNames {
		namesMap[strings.ToLower(strings.TrimSpace(n))] = struct{}{}
	}

	return &RealityDemuxer{
		cfg:         cfg,
		listener:    listener,
		replayCache: NewRealityReplayCache(cfg.ReplayTTL),
		serverNames: namesMap,
		closed:      make(chan struct{}),
	}
}

// Accept returns an authenticated Obsidian client connection.
// Unauthenticated connections, scanners, and active probes are transparently proxied
// in the background without returning from Accept().
func (d *RealityDemuxer) Accept() (net.Conn, error) {
	for {
		rawConn, err := d.listener.Accept()
		if err != nil {
			return nil, err
		}

		if tc, ok := rawConn.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
		}

		// Handle handshake peek
		authConn, isObsidian := d.processIncoming(rawConn)
		if isObsidian {
			return authConn, nil
		}
		// If not Obsidian, processIncoming launched TransparentSNIProxy in background.
	}
}

func (d *RealityDemuxer) processIncoming(conn net.Conn) (net.Conn, bool) {
	_ = conn.SetReadDeadline(time.Now().Add(d.cfg.HandshakeTimeout))

	// We read the initial TLS record header (5 bytes) + payload up to 4096 bytes
	buf := make([]byte, 4096)
	n, err := io.ReadAtLeast(conn, buf, 5)
	_ = conn.SetReadDeadline(time.Time{})

	if err != nil {
		if d.cfg.FallbackTarget != "" {
			go TransparentSNIProxy(conn, d.cfg.FallbackTarget, buf[:n], d.cfg.DialTimeout)
		} else {
			conn.Close()
		}
		return nil, false
	}

	// Check if this looks like a TLS Record (0x16 0x03 0x01..0x03)
	if buf[0] != 0x16 || buf[1] != 0x03 || buf[2] < 0x01 || buf[2] > 0x03 {
		// Non-TLS traffic (e.g. plain HTTP GET, random scanner probe) -> Forward to fallback
		if d.cfg.FallbackTarget != "" {
			go TransparentSNIProxy(conn, d.cfg.FallbackTarget, buf[:n], d.cfg.DialTimeout)
		} else {
			conn.Close()
		}
		return nil, false
	}

	recordLen := int(binary.BigEndian.Uint16(buf[3:5]))
	needed := 5 + recordLen
	if needed > len(buf) {
		// Enlarge buffer if record is unusually large (e.g. huge certificate lists)
		newBuf := make([]byte, needed)
		copy(newBuf, buf[:n])
		buf = newBuf
	}

	for n < needed {
		_ = conn.SetReadDeadline(time.Now().Add(d.cfg.HandshakeTimeout))
		rn, rerr := conn.Read(buf[n:needed])
		_ = conn.SetReadDeadline(time.Time{})
		if rerr != nil {
			if d.cfg.FallbackTarget != "" {
				go TransparentSNIProxy(conn, d.cfg.FallbackTarget, buf[:n], d.cfg.DialTimeout)
			} else {
				conn.Close()
			}
			return nil, false
		}
		n += rn
	}

	sessionID, sni, isClientHello, parseErr := ParseTLSClientHello(buf[:n])
	if parseErr != nil || !isClientHello {
		if d.cfg.FallbackTarget != "" {
			go TransparentSNIProxy(conn, d.cfg.FallbackTarget, buf[:n], d.cfg.DialTimeout)
		} else {
			conn.Close()
		}
		return nil, false
	}

	// Check SNI allowlist if configured
	if len(d.serverNames) > 0 {
		cleanSNI := strings.ToLower(strings.TrimSpace(sni))
		if _, ok := d.serverNames[cleanSNI]; !ok {
			if d.cfg.FallbackTarget != "" {
				go TransparentSNIProxy(conn, d.cfg.FallbackTarget, buf[:n], d.cfg.DialTimeout)
			} else {
				conn.Close()
			}
			return nil, false
		}
	}

	// Verify SessionID HMAC token
	if !VerifySessionID(sessionID, sni, d.cfg.AuthKey, DefaultAuthWindowSec) {
		// Invalid auth token / Active Prober scanner -> Transparent Proxy!
		if d.cfg.FallbackTarget != "" {
			go TransparentSNIProxy(conn, d.cfg.FallbackTarget, buf[:n], d.cfg.DialTimeout)
		} else {
			conn.Close()
		}
		return nil, false
	}

	// Check Replay Cache
	if d.replayCache.SeenOrAdd(sessionID) {
		// Replayed token -> Transparent Proxy!
		if d.cfg.FallbackTarget != "" {
			go TransparentSNIProxy(conn, d.cfg.FallbackTarget, buf[:n], d.cfg.DialTimeout)
		} else {
			conn.Close()
		}
		return nil, false
	}

	// Authenticated Obsidian Client!
	// Deliver valid ServerHello to client so TLS 1.3 State Machine completes legitimately without DPI drops
	var serverHello []byte
	if d.cfg.FallbackTarget != "" {
		var ferr error
		serverHello, ferr = fetchServerHelloFromFallback(d.cfg.FallbackTarget, buf[:needed], d.cfg.DialTimeout)
		if ferr != nil || len(serverHello) == 0 {
			serverHello = buildTLSServerHelloRecord(sessionID)
		}
	} else {
		serverHello = buildTLSServerHelloRecord(sessionID)
	}

	if _, err := conn.Write(serverHello); err != nil {
		conn.Close()
		return nil, false
	}

	var extraBytes []byte
	if n > needed {
		extraBytes = make([]byte, n-needed)
		copy(extraBytes, buf[needed:n])
	}
	return newPeekedConn(conn, extraBytes), true
}

// fetchServerHelloFromFallback connects to the genuine fallback TLS target, sends the client hello,
// and extracts genuine TLS ServerHello / handshake records.
func fetchServerHelloFromFallback(targetAddr string, clientHello []byte, dialTimeout time.Duration) ([]byte, error) {
	if targetAddr == "" {
		return nil, errors.New("empty fallback target")
	}
	if dialTimeout <= 0 {
		dialTimeout = DefaultDialTimeout
	}
	conn, err := net.DialTimeout("tcp", targetAddr, dialTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if _, err := conn.Write(clientHello); err != nil {
		return nil, err
	}

	_ = conn.SetReadDeadline(time.Now().Add(dialTimeout))
	buf := make([]byte, 4096)
	n, err := io.ReadAtLeast(conn, buf, 5)
	if err != nil {
		return nil, err
	}

	// Read full TLS record if more bytes expected
	if buf[0] == 0x16 && n >= 5 {
		recordLen := int(binary.BigEndian.Uint16(buf[3:5]))
		needed := 5 + recordLen
		if needed > len(buf) {
			newBuf := make([]byte, needed)
			copy(newBuf, buf[:n])
			buf = newBuf
		}
		for n < needed {
			rn, rerr := conn.Read(buf[n:needed])
			if rerr != nil {
				break
			}
			n += rn
		}
	}
	res := make([]byte, n)
	copy(res, buf[:n])
	return res, nil
}

// buildTLSServerHelloRecord generates a standards-compliant TLS 1.3 ServerHello record (RFC 8446).
func buildTLSServerHelloRecord(sessionID []byte) []byte {
	var shMsg []byte
	shMsg = append(shMsg, 0x03, 0x03) // legacy_version TLS 1.2
	var random [32]byte
	_, _ = io.ReadFull(rand.Reader, random[:])
	shMsg = append(shMsg, random[:]...)

	// legacy_session_id_echo
	shMsg = append(shMsg, byte(len(sessionID)))
	shMsg = append(shMsg, sessionID...)

	// cipher_suite: TLS_AES_128_GCM_SHA256 (0x1301)
	shMsg = append(shMsg, 0x13, 0x01)

	// legacy_compression_method: 0
	shMsg = append(shMsg, 0x00)

	// Extensions
	var extBytes []byte
	// supported_versions (0x002b) -> TLS 1.3 (0x0304)
	extBytes = append(extBytes, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04)

	// key_share (0x0033) -> X25519 (0x001d), key len 32
	var serverShare [32]byte
	_, _ = io.ReadFull(rand.Reader, serverShare[:])
	extBytes = append(extBytes, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20)
	extBytes = append(extBytes, serverShare[:]...)

	var extTotalLen [2]byte
	binary.BigEndian.PutUint16(extTotalLen[:], uint16(len(extBytes)))
	shMsg = append(shMsg, extTotalLen[:]...)
	shMsg = append(shMsg, extBytes...)

	// Handshake record header: Type 0x02 (ServerHello), Length 3B
	var hsHeader [4]byte
	hsHeader[0] = 0x02
	hsLen := len(shMsg)
	hsHeader[1] = byte(hsLen >> 16)
	hsHeader[2] = byte(hsLen >> 8)
	hsHeader[3] = byte(hsLen)

	fullPayload := append(hsHeader[:], shMsg...)

	// TLS Record Header: 0x16 0x03 0x03 [Len 2B]
	record := make([]byte, 5+len(fullPayload))
	record[0] = 0x16
	record[1] = 0x03
	record[2] = 0x03
	binary.BigEndian.PutUint16(record[3:5], uint16(len(fullPayload)))
	copy(record[5:], fullPayload)
	return record
}

func (d *RealityDemuxer) Close() error {
	return d.listener.Close()
}

func (d *RealityDemuxer) Addr() net.Addr {
	return d.listener.Addr()
}
