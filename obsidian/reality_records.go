package obsidian

import (
	"bufio"
	"crypto/cipher"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// ── REALITY record mode ──────────────────────────────────────────────────────
//
// Before record mode the stream after the ServerHello was raw tunnel bytes. A DPI box that
// follows TLS record framing sees the second server record fail to parse and knows the
// connection is not TLS. Record mode uses TLS 1.3-shaped framing with per-session AEAD
// protection of every inner byte, including the ML-KEM handshake. This is camouflage,
// not a completed, certificate-authenticated TLS handshake with the cover target:
//
//	client: ClientHello
//	server: the target's real first flight (ServerHello, CCS, encrypted handshake records)
//	client: CCS, a Finished-sized 0x17 record, then the tunnel in 0x17 records
//	server: the tunnel in 0x17 records
//
// The protected record reader skips a bounded unauthenticated cover-flight tail. Record
// mode is negotiated by the SessionID label; unknown labels are treated as probes.
// Falling back to the old raw format requires explicit compatibility settings.

// RealityAuthMode is the SessionID format, and with it the wire format after the ClientHello.
type RealityAuthMode int

const (
	// RealityAuthRecords is the masked SessionID with the record-mode label.
	RealityAuthRecords RealityAuthMode = iota
	// RealityAuthMasked is the masked SessionID, raw stream after the ServerHello.
	RealityAuthMasked
	// RealityAuthLegacy is the plain-timestamp SessionID, raw stream after the ServerHello.
	RealityAuthLegacy
	realityAuthModes
)

func (m RealityAuthMode) String() string {
	switch m {
	case RealityAuthRecords:
		return "records"
	case RealityAuthMasked:
		return "masked"
	case RealityAuthLegacy:
		return "legacy"
	}
	return fmt.Sprintf("mode(%d)", int(m))
}

var realityRecordsLabel = []byte("obsidian_reality_v5_records_aead")

// GenerateRecordSessionID builds a masked SessionID that also asks for record mode.
func GenerateRecordSessionID(authKey []byte, sni string) ([TLSSessionIDSize]byte, error) {
	return generateMaskedSessionIDLabel(authKey, sni, time.Now().Unix(), realityRecordsLabel)
}

const (
	tlsRecordHeaderSize = 5
	// tlsMaxRecordPayload is the size of a full TLS 1.3 record as servers send it during bulk
	// transfer: 2^14 bytes of plaintext, the content type byte and the 16-byte AEAD tag.
	tlsMaxRecordPayload = 16384 + 1 + 16
	tlsMaxCiphertext    = 16384 + 256

	recordTypeCCS       = 0x14
	recordTypeAlert     = 0x15
	recordTypeHandshake = 0x16
	recordTypeAppData   = 0x17
)

// ErrRealityAlert means the far end answered with a TLS alert: the genuine target, not our
// server, is on the other side, so the SessionID was not accepted.
var ErrRealityAlert = fmt.Errorf("%w: tls alert from peer", ErrRealityNoServerHello)

// tlsRecordConn carries a byte stream inside TLS application data records.
type tlsRecordConn struct {
	net.Conn

	rmu    sync.Mutex
	br     *bufio.Reader
	hdr    [tlsRecordHeaderSize]byte
	remain int // unread payload bytes of the current application data record

	wmu                       sync.Mutex
	wbuf                      []byte
	enc, dec                  cipher.AEAD
	writeCounter, readCounter uint64
	writeNonce, readNonce     [12]byte
	readBuf                   []byte
	readWire                  []byte
	readOff, flightSkipped    int
	readStarted               bool
}

func newTLSRecordConn(c net.Conn) *tlsRecordConn {
	// The buffer makes record headers and the byte-by-byte hello scan cheap; large reads still
	// go straight into the caller's slice.
	return &tlsRecordConn{Conn: c, br: bufio.NewReaderSize(c, 32*1024)}
}

// RealityRecordMode reports whether conn carries the tunnel inside TLS records, which also means
// the peer is new enough for the other record-mode formats (see UDPChannel.SetRouteMask).
func RealityRecordMode(conn net.Conn) bool {
	_, ok := conn.(*tlsRecordConn)
	return ok
}

func (c *tlsRecordConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if c.dec != nil {
		return c.readProtectedRecord(b)
	}
	for c.remain == 0 {
		if _, err := io.ReadFull(c.br, c.hdr[:]); err != nil {
			return 0, err
		}
		n := int(binary.BigEndian.Uint16(c.hdr[3:5]))
		if c.hdr[1] != 0x03 || n > tlsMaxCiphertext {
			return 0, fmt.Errorf("bad tls record header %x", c.hdr)
		}
		switch c.hdr[0] {
		case recordTypeAppData:
			c.remain = n
		case recordTypeCCS, recordTypeHandshake:
			// CCS, and handshake records such as NewSessionTicket: not ours, drop them.
			if err := c.discard(n); err != nil {
				return 0, err
			}
		case recordTypeAlert:
			return 0, ErrRealityAlert
		default:
			return 0, fmt.Errorf("unexpected tls record type 0x%02x", c.hdr[0])
		}
	}
	if len(b) > c.remain {
		b = b[:c.remain]
	}
	n, err := c.br.Read(b)
	c.remain -= n
	return n, err
}

func (c *tlsRecordConn) discard(n int) error {
	_, err := c.br.Discard(n)
	return err
}

// Write sends b as application data records in a single write, so a burst of tunnel frames
// still leaves in as few TCP segments as before.
func (c *tlsRecordConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	maxChunk, overhead := tlsMaxRecordPayload, 0
	if c.enc != nil {
		maxChunk, overhead = 16384, 1+c.enc.Overhead()
	}
	records := (len(b) + maxChunk - 1) / maxChunk
	need := len(b) + records*(tlsRecordHeaderSize+overhead)
	if cap(c.wbuf) < need {
		c.wbuf = make([]byte, need)
	}
	out := c.wbuf[:0]
	for p := b; len(p) > 0; {
		if c.enc != nil && c.writeCounter >= maxRealityRecords {
			return 0, errors.New("reality record key usage limit reached")
		}
		n := min(len(p), maxChunk)
		out = appendRecordHeader(out, recordTypeAppData, n+overhead)
		start := len(out)
		out = append(out, p[:n]...)
		if c.enc != nil {
			out = append(out, recordTypeAppData)
			binary.BigEndian.PutUint64(c.writeNonce[4:], c.writeCounter)
			out = c.enc.Seal(out[:start], c.writeNonce[:], out[start:], out[start-5:start])
			c.writeCounter++
		}
		p = p[n:]
	}
	if n, err := c.Conn.Write(out); err != nil {
		return 0, err
	} else if n != len(out) {
		return 0, io.ErrShortWrite
	}
	// Do not let one huge burst pin a large buffer for the life of the session.
	if cap(c.wbuf) > 256*1024 {
		c.wbuf = nil
	}
	return len(b), nil
}

func appendRecordHeader(dst []byte, typ byte, n int) []byte {
	return append(dst, typ, 0x03, 0x03, byte(n>>8), byte(n))
}

// readTLSRecord reads one whole record from r into a new slice, header included.
var errPartialTLSRecord = errors.New("incomplete TLS record")

func readTLSRecord(r io.Reader) ([]byte, error) {
	var hdr [tlsRecordHeaderSize]byte
	if n, err := io.ReadFull(r, hdr[:]); err != nil {
		if n > 0 {
			return nil, fmt.Errorf("%w: %w", errPartialTLSRecord, err)
		}
		return nil, err
	}
	if hdr[1] != 0x03 {
		return nil, fmt.Errorf("bad tls record header %x", hdr)
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if n > tlsMaxCiphertext {
		return nil, fmt.Errorf("tls record too large: %d", n)
	}
	rec := make([]byte, tlsRecordHeaderSize+n)
	copy(rec, hdr[:])
	if _, err := io.ReadFull(r, rec[tlsRecordHeaderSize:]); err != nil {
		return nil, fmt.Errorf("%w: %w", errPartialTLSRecord, err)
	}
	return rec, nil
}

// ── Server side: the first flight ────────────────────────────────────────────

const (
	// flightIdleGap ends the flight once the target goes quiet. TLS 1.3 servers send the whole
	// flight in one burst and then wait for the client.
	flightIdleGap = 120 * time.Millisecond
	flightMaxWait = 3 * time.Second
	flightMaxSize = 64 * 1024
)

// relayFirstFlight sends the client's ClientHello to the genuine target and streams the target's
// first flight (ServerHello, CCS, encrypted handshake records) to dst record by record, as it
// arrives. An authenticated client therefore sees the same bytes with the same timing as a
// prober, whose connection is relayed the same way. Once the target goes quiet the flight is
// over. An unavailable or incompatible target must fail the connection: inventing TLS 1.3
// records after a TLS 1.2 ServerHello or HelloRetryRequest creates an invalid wire transcript.
func relayFirstFlight(dst io.Writer, targetAddr string, clientHello, _ []byte, dialTimeout time.Duration) error {
	_, sawEncrypted, err := streamFlight(dst, targetAddr, clientHello, dialTimeout)
	if err != nil {
		var ne net.Error
		if !sawEncrypted || errors.Is(err, errFlightWrite) || errors.Is(err, errPartialTLSRecord) || !errors.As(err, &ne) || !ne.Timeout() {
			return err
		}
	}
	if !sawEncrypted {
		return errors.New("reality target did not send a TLS 1.3 encrypted flight")
	}
	return nil
}

var errFlightWrite = errors.New("write flight to client")

func streamFlight(dst io.Writer, targetAddr string, clientHello []byte, dialTimeout time.Duration) (sent int, sawEncrypted bool, err error) {
	if targetAddr == "" {
		return 0, false, errors.New("empty fallback target")
	}
	conn, err := net.DialTimeout("tcp", targetAddr, dialTimeout)
	if err != nil {
		return 0, false, err
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(dialTimeout))
	if _, err := conn.Write(clientHello); err != nil {
		return 0, false, err
	}
	start := time.Now()
	_ = conn.SetReadDeadline(start.Add(dialTimeout))
	for sent < flightMaxSize {
		rec, err := readTLSRecord(conn)
		if err != nil {
			if time.Since(start) >= flightMaxWait {
				return sent, sawEncrypted, errors.New("reality target flight exceeded time limit")
			}
			return sent, sawEncrypted, err // after the first record this is the idle gap
		}
		if sent+len(rec) > flightMaxSize {
			return sent, sawEncrypted, errors.New("reality target flight exceeded size limit")
		}
		if sent == 0 {
			if _, err := serverFinishedRecordSize(rec); err != nil {
				return 0, false, err
			}
		}
		switch rec[0] {
		case recordTypeHandshake, recordTypeCCS:
		case recordTypeAppData:
			sawEncrypted = true
		default:
			return sent, sawEncrypted, fmt.Errorf("target sent record type 0x%02x", rec[0])
		}
		if n, err := dst.Write(rec); err != nil {
			return sent, sawEncrypted, fmt.Errorf("%w: %w", errFlightWrite, err)
		} else if n != len(rec) {
			return sent, sawEncrypted, fmt.Errorf("%w: %w", errFlightWrite, io.ErrShortWrite)
		}
		sent += len(rec)
		deadline := time.Now().Add(flightIdleGap)
		if max := start.Add(flightMaxWait); deadline.After(max) {
			deadline = max
		}
		_ = conn.SetReadDeadline(deadline)
	}
	return sent, sawEncrypted, errors.New("reality target flight reached size limit")
}

// CheckRealityTarget reports whether target negotiates TLS 1.3 for sni. Record mode relays the
// target's flight, and only a TLS 1.3 flight has the shape the client expects.
func CheckRealityTarget(target, sni string, timeout time.Duration) error {
	d := &net.Dialer{Timeout: timeout}
	c, err := tls.DialWithDialer(d, "tcp", target, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // only the version matters here
		MinVersion:         tls.VersionTLS13,
	})
	if err != nil {
		return err
	}
	return c.Close()
}

// ── Client side ──────────────────────────────────────────────────────────────

// clientFinishRecords is what a TLS 1.3 client sends after the server flight: CCS and an
// encrypted Finished: handshake header + hash-sized verify_data + inner type + AEAD tag.
func clientFinishRecords(finishedSize int) []byte {
	out := appendRecordHeader(nil, recordTypeCCS, 1)
	out = append(out, 0x01)
	out = appendRecordHeader(out, recordTypeAppData, finishedSize)
	start := len(out)
	out = append(out, make([]byte, finishedSize)...)
	FastRandomBytes(out[start:])
	return out
}

// awaitServerFlight waits for the bounded first flight to go quiet. Answering after only
// EncryptedExtensions can put the client's Finished on the wire before the server's Finished.
// Without the target's traffic secret we cannot parse encrypted handshake boundaries, so this
// uses the same idle-gap heuristic as the relay, at a small connection-setup latency cost.
func awaitServerFlight(conn net.Conn) (int, error) {
	finishedSize := 0
	sawEncrypted := false
	start := time.Now()
	for total := 0; total < flightMaxSize; {
		rec, err := readTLSRecord(conn)
		if err != nil {
			var ne net.Error
			if sawEncrypted && !errors.Is(err, errPartialTLSRecord) && errors.As(err, &ne) && ne.Timeout() && time.Since(start) < flightMaxWait {
				return finishedSize, nil
			}
			return 0, fmt.Errorf("read reality server flight: %w: %w", ErrRealityNoServerHello, err)
		}
		total += len(rec)
		switch rec[0] {
		case recordTypeAppData:
			if finishedSize == 0 {
				return 0, errors.New("encrypted flight before TLS 1.3 ServerHello")
			}
			sawEncrypted = true
		case recordTypeHandshake:
			finishedSize, err = serverFinishedRecordSize(rec)
			if err != nil {
				return 0, err
			}
		case recordTypeCCS:
		case recordTypeAlert:
			return 0, ErrRealityAlert
		default:
			return 0, fmt.Errorf("unexpected TLS record content type: 0x%02x", rec[0])
		}
		if sawEncrypted {
			deadline := time.Now().Add(flightIdleGap)
			if limit := start.Add(flightMaxWait); deadline.After(limit) {
				deadline = limit
			}
			_ = conn.SetReadDeadline(deadline)
		}
	}
	return 0, fmt.Errorf("%w: no encrypted record in server flight", ErrRealityNoServerHello)
}

// serverFinishedRecordSize validates the visible ServerHello and uses its negotiated cipher
// suite to size the client's encrypted Finished. The inner handshake authenticates the VPN
// server; this parser alone does not authenticate the TLS transcript.
func serverFinishedRecordSize(rec []byte) (int, error) {
	bad := errors.New("reality target requires an ordinary TLS 1.3 ServerHello")
	if len(rec) < 44 || rec[0] != recordTypeHandshake || rec[5] != 2 {
		return 0, bad
	}
	if int(rec[6])<<16|int(rec[7])<<8|int(rec[8]) != len(rec)-9 || rec[9] != 3 || rec[10] != 3 {
		return 0, bad
	}
	hrr := [32]byte{0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c}
	if string(rec[11:43]) == string(hrr[:]) {
		return 0, bad
	}
	p := 44 + int(rec[43])
	if p+5 > len(rec) {
		return 0, bad
	}
	cipherSuite := binary.BigEndian.Uint16(rec[p : p+2])
	if rec[p+2] != 0 {
		return 0, bad
	}
	extLen := int(binary.BigEndian.Uint16(rec[p+3 : p+5]))
	p += 5
	if p+extLen != len(rec) {
		return 0, bad
	}
	tls13 := false
	for p < len(rec) {
		if p+4 > len(rec) {
			return 0, bad
		}
		typ, n := binary.BigEndian.Uint16(rec[p:p+2]), int(binary.BigEndian.Uint16(rec[p+2:p+4]))
		p += 4
		if p+n > len(rec) {
			return 0, bad
		}
		if typ == 43 && n == 2 && binary.BigEndian.Uint16(rec[p:p+2]) == tls.VersionTLS13 {
			tls13 = true
		}
		p += n
	}
	if !tls13 {
		return 0, bad
	}
	switch cipherSuite {
	case tls.TLS_AES_128_GCM_SHA256, tls.TLS_CHACHA20_POLY1305_SHA256:
		return 4 + 32 + 1 + 16, nil
	case tls.TLS_AES_256_GCM_SHA384:
		return 4 + 48 + 1 + 16, nil
	default:
		return 0, fmt.Errorf("unsupported reality target cipher suite: 0x%04x", cipherSuite)
	}
}
