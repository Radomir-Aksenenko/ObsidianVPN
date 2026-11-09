package obsidian

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"net"
	"sync"
	"time"
)

// ── REALITY record mode ──────────────────────────────────────────────────────
//
// Before record mode the stream after the ServerHello was raw tunnel bytes. A DPI box that
// follows TLS record framing sees the second server record fail to parse and knows the
// connection is not TLS. In record mode both directions look like a TLS 1.3 session:
//
//	client: ClientHello
//	server: the target's real first flight (ServerHello, CCS, encrypted handshake records)
//	client: CCS, a Finished-sized 0x17 record, then the tunnel in 0x17 records
//	server: the tunnel in 0x17 records
//
// The tunnel does not need a marker for where it starts: both sides already scan for the
// HMAC-tagged hello frame (ReadHelloFrame), and that scan skips the flight and the fake
// Finished. Record mode is negotiated by the SessionID label, so a server that does not know
// it treats the client as a prober, and the client falls back (see RealityAuthSelector).

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

var realityRecordsLabel = []byte("obsidian_reality_v4_records")

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

	wmu  sync.Mutex
	wbuf []byte
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
	records := (len(b) + tlsMaxRecordPayload - 1) / tlsMaxRecordPayload
	need := len(b) + records*tlsRecordHeaderSize
	if cap(c.wbuf) < need {
		c.wbuf = make([]byte, need)
	}
	out := c.wbuf[:0]
	for p := b; len(p) > 0; {
		n := min(len(p), tlsMaxRecordPayload)
		out = appendRecordHeader(out, recordTypeAppData, n)
		out = append(out, p[:n]...)
		p = p[n:]
	}
	if _, err := c.Conn.Write(out); err != nil {
		return 0, err
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
func readTLSRecord(r io.Reader) ([]byte, error) {
	var hdr [tlsRecordHeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
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
		return nil, err
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
// over. If the target cannot be reached, or never sends an encrypted record (TLS 1.2, a
// HelloRetryRequest), the missing part is synthesized so that the client can go on; check the
// target with CheckRealityTarget to avoid that.
func relayFirstFlight(dst io.Writer, targetAddr string, clientHello, sessionID []byte, dialTimeout time.Duration) error {
	sent, sawEncrypted, err := streamFlight(dst, targetAddr, clientHello, dialTimeout)
	if sawEncrypted {
		return nil
	}
	if sent == 0 {
		// Nothing reached the client yet: a whole synthetic flight looks consistent.
		_, werr := dst.Write(syntheticFirstFlight(sessionID))
		return werr
	}
	if err != nil && errors.Is(err, errFlightWrite) {
		return err
	}
	// The ServerHello went out but no encrypted record followed: finish with a synthetic one.
	_, werr := dst.Write(syntheticEncryptedFlight())
	return werr
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
	if _, err := conn.Write(clientHello); err != nil {
		return 0, false, err
	}
	start := time.Now()
	_ = conn.SetReadDeadline(start.Add(dialTimeout))
	for sent < flightMaxSize {
		rec, err := readTLSRecord(conn)
		if err != nil {
			return sent, sawEncrypted, err // after the first record this is the idle gap
		}
		switch rec[0] {
		case recordTypeHandshake, recordTypeCCS:
		case recordTypeAppData:
			sawEncrypted = true
		default:
			return sent, sawEncrypted, fmt.Errorf("target sent record type 0x%02x", rec[0])
		}
		if _, err := dst.Write(rec); err != nil {
			return sent, sawEncrypted, fmt.Errorf("%w: %w", errFlightWrite, err)
		}
		sent += len(rec)
		deadline := time.Now().Add(flightIdleGap)
		if max := start.Add(flightMaxWait); deadline.After(max) {
			deadline = max
		}
		_ = conn.SetReadDeadline(deadline)
	}
	return sent, sawEncrypted, nil
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

// syntheticFirstFlight stands in when the target cannot be reached: a ServerHello, CCS and
// encrypted records shaped like a typical certificate flight.
func syntheticFirstFlight(sessionID []byte) []byte {
	flight := buildTLSServerHelloRecord(sessionID)
	flight = appendRecordHeader(flight, recordTypeCCS, 1)
	flight = append(flight, 0x01)
	return append(flight, syntheticEncryptedFlight()...)
}

// syntheticEncryptedFlight is the encrypted part of a flight:
// EncryptedExtensions+Certificate+CertificateVerify, then Finished.
func syntheticEncryptedFlight() []byte {
	var flight []byte
	for _, n := range []int{2600 + mathrand.IntN(2400), 53} {
		flight = appendRecordHeader(flight, recordTypeAppData, n)
		start := len(flight)
		flight = append(flight, make([]byte, n)...)
		FastRandomBytes(flight[start:])
	}
	return flight
}

// ── Client side ──────────────────────────────────────────────────────────────

// clientFinishRecords is what a TLS 1.3 client sends after the server flight: CCS and an
// encrypted Finished (32-byte verify_data + type byte + 16-byte tag = 53 bytes).
func clientFinishRecords() []byte {
	out := appendRecordHeader(nil, recordTypeCCS, 1)
	out = append(out, 0x01)
	out = appendRecordHeader(out, recordTypeAppData, 53)
	start := len(out)
	out = append(out, make([]byte, 53)...)
	FastRandomBytes(out[start:])
	return out
}

// awaitServerFlight reads records until the first encrypted one, as a real client waits for the
// server flight before it answers. Later flight records are skipped by the tunnel's hello scan.
func awaitServerFlight(conn net.Conn) error {
	for i := 0; i < 16; i++ {
		rec, err := readTLSRecord(conn)
		if err != nil {
			return fmt.Errorf("read reality server flight: %w: %w", ErrRealityNoServerHello, err)
		}
		switch rec[0] {
		case recordTypeAppData:
			return nil
		case recordTypeHandshake, recordTypeCCS:
		case recordTypeAlert:
			return ErrRealityAlert
		default:
			return fmt.Errorf("unexpected TLS record content type: 0x%02x", rec[0])
		}
	}
	return fmt.Errorf("%w: no encrypted record in server flight", ErrRealityNoServerHello)
}
