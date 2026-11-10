package obsidian

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/hkdf"
)

// maxRealityRecords is the number of records sealed under one AES-GCM key, below the TLS 1.3
// per-key bound. At that point both peers step to the next key (see nextRealityRecordKey) and
// restart the counter, so a long session keeps running instead of failing. Older cores stop with
// an error at exactly this counter, so a mixed pair fails where it always did. A variable so tests
// can reach the boundary.
var maxRealityRecords uint64 = 1 << 24

const realityRecordUpdateLabel = "obsidian_reality_v5_record_update"

// nextRealityRecordKey replaces key in place with HKDF(key) and returns a GCM for it. The old key
// cannot be recovered from the new one, so records sealed before the step stay protected if the
// current key leaks later.
func nextRealityRecordKey(key *[32]byte) (cipher.AEAD, error) {
	var next [32]byte
	if _, err := io.ReadFull(hkdf.New(sha256.New, key[:], nil, []byte(realityRecordUpdateLabel)), next[:]); err != nil {
		return nil, err
	}
	*key = next
	clear(next[:])
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// newRealityRecordConn protects ALL tunnel bytes, including the pre-session handshake.
// Merely wrapping BuildHello in 0x17 records leaves the ML-KEM public key's canonical
// polynomial encoding visible. Use separate keys in each direction and fresh SessionID
// salt so no record nonce is reused across directions or connections.
func newRealityRecordConn(conn net.Conn, authKey, sessionID []byte, client bool) (*tlsRecordConn, error) {
	if len(authKey) < 16 || len(sessionID) != TLSSessionIDSize {
		return nil, errors.New("record mode requires a secret auth key of at least 16 bytes and a 32-byte SessionID")
	}
	derive := func(direction string, key *[32]byte) (cipher.AEAD, error) {
		if _, err := io.ReadFull(hkdf.New(sha256.New, authKey, sessionID,
			[]byte("obsidian_reality_v5_record_"+direction)), key[:]); err != nil {
			return nil, err
		}
		block, err := aes.NewCipher(key[:])
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	}
	var c2sKey, s2cKey [32]byte
	c2s, err := derive("c2s", &c2sKey)
	if err != nil {
		return nil, err
	}
	s2c, err := derive("s2c", &s2cKey)
	if err != nil {
		return nil, err
	}
	c := newTLSRecordConn(conn)
	c.enc, c.dec = c2s, s2c
	c.encKey, c.decKey = c2sKey, s2cKey
	if !client {
		c.enc, c.dec = s2c, c2s
		c.encKey, c.decKey = s2cKey, c2sKey
	}
	clear(c2sKey[:])
	clear(s2cKey[:])
	return c, nil
}

// readProtectedRecord skips only the bounded unauthenticated tail of the cover flight
// (including the client's dummy Finished). After the first authenticated record, any
// authentication failure terminates the stream; it must never resynchronize past corruption.
func (c *tlsRecordConn) readProtectedRecord(b []byte) (int, error) {
	if c.readWire == nil {
		c.readWire = make([]byte, tlsRecordHeaderSize+tlsMaxCiphertext)
	}
	for c.readOff == len(c.readBuf) {
		rec := c.readWire[:tlsRecordHeaderSize]
		if _, err := io.ReadFull(c.br, rec); err != nil {
			return 0, err
		}
		n := int(binary.BigEndian.Uint16(rec[3:5]))
		if rec[1] != 3 || rec[2] != 3 || n > tlsMaxCiphertext {
			return 0, errors.New("invalid reality record header")
		}
		rec = c.readWire[:tlsRecordHeaderSize+n]
		if _, err := io.ReadFull(c.br, rec[tlsRecordHeaderSize:]); err != nil {
			return 0, err
		}
		switch rec[0] {
		case recordTypeCCS:
			if c.readStarted || len(rec) != 6 || rec[5] != 1 {
				return 0, errors.New("unexpected reality change cipher spec")
			}
			c.flightSkipped += len(rec)
			if c.flightSkipped > ClientHelloScanLimit {
				return 0, errors.New("reality cover flight exceeds scan limit")
			}
			continue
		case recordTypeAppData:
		default:
			return 0, fmt.Errorf("unexpected reality record type 0x%02x", rec[0])
		}
		if c.readCounter >= maxRealityRecords {
			dec, err := nextRealityRecordKey(&c.decKey)
			if err != nil {
				return 0, err
			}
			c.dec, c.readCounter = dec, 0
		}
		binary.BigEndian.PutUint64(c.readNonce[4:], c.readCounter)
		plain, err := c.dec.Open(rec[5:5], c.readNonce[:], rec[5:], rec[:5])
		if err != nil {
			if !c.readStarted {
				c.flightSkipped += len(rec)
				if c.flightSkipped > ClientHelloScanLimit {
					return 0, errors.New("reality cover flight exceeds scan limit")
				}
				continue
			}
			return 0, fmt.Errorf("authenticate reality record: %w", err)
		}
		if len(plain) == 0 || plain[len(plain)-1] != recordTypeAppData {
			return 0, errors.New("invalid reality inner content type")
		}
		c.readCounter++
		c.readStarted = true
		c.readBuf = plain[:len(plain)-1]
		c.readOff = 0
	}
	n := copy(b, c.readBuf[c.readOff:])
	c.readOff += n
	return n, nil
}
