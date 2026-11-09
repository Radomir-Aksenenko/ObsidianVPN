package obsidian

import (
	"encoding/binary"
	mathrand "math/rand/v2"
	"time"
)

// MaintenanceDelay varies service events, never DATA packet timing. Bulk sends
// keep their batching/GSO path and pay no sleep per packet.
func MaintenanceDelay(base time.Duration) time.Duration {
	if base <= 0 {
		return time.Millisecond
	}
	span := base / 4
	if span == 0 {
		return base
	}
	return base - span + time.Duration(mathrand.Int64N(int64(2*span)+1))
}

// UDPProbeSchedule avoids synchronized recovery/keepalive trains. It is owned
// by one health-monitor goroutine. Active authenticated traffic replaces probes.
type UDPProbeSchedule struct{ recovery, keepalive time.Time }

func (s *UDPProbeSchedule) Due(now time.Time, active bool, lastAuthNano int64) bool {
	if !active {
		if s.recovery.IsZero() || !now.Before(s.recovery) {
			s.recovery = now.Add(MaintenanceDelay(7 * time.Second))
			return true
		}
		return false
	}
	if s.keepalive.IsZero() {
		s.keepalive = now.Add(MaintenanceDelay(18 * time.Second))
		return false
	}
	if now.Before(s.keepalive) {
		return false
	}
	s.keepalive = now.Add(MaintenanceDelay(18 * time.Second))
	return lastAuthNano == 0 || now.Sub(time.Unix(0, lastAuthNano)) >= 10*time.Second
}

// shapeUDPPayload is negotiated only by native REALITY transport. The encrypted
// length prefix permits randomized empty probes too. Padding is bounded: <=32
// extra bytes for small DATA, <=16 for medium DATA, none on full bulk packets.
// A 1420-byte inner packet stays within an IPv6 1500-byte outer packet.
func shapeUDPPayload(payload []byte) ([]byte, *[]byte) {
	total := 2 + len(payload)
	switch {
	case len(payload) == 0:
		total = 32 + mathrand.IntN(129)
	case len(payload) <= 256:
		total += mathrand.IntN(33)
	case len(payload) <= 1024:
		total += mathrand.IntN(17)
	}
	holder := getUDPPlainBuf()
	buf := *holder
	if total > cap(buf) {
		putUDPPlainBuf(holder)
		holder = nil
		buf = make([]byte, total)
	} else {
		buf = buf[:total]
	}
	binary.BigEndian.PutUint16(buf[:2], uint16(len(payload)))
	copy(buf[2:], payload)
	FastRandomBytes(buf[2+len(payload):])
	return buf, holder
}

func unshapeUDPPayload(plain []byte) ([]byte, bool) {
	if len(plain) < 2 {
		return nil, false
	}
	n := int(binary.BigEndian.Uint16(plain[:2]))
	if n > len(plain)-2 {
		return nil, false
	}
	return plain[2 : 2+n], true
}
