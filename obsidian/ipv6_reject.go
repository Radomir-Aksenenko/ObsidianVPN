package obsidian

import (
	"encoding/binary"
	"sync"
	"time"
)

// Local rejection of IPv6 packets that cannot be carried by the tunnel.
//
// When IPv6 is disabled, silently dropping an IPv6 packet looks like a black hole to
// the host: TCP SYNs retransmit for seconds and Happy Eyeballs / QUIC stall. Instead the
// packet is answered locally with the same signal a router would give:
//   - TCP: RST (RFC 793 reset generation rules), so the connect fails at once.
//   - everything else: ICMPv6 Destination Unreachable, code 1 (administratively prohibited),
//     quoting the original packet (RFC 4443 section 3.1), limited to the 1280-byte IPv6 minimum MTU.
//
// No reply is generated for packets that must never be answered: multicast or
// unspecified destinations/sources, ICMPv6 error messages, and TCP RSTs.

const (
	ipv6HeaderLen     = 40
	ipv6MinMTU        = 1280
	icmpv6DestUnreach = 1
	icmpv6CodeAdmin   = 1
	icmpv6QuoteMax    = ipv6MinMTU - ipv6HeaderLen - 8
	ipv6NextTCP       = 6
	ipv6NextICMPv6    = 58
	tcpFlagFIN        = 0x01
	tcpFlagSYN        = 0x02
	tcpFlagRST        = 0x04
	tcpFlagACK        = 0x10
)

// IPv6RejectBufSize is the minimum output buffer for BuildIPv6Reject.
const IPv6RejectBufSize = ipv6MinMTU

// BuildIPv6Reject writes the locally generated reply for pkt into out and returns its
// length. ok is false when no reply should be sent. out must be at least IPv6RejectBufSize bytes.
func BuildIPv6Reject(pkt []byte, out []byte) (n int, ok bool) {
	if len(pkt) < ipv6HeaderLen || pkt[0]>>4 != 6 || len(out) < IPv6RejectBufSize {
		return 0, false
	}
	var src, dst [16]byte
	copy(src[:], pkt[8:24])
	copy(dst[:], pkt[24:40])
	if dst[0] == 0xff || src[0] == 0xff || isAllZero(src[:]) {
		return 0, false
	}

	// Walk the extension header chain to find the upper-layer protocol.
	nh := pkt[6]
	off := ipv6HeaderLen
	for nh == 0 || nh == 43 || nh == 60 { // hop-by-hop, routing, destination options
		if len(pkt) < off+2 {
			return 0, false
		}
		nh = pkt[off]
		off += (int(pkt[off+1]) + 1) * 8
		if off > len(pkt) {
			return 0, false
		}
	}

	if nh == ipv6NextTCP {
		return buildTCPReset(pkt, off, src, dst, out)
	}
	// ICMPv6 errors (types < 128) are never answered.
	if nh == ipv6NextICMPv6 && len(pkt) > off && pkt[off] < 128 {
		return 0, false
	}
	return buildICMPv6Unreach(pkt, src, dst, out), true
}

// buildTCPReset answers a TCP segment that has no connection behind it.
// RFC 793: if the segment carries ACK, RST.seq = SEG.ACK with no ACK flag; otherwise
// RST.seq = 0 and RST.ack = SEG.SEQ + SEG.LEN (SYN and FIN each count as one).
func buildTCPReset(pkt []byte, off int, src, dst [16]byte, out []byte) (int, bool) {
	if len(pkt) < off+20 {
		return 0, false
	}
	doff := int(pkt[off+12]>>4) * 4
	if doff < 20 || len(pkt) < off+doff {
		return 0, false
	}
	flags := pkt[off+13]
	if flags&tcpFlagRST != 0 {
		return 0, false
	}
	segSeq := binary.BigEndian.Uint32(pkt[off+4:])
	segAck := binary.BigEndian.Uint32(pkt[off+8:])

	// Payload length from the IPv6 header (bounded by the captured bytes).
	end := ipv6HeaderLen + int(binary.BigEndian.Uint16(pkt[4:6]))
	if end > len(pkt) {
		end = len(pkt)
	}
	segLen := uint32(0)
	if end-off-doff > 0 {
		segLen = uint32(end - off - doff)
	}
	if flags&tcpFlagSYN != 0 {
		segLen++
	}
	if flags&tcpFlagFIN != 0 {
		segLen++
	}

	var rseq, rack uint32
	var rflags byte
	if flags&tcpFlagACK != 0 {
		rseq = segAck
		rflags = tcpFlagRST
	} else {
		rack = segSeq + segLen
		rflags = tcpFlagRST | tcpFlagACK
	}

	n := ipv6HeaderLen + 20
	writeIPv6Header(out, dst, src, 20, ipv6NextTCP)
	tcp := out[ipv6HeaderLen:n]
	binary.BigEndian.PutUint16(tcp[0:2], binary.BigEndian.Uint16(pkt[off+2:off+4])) // our sport = their dport
	binary.BigEndian.PutUint16(tcp[2:4], binary.BigEndian.Uint16(pkt[off:off+2]))   // our dport = their sport
	binary.BigEndian.PutUint32(tcp[4:8], rseq)
	binary.BigEndian.PutUint32(tcp[8:12], rack)
	tcp[12] = 5 << 4
	tcp[13] = rflags
	tcp[14], tcp[15] = 0, 0 // window
	tcp[16], tcp[17] = 0, 0 // checksum
	tcp[18], tcp[19] = 0, 0 // urgent
	cs := ipv6Checksum(out[8:24], out[24:40], ipv6NextTCP, tcp)
	binary.BigEndian.PutUint16(tcp[16:18], cs)
	return n, true
}

// buildICMPv6Unreach writes ICMPv6 Destination Unreachable (type 1, code 1) quoting pkt.
func buildICMPv6Unreach(pkt []byte, src, dst [16]byte, out []byte) int {
	quote := len(pkt)
	if quote > icmpv6QuoteMax {
		quote = icmpv6QuoteMax
	}
	icmpLen := 8 + quote
	n := ipv6HeaderLen + icmpLen
	// Reply comes from the address the packet was sent to, back to its sender.
	writeIPv6Header(out, dst, src, icmpLen, ipv6NextICMPv6)
	icmp := out[ipv6HeaderLen:n]
	icmp[0] = icmpv6DestUnreach
	icmp[1] = icmpv6CodeAdmin
	icmp[2], icmp[3] = 0, 0 // checksum
	icmp[4], icmp[5], icmp[6], icmp[7] = 0, 0, 0, 0
	copy(icmp[8:], pkt[:quote])
	cs := ipv6Checksum(out[8:24], out[24:40], ipv6NextICMPv6, icmp)
	binary.BigEndian.PutUint16(icmp[2:4], cs)
	return n
}

func writeIPv6Header(out []byte, src, dst [16]byte, payloadLen int, nextHeader byte) {
	out[0] = 0x60
	out[1], out[2], out[3] = 0, 0, 0
	binary.BigEndian.PutUint16(out[4:6], uint16(payloadLen))
	out[6] = nextHeader
	out[7] = 64 // hop limit
	copy(out[8:24], src[:])
	copy(out[24:40], dst[:])
}

// ipv6Checksum computes the upper-layer checksum with the IPv6 pseudo-header (RFC 8200 section 8.1).
// The checksum field inside seg must be zero.
func ipv6Checksum(src, dst []byte, nextHeader byte, seg []byte) uint16 {
	var sum uint32
	sum = onesSum(src, sum)
	sum = onesSum(dst, sum)
	l := uint32(len(seg))
	sum += l >> 16
	sum += l & 0xffff
	sum += uint32(nextHeader)
	sum = onesSum(seg, sum)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func onesSum(b []byte, sum uint32) uint32 {
	i := 0
	for ; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if i < len(b) {
		sum += uint32(b[i]) << 8
	}
	return sum
}

func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// RejectLimiter is a token bucket for locally generated rejects, so that a flood of
// IPv6 packets cannot turn the tunnel into a packet amplifier or an allocation loop.
type RejectLimiter struct {
	mu     sync.Mutex
	rate   float64 // tokens per second
	burst  float64
	tokens float64
	last   time.Time
}

// NewRejectLimiter returns a limiter that allows perSec replies per second with a burst of burst.
func NewRejectLimiter(perSec, burst int) *RejectLimiter {
	if perSec <= 0 {
		perSec = 100
	}
	if burst <= 0 {
		burst = 20
	}
	return &RejectLimiter{rate: float64(perSec), burst: float64(burst), tokens: float64(burst)}
}

// Allow reports whether one more reject may be sent now.
func (l *RejectLimiter) Allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if !l.last.IsZero() {
		l.tokens += now.Sub(l.last).Seconds() * l.rate
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
	}
	l.last = now
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}
