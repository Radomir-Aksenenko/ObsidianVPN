package obsidian

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

var (
	testClientV6 = [16]byte{0xfd, 0x00, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02} // fd00:8::2 (tunnel client)
	testRemoteV6 = [16]byte{0x20, 0x01, 0x06, 0x7c, 0x04, 0xe8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a}
)

func buildTestIPv6(src, dst [16]byte, nh byte, payload []byte) []byte {
	pkt := make([]byte, 40+len(payload))
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(payload)))
	pkt[6] = nh
	pkt[7] = 64
	copy(pkt[8:24], src[:])
	copy(pkt[24:40], dst[:])
	copy(pkt[40:], payload)
	return pkt
}

// buildTestTCP returns a TCP segment (20-byte header, no options) with a valid checksum.
func buildTestTCP(src, dst [16]byte, sport, dport uint16, seq, ack uint32, flags byte, payload []byte) []byte {
	seg := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(seg[0:2], sport)
	binary.BigEndian.PutUint16(seg[2:4], dport)
	binary.BigEndian.PutUint32(seg[4:8], seq)
	binary.BigEndian.PutUint32(seg[8:12], ack)
	seg[12] = 5 << 4
	seg[13] = flags
	binary.BigEndian.PutUint16(seg[14:16], 65535)
	copy(seg[20:], payload)
	binary.BigEndian.PutUint16(seg[16:18], ipv6Checksum(src[:], dst[:], 6, seg))
	return seg
}

// verifyReply checks the IPv6 header, the upper-layer checksum (a valid checksum sums to zero
// with the checksum field included) and returns the upper-layer segment.
func verifyReply(t *testing.T, reply []byte, wantSrc, wantDst [16]byte, wantNH byte) []byte {
	t.Helper()
	if len(reply) < 40 {
		t.Fatalf("reply too short: %d", len(reply))
	}
	if reply[0]>>4 != 6 {
		t.Fatalf("reply is not IPv6")
	}
	plen := int(binary.BigEndian.Uint16(reply[4:6]))
	if 40+plen != len(reply) {
		t.Fatalf("payload length %d does not match packet length %d", plen, len(reply))
	}
	if reply[6] != wantNH {
		t.Fatalf("next header = %d, want %d", reply[6], wantNH)
	}
	if !bytes.Equal(reply[8:24], wantSrc[:]) {
		t.Fatalf("reply source %x, want %x", reply[8:24], wantSrc)
	}
	if !bytes.Equal(reply[24:40], wantDst[:]) {
		t.Fatalf("reply destination %x, want %x", reply[24:40], wantDst)
	}
	if len(reply) > 1280 {
		t.Fatalf("reply exceeds IPv6 minimum MTU: %d", len(reply))
	}
	seg := reply[40:]
	if got := ipv6Checksum(reply[8:24], reply[24:40], wantNH, seg); got != 0 {
		t.Fatalf("upper-layer checksum invalid (verify sum %#04x)", got)
	}
	return seg
}

func TestRejectTCPSynGetsRST(t *testing.T) {
	syn := buildTestTCP(testClientV6, testRemoteV6, 51000, 443, 1000, 0, tcpFlagSYN, nil)
	pkt := buildTestIPv6(testClientV6, testRemoteV6, 6, syn)

	out := make([]byte, IPv6RejectBufSize)
	n, ok := BuildIPv6Reject(pkt, out)
	if !ok {
		t.Fatal("expected a reply for a SYN")
	}
	seg := verifyReply(t, out[:n], testRemoteV6, testClientV6, 6)

	if binary.BigEndian.Uint16(seg[0:2]) != 443 || binary.BigEndian.Uint16(seg[2:4]) != 51000 {
		t.Fatalf("ports not swapped: sport=%d dport=%d", binary.BigEndian.Uint16(seg[0:2]), binary.BigEndian.Uint16(seg[2:4]))
	}
	if seg[13] != tcpFlagRST|tcpFlagACK {
		t.Fatalf("flags = %#x, want RST|ACK", seg[13])
	}
	// RFC 793: no ACK in the segment, so seq=0 and ack = SEG.SEQ + 1 (SYN counts as one).
	if binary.BigEndian.Uint32(seg[4:8]) != 0 {
		t.Fatalf("seq = %d, want 0", binary.BigEndian.Uint32(seg[4:8]))
	}
	if binary.BigEndian.Uint32(seg[8:12]) != 1001 {
		t.Fatalf("ack = %d, want 1001", binary.BigEndian.Uint32(seg[8:12]))
	}
}

func TestRejectTCPDataWithACKGetsRSTWithSeqFromAck(t *testing.T) {
	data := buildTestTCP(testClientV6, testRemoteV6, 51000, 443, 5000, 777, tcpFlagACK|0x08, make([]byte, 100))
	pkt := buildTestIPv6(testClientV6, testRemoteV6, 6, data)

	out := make([]byte, IPv6RejectBufSize)
	n, ok := BuildIPv6Reject(pkt, out)
	if !ok {
		t.Fatal("expected a reply for an ACK segment")
	}
	seg := verifyReply(t, out[:n], testRemoteV6, testClientV6, 6)
	if seg[13] != tcpFlagRST {
		t.Fatalf("flags = %#x, want bare RST (no ACK) per RFC 793", seg[13])
	}
	if binary.BigEndian.Uint32(seg[4:8]) != 777 {
		t.Fatalf("seq = %d, want SEG.ACK 777", binary.BigEndian.Uint32(seg[4:8]))
	}
}

func TestRejectTCPFINWithPayloadAckNumber(t *testing.T) {
	// No ACK: ack = SEQ + LEN where LEN = payload (100) + FIN (1).
	fin := buildTestTCP(testClientV6, testRemoteV6, 51000, 443, 2000, 0, tcpFlagFIN, make([]byte, 100))
	pkt := buildTestIPv6(testClientV6, testRemoteV6, 6, fin)
	out := make([]byte, IPv6RejectBufSize)
	n, ok := BuildIPv6Reject(pkt, out)
	if !ok {
		t.Fatal("expected a reply")
	}
	seg := verifyReply(t, out[:n], testRemoteV6, testClientV6, 6)
	if binary.BigEndian.Uint32(seg[8:12]) != 2101 {
		t.Fatalf("ack = %d, want 2101", binary.BigEndian.Uint32(seg[8:12]))
	}
}

func TestRejectNeverAnswersRST(t *testing.T) {
	rst := buildTestTCP(testClientV6, testRemoteV6, 51000, 443, 1, 0, tcpFlagRST, nil)
	out := make([]byte, IPv6RejectBufSize)
	if _, ok := BuildIPv6Reject(buildTestIPv6(testClientV6, testRemoteV6, 6, rst), out); ok {
		t.Fatal("must not answer a RST")
	}
}

func TestRejectUDPGetsICMPv6AdminProhibited(t *testing.T) {
	udp := make([]byte, 8+100)
	binary.BigEndian.PutUint16(udp[0:2], 40000)
	binary.BigEndian.PutUint16(udp[2:4], 443)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	pkt := buildTestIPv6(testClientV6, testRemoteV6, 17, udp)

	out := make([]byte, IPv6RejectBufSize)
	n, ok := BuildIPv6Reject(pkt, out)
	if !ok {
		t.Fatal("expected ICMPv6 for UDP")
	}
	seg := verifyReply(t, out[:n], testRemoteV6, testClientV6, 58)
	if seg[0] != 1 || seg[1] != 1 {
		t.Fatalf("type/code = %d/%d, want 1/1 (destination unreachable, administratively prohibited)", seg[0], seg[1])
	}
	if !bytes.Equal(seg[8:], pkt) {
		t.Fatalf("quoted packet does not match original (len %d vs %d)", len(seg)-8, len(pkt))
	}
}

func TestRejectICMPv6QuoteIsTruncatedTo1280(t *testing.T) {
	big := make([]byte, 1400)
	pkt := buildTestIPv6(testClientV6, testRemoteV6, 17, big[:1360])
	out := make([]byte, IPv6RejectBufSize)
	n, ok := BuildIPv6Reject(pkt, out)
	if !ok {
		t.Fatal("expected a reply")
	}
	if n != 1280 {
		t.Fatalf("reply length = %d, want 1280 (IPv6 minimum MTU)", n)
	}
	seg := verifyReply(t, out[:n], testRemoteV6, testClientV6, 58)
	if !bytes.Equal(seg[8:], pkt[:1232]) {
		t.Fatal("quote is not the first 1232 bytes of the original packet")
	}
}

func TestRejectICMPv6ErrorsAndMulticastAreNotAnswered(t *testing.T) {
	out := make([]byte, IPv6RejectBufSize)

	// ICMPv6 error (Destination Unreachable) must never be answered.
	errMsg := []byte{1, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4}
	if _, ok := BuildIPv6Reject(buildTestIPv6(testClientV6, testRemoteV6, 58, errMsg), out); ok {
		t.Fatal("must not answer an ICMPv6 error")
	}

	// ICMPv6 echo request (128) is answered with destination unreachable.
	echo := []byte{128, 0, 0, 0, 0, 1, 0, 1}
	if _, ok := BuildIPv6Reject(buildTestIPv6(testClientV6, testRemoteV6, 58, echo), out); !ok {
		t.Fatal("echo request should get a reject")
	}

	// Multicast destination (e.g. ND/MLD/mDNS) is never answered.
	mcast := [16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb}
	udp := make([]byte, 8)
	if _, ok := BuildIPv6Reject(buildTestIPv6(testClientV6, mcast, 17, udp), out); ok {
		t.Fatal("must not answer multicast")
	}
}

func TestRejectWalksExtensionHeaders(t *testing.T) {
	// Hop-by-hop options header (8 bytes, next header = TCP) before the SYN.
	hbh := []byte{6, 0, 1, 4, 0, 0, 0, 0}
	syn := buildTestTCP(testClientV6, testRemoteV6, 51000, 443, 42, 0, tcpFlagSYN, nil)
	pkt := buildTestIPv6(testClientV6, testRemoteV6, 0, append(hbh, syn...))

	out := make([]byte, IPv6RejectBufSize)
	n, ok := BuildIPv6Reject(pkt, out)
	if !ok {
		t.Fatal("expected RST after hop-by-hop header")
	}
	seg := verifyReply(t, out[:n], testRemoteV6, testClientV6, 6)
	if binary.BigEndian.Uint32(seg[8:12]) != 43 {
		t.Fatalf("ack = %d, want 43", binary.BigEndian.Uint32(seg[8:12]))
	}
}

func TestRejectMalformedInputIsIgnored(t *testing.T) {
	out := make([]byte, IPv6RejectBufSize)
	if _, ok := BuildIPv6Reject([]byte{0x60, 0, 0}, out); ok {
		t.Fatal("short packet must be ignored")
	}
	truncatedTCP := buildTestIPv6(testClientV6, testRemoteV6, 6, make([]byte, 10))
	if _, ok := BuildIPv6Reject(truncatedTCP, out); ok {
		t.Fatal("truncated TCP header must be ignored")
	}
}

func TestRejectLimiterBurstThenRefill(t *testing.T) {
	l := NewRejectLimiter(100, 3)
	for i := 0; i < 3; i++ {
		if !l.Allow() {
			t.Fatalf("burst token %d denied", i)
		}
	}
	if l.Allow() {
		t.Fatal("fourth reject must be denied while the bucket is empty")
	}
	time.Sleep(30 * time.Millisecond) // 100/s refills ~3 tokens in 30 ms
	if !l.Allow() {
		t.Fatal("bucket should refill")
	}
}
