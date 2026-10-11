package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

const tcpACK = 0x10

var (
	testClientV4 = []byte{10, 8, 0, 2}
	testRemoteV4 = []byte{93, 184, 216, 34}
	testClientV6 = [16]byte{0xfd, 0x00, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}
	testRemoteV6 = [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
)

// inetChecksum is an independent RFC 1071 checksum. Over a buffer that already holds a
// valid checksum it returns 0.
func inetChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func tcpPseudoHeader(ip []byte, v6 bool, segLen int) []byte {
	if v6 {
		p := append([]byte(nil), ip[8:40]...)
		p = binary.BigEndian.AppendUint32(p, uint32(segLen))
		return append(p, 0, 0, 0, 6)
	}
	p := append([]byte(nil), ip[12:20]...)
	p = append(p, 0, 6)
	return binary.BigEndian.AppendUint16(p, uint16(segLen))
}

// buildTCPPacket returns an IPv4 or IPv6 TCP packet with valid checksums.
func buildTCPPacket(v6 bool, id uint16, seq uint32, flags byte, opts, payload []byte) []byte {
	tcpLen := 20 + len(opts)
	segLen := tcpLen + len(payload)
	ipLen := 20
	if v6 {
		ipLen = 40
	}
	pkt := make([]byte, ipLen+segLen)
	if v6 {
		pkt[0] = 0x60
		binary.BigEndian.PutUint16(pkt[4:6], uint16(segLen))
		pkt[6] = 6
		pkt[7] = 64
		copy(pkt[8:24], testClientV6[:])
		copy(pkt[24:40], testRemoteV6[:])
	} else {
		pkt[0] = 0x45
		binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
		binary.BigEndian.PutUint16(pkt[4:6], id)
		pkt[8] = 64
		pkt[9] = 6
		copy(pkt[12:16], testClientV4)
		copy(pkt[16:20], testRemoteV4)
		binary.BigEndian.PutUint16(pkt[10:12], inetChecksum(pkt[:20]))
	}
	tcp := pkt[ipLen:]
	binary.BigEndian.PutUint16(tcp[0:2], 40000)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	tcp[12] = byte(tcpLen/4) << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[20:], opts)
	copy(tcp[tcpLen:], payload)
	binary.BigEndian.PutUint16(tcp[16:18], inetChecksum(append(tcpPseudoHeader(pkt, v6, segLen), tcp...)))
	return pkt
}

// requireValidChecksums fails the test unless the IPv4 header checksum and the TCP
// checksum of pkt are valid.
func requireValidChecksums(t *testing.T, pkt []byte, v6 bool) {
	t.Helper()
	ipLen := 20
	if v6 {
		ipLen = 40
	} else if inetChecksum(pkt[:20]) != 0 {
		t.Fatal("bad IPv4 header checksum")
	}
	seg := pkt[ipLen:]
	if inetChecksum(append(tcpPseudoHeader(pkt, v6, len(seg)), seg...)) != 0 {
		t.Fatal("bad TCP checksum")
	}
}

func TestNormalizeUplinkSYN(t *testing.T) {
	cases := []struct {
		name    string
		v6      bool
		flags   byte
		opts    []byte
		mssAt   int // offset of the MSS value within the TCP header; 0 if absent
		wantRet int
		wantMSS uint16
	}{
		{"v4 MSS 1240 raised", false, tcpSYN, []byte{2, 4, 0x04, 0xd8, 1, 3, 3, 7}, 22, 1280, 1460},
		{"v4 MSS after NOP raised", false, tcpSYN, []byte{1, 2, 4, 0x04, 0xd8, 1, 1, 1}, 23, 1280, 1460},
		{"v6 MSS 1220 raised", true, tcpSYN, []byte{2, 4, 0x04, 0xc4, 1, 3, 3, 7}, 22, 1280, 1440},
		{"v4 MSS 1460 kept", false, tcpSYN, []byte{2, 4, 0x05, 0xb4, 1, 3, 3, 7}, 22, 1500, 1460},
		{"not a SYN ignored", false, tcpACK, []byte{2, 4, 0x04, 0xd8, 1, 3, 3, 7}, 22, 0, 1240},
		{"no MSS option ignored", false, tcpSYN, []byte{1, 1, 1, 1}, 0, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkt := buildTCPPacket(tc.v6, 1, 100, tc.flags, tc.opts, nil)
			ipLen := 20
			if tc.v6 {
				ipLen = 40
			}
			if got := normalizeUplinkSYN(pkt); got != tc.wantRet {
				t.Fatalf("returned %d, want %d", got, tc.wantRet)
			}
			if tc.mssAt != 0 {
				if got := binary.BigEndian.Uint16(pkt[ipLen+tc.mssAt:]); got != tc.wantMSS {
					t.Fatalf("MSS = %d, want %d", got, tc.wantMSS)
				}
			}
			requireValidChecksums(t, pkt, tc.v6)
		})
	}
}

func TestClampDownlinkSYNACK(t *testing.T) {
	cases := []struct {
		name    string
		v6      bool
		opts    []byte
		wantMSS uint16
	}{
		{"v4 MSS 1460 clamped to 1240", false, []byte{2, 4, 0x05, 0xb4, 1, 3, 3, 7}, 1240},
		{"v4 MSS 1200 untouched", false, []byte{2, 4, 0x04, 0xb0, 1, 3, 3, 7}, 1200},
		{"v6 MSS 1440 clamped to 1220", true, []byte{2, 4, 0x05, 0xa0, 1, 3, 3, 7}, 1220},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkt := buildTCPPacket(tc.v6, 1, 100, tcpSYN|tcpACK, tc.opts, nil)
			clampDownlinkSYN(pkt, 1280)
			ipLen := 20
			if tc.v6 {
				ipLen = 40
			}
			if got := binary.BigEndian.Uint16(pkt[ipLen+22:]); got != tc.wantMSS {
				t.Fatalf("MSS = %d, want %d", got, tc.wantMSS)
			}
			requireValidChecksums(t, pkt, tc.v6)
		})
	}
}

func TestSplitTCP(t *testing.T) {
	const maxLen = 1280
	const tcpACKPSHFIN = tcpACK | tcpPSH | tcpFIN
	opts := []byte{1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2}
	for _, v6 := range []bool{false, true} {
		name, ipLen := "IPv4", 20
		if v6 {
			name, ipLen = "IPv6", 40
		}
		t.Run(name, func(t *testing.T) {
			tcpLen := 20 + len(opts)
			payload := make([]byte, 1500-ipLen-tcpLen)
			for i := range payload {
				payload[i] = byte(i*7 + 3)
			}
			orig := buildTCPPacket(v6, 0x1234, 1000, tcpACKPSHFIN, opts, payload)
			if len(orig) != 1500 {
				t.Fatalf("test packet len %d, want 1500", len(orig))
			}

			var pieces [][]byte
			if !splitTCP(orig, maxLen, func(p []byte) { pieces = append(pieces, p) }) {
				t.Fatal("splitTCP refused a TCP packet")
			}
			if len(pieces) != 2 {
				t.Fatalf("got %d pieces, want 2", len(pieces))
			}

			var got []byte
			wantSeq := uint32(1000)
			for i, p := range pieces {
				if len(p) > maxLen {
					t.Fatalf("piece %d len %d exceeds %d", i, len(p), maxLen)
				}
				requireValidChecksums(t, p, v6)
				tcp := p[ipLen:]
				if v6 {
					if int(binary.BigEndian.Uint16(p[4:6])) != len(p)-40 {
						t.Fatalf("piece %d: IPv6 payload length not updated", i)
					}
				} else {
					if int(binary.BigEndian.Uint16(p[2:4])) != len(p) {
						t.Fatalf("piece %d: IPv4 total length not updated", i)
					}
					if id := binary.BigEndian.Uint16(p[4:6]); id != 0x1234+uint16(i) {
						t.Fatalf("piece %d: IPv4 ID = %#x", i, id)
					}
				}
				if seq := binary.BigEndian.Uint32(tcp[4:8]); seq != wantSeq {
					t.Fatalf("piece %d: seq = %d, want %d", i, seq, wantSeq)
				}
				wantFlags := byte(tcpACK)
				if i == len(pieces)-1 {
					wantFlags = tcpACKPSHFIN
				}
				if tcp[13] != wantFlags {
					t.Fatalf("piece %d: flags = %#x, want %#x", i, tcp[13], wantFlags)
				}
				data := tcp[tcpLen:]
				wantSeq += uint32(len(data))
				got = append(got, data...)
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("concatenated payload differs from the original")
			}
		})
	}
}

func TestSplitTCPRejectsUnsplittable(t *testing.T) {
	udp := make([]byte, 1500)
	udp[0] = 0x45
	binary.BigEndian.PutUint16(udp[2:4], 1500)
	udp[9] = 17

	frag := buildTCPPacket(false, 1, 1, tcpACK, nil, make([]byte, 1460))
	binary.BigEndian.PutUint16(frag[6:8], 0x2000|10) // MF set, offset 80

	for name, pkt := range map[string][]byte{"UDP": udp, "non-first fragment": frag} {
		called := false
		if splitTCP(pkt, 1280, func([]byte) { called = true }) {
			t.Fatalf("%s: splitTCP accepted the packet", name)
		}
		if called {
			t.Fatalf("%s: emit called for a refused packet", name)
		}
	}
}

func TestFragmentIPv4(t *testing.T) {
	const total = 1500
	const maxLen = 1280
	pkt := make([]byte, total)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], total)
	binary.BigEndian.PutUint16(pkt[4:6], 0xbeef)
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000) // DF
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], testClientV4)
	copy(pkt[16:20], testRemoteV4)
	for i := 20; i < total; i++ {
		pkt[i] = byte(i)
	}
	binary.BigEndian.PutUint16(pkt[10:12], inetChecksum(pkt[:20]))

	out := make([]byte, total-20)
	var frags int
	var covered int
	ok := fragmentIPv4(pkt, maxLen, func(f []byte) {
		frags++
		if len(f) > maxLen {
			t.Fatalf("fragment len %d exceeds %d", len(f), maxLen)
		}
		if inetChecksum(f[:20]) != 0 {
			t.Fatal("bad IPv4 header checksum on fragment")
		}
		if binary.BigEndian.Uint16(f[4:6]) != 0xbeef {
			t.Fatal("fragment ID changed")
		}
		ff := binary.BigEndian.Uint16(f[6:8])
		if ff&0x4000 != 0 {
			t.Fatal("DF still set on fragment")
		}
		off := int(ff&0x1fff) * 8
		more := ff&0x2000 != 0
		if last := off+len(f)-20 == total-20; more == last {
			t.Fatalf("fragment at offset %d: MF = %v, last = %v", off, more, last)
		}
		copy(out[off:], f[20:])
		covered += len(f) - 20
	})
	if !ok {
		t.Fatal("fragmentIPv4 refused an oversized packet")
	}
	if frags != 2 {
		t.Fatalf("got %d fragments, want 2", frags)
	}
	if covered != total-20 || !bytes.Equal(out, pkt[20:]) {
		t.Fatal("reassembled payload differs from the original")
	}
}
