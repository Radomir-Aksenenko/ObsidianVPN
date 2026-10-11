package main

import "encoding/binary"

// Client-facing MSS values. A plain Ethernet host advertises 1460 (IPv4) and 1440 (IPv6),
// that is 1500 minus the IP and TCP headers, so the tunnel's smaller MTU does not show up
// in the SYN a website sees.
const (
	externalMSS4 = 1460
	externalMSS6 = 1440
	minClientMTU = 1280
	maxTunnelMTU = 1420

	ipProtoTCP = 6
	tcpFIN     = 0x01
	tcpSYN     = 0x02
	tcpPSH     = 0x08
	tcpOptMSS  = 2
)

// tunnelMTUFor returns the inner packet size that fits the encrypted transport.
func tunnelMTUFor(configured int) int {
	if configured <= 0 || configured > maxTunnelMTU {
		return maxTunnelMTU
	}
	return configured
}

// tcpLayout describes where the TCP header sits in an IPv4 or IPv6 packet.
type tcpLayout struct {
	v6     bool
	ipLen  int // IP header length
	tcpLen int // TCP header length, options included
	total  int // IP total length; bytes past it are ignored
}

// locateTCP finds the TCP header of an unfragmented TCP packet. IPv4 fragments and IPv6
// packets with extension headers are not located.
func locateTCP(pkt []byte) (tcpLayout, bool) {
	var l tcpLayout
	if len(pkt) < 1 {
		return l, false
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return l, false
		}
		ihl := int(pkt[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(pkt[2:4]))
		if ihl < 20 || total < ihl || total > len(pkt) || pkt[9] != ipProtoTCP {
			return l, false
		}
		// MF flag or a non-zero fragment offset.
		if binary.BigEndian.Uint16(pkt[6:8])&0x3fff != 0 {
			return l, false
		}
		l.ipLen, l.total = ihl, total
	case 6:
		if len(pkt) < 40 || pkt[6] != ipProtoTCP {
			return l, false
		}
		total := 40 + int(binary.BigEndian.Uint16(pkt[4:6]))
		if total > len(pkt) {
			return l, false
		}
		l.v6, l.ipLen, l.total = true, 40, total
	default:
		return l, false
	}
	if l.total < l.ipLen+20 {
		return l, false
	}
	l.tcpLen = int(pkt[l.ipLen+12]>>4) * 4
	if l.tcpLen < 20 || l.ipLen+l.tcpLen > l.total {
		return l, false
	}
	return l, true
}

// mssOptionValue returns the offset of the MSS option value within a TCP header, or -1.
func mssOptionValue(hdr []byte) int {
	for i := 20; i < len(hdr); {
		switch hdr[i] {
		case 0: // end of option list
			return -1
		case 1: // NOP
			i++
			continue
		}
		if i+1 >= len(hdr) || hdr[i+1] < 2 || i+int(hdr[i+1]) > len(hdr) {
			return -1
		}
		if hdr[i] == tcpOptMSS && hdr[i+1] == 4 {
			return i + 2
		}
		i += int(hdr[i+1])
	}
	return -1
}

// onesSum adds b as big-endian 16-bit words; an odd trailing byte is padded with zero.
func onesSum(b []byte) uint32 {
	var sum uint32
	for ; len(b) >= 2; b = b[2:] {
		sum += uint32(binary.BigEndian.Uint16(b))
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	return sum
}

func foldSum(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return uint16(sum)
}

// pseudoSum returns the TCP pseudo-header sum for the addresses in ip.
func pseudoSum(ip []byte, v6 bool, segLen int) uint32 {
	var sum uint32
	if v6 {
		sum = onesSum(ip[8:40])
	} else {
		sum = onesSum(ip[12:20])
	}
	return sum + ipProtoTCP + uint32(segLen)
}

// setTCPChecksum recomputes the checksum of tcp, the TCP header and payload of the packet ip.
func setTCPChecksum(ip []byte, v6 bool, tcp []byte) {
	tcp[16], tcp[17] = 0, 0
	sum := pseudoSum(ip, v6, len(tcp)) + onesSum(tcp)
	binary.BigEndian.PutUint16(tcp[16:18], ^foldSum(sum))
}

// setIPv4Checksum recomputes the IPv4 header checksum of h.
func setIPv4Checksum(h []byte) {
	h[10], h[11] = 0, 0
	binary.BigEndian.PutUint16(h[10:12], ^foldSum(onesSum(h)))
}

// setMSSValue writes mss at offset idx of tcp and patches the TCP checksum per RFC 1624.
// The MSS value may start at an odd offset, so the affected 16-bit words are summed
// before and after the write.
func setMSSValue(tcp []byte, idx int, mss uint16) {
	start, end := idx&^1, (idx+3)&^1
	oldSum := onesSum(tcp[start:end])
	binary.BigEndian.PutUint16(tcp[idx:], mss)
	newSum := onesSum(tcp[start:end])
	m, mNew := foldSum(oldSum), foldSum(newSum)
	hc := binary.BigEndian.Uint16(tcp[16:18])
	// HC' = ~(~HC + ~m + m')
	binary.BigEndian.PutUint16(tcp[16:18], ^foldSum(uint32(^hc)+uint32(^m)+uint32(mNew)))
}

// normalizeUplinkSYN raises a client SYN's MSS to the external value. It returns the IP
// MTU the client's original MSS implies, or 0 if pkt is not a SYN with an MSS option.
func normalizeUplinkSYN(pkt []byte) int {
	l, ok := locateTCP(pkt)
	if !ok {
		return 0
	}
	tcp := pkt[l.ipLen:l.total]
	if tcp[13]&tcpSYN == 0 {
		return 0
	}
	idx := mssOptionValue(tcp[:l.tcpLen])
	if idx < 0 {
		return 0
	}
	mss := int(binary.BigEndian.Uint16(tcp[idx:]))
	ext, overhead := externalMSS4, 40
	if l.v6 {
		ext, overhead = externalMSS6, 60
	}
	if mss < ext {
		setMSSValue(tcp, idx, uint16(ext))
	}
	return mss + overhead
}

// clampDownlinkSYN lowers the MSS of a SYN or SYN-ACK sent to a client so the peer's
// segments fit limitMTU.
func clampDownlinkSYN(pkt []byte, limitMTU int) {
	l, ok := locateTCP(pkt)
	if !ok {
		return
	}
	tcp := pkt[l.ipLen:l.total]
	if tcp[13]&tcpSYN == 0 {
		return
	}
	idx := mssOptionValue(tcp[:l.tcpLen])
	if idx < 0 {
		return
	}
	overhead := 40
	if l.v6 {
		overhead = 60
	}
	limit := limitMTU - overhead
	if limit <= 0 {
		return
	}
	if int(binary.BigEndian.Uint16(tcp[idx:])) > limit {
		setMSSValue(tcp, idx, uint16(limit))
	}
}

// splitTCP cuts a TCP packet longer than maxLen into segments of at most maxLen bytes and
// passes each new packet to emit. It returns false without calling emit when pkt cannot
// be split.
func splitTCP(pkt []byte, maxLen int, emit func([]byte)) bool {
	l, ok := locateTCP(pkt)
	if !ok {
		return false
	}
	hdrLen := l.ipLen + l.tcpLen
	chunk := maxLen - hdrLen
	payload := pkt[hdrLen:l.total]
	if chunk <= 0 || len(payload) <= chunk {
		return false
	}
	id := binary.BigEndian.Uint16(pkt[4:6])
	seq := binary.BigEndian.Uint32(pkt[l.ipLen+4:])
	flags := pkt[l.ipLen+13]
	for i, off := 0, 0; off < len(payload); i, off = i+1, off+chunk {
		end := min(off+chunk, len(payload))
		buf := make([]byte, hdrLen+end-off)
		copy(buf, pkt[:hdrLen])
		copy(buf[hdrLen:], payload[off:end])
		if l.v6 {
			binary.BigEndian.PutUint16(buf[4:6], uint16(l.tcpLen+end-off))
		} else {
			binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))
			binary.BigEndian.PutUint16(buf[4:6], id+uint16(i))
			setIPv4Checksum(buf[:l.ipLen])
		}
		tcp := buf[l.ipLen:]
		binary.BigEndian.PutUint32(tcp[4:8], seq+uint32(off))
		if end != len(payload) {
			tcp[13] = flags &^ (tcpFIN | tcpPSH)
		} else {
			tcp[13] = flags
		}
		setTCPChecksum(buf, l.v6, tcp)
		emit(buf)
	}
	return true
}

// fragmentIPv4 splits an IPv4 packet longer than maxLen into fragments of at most maxLen
// bytes. DF is cleared on the fragments so the peer's large datagrams are not dropped.
// It returns false without calling emit when pkt cannot be fragmented.
func fragmentIPv4(pkt []byte, maxLen int, emit func([]byte)) bool {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return false
	}
	ihl := int(pkt[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if ihl < 20 || total < ihl || total > len(pkt) || total <= maxLen {
		return false
	}
	per := (maxLen - ihl) &^ 7
	if per <= 0 {
		return false
	}
	ff := binary.BigEndian.Uint16(pkt[6:8])
	base := int(ff&0x1fff) * 8
	moreFrags := ff&0x2000 != 0
	payload := pkt[ihl:total]
	for off := 0; off < len(payload); off += per {
		end := min(off+per, len(payload))
		frag := make([]byte, ihl+end-off)
		copy(frag, pkt[:ihl])
		copy(frag[ihl:], payload[off:end])
		binary.BigEndian.PutUint16(frag[2:4], uint16(len(frag)))
		f := uint16((base + off) / 8)
		if end != len(payload) || moreFrags {
			f |= 0x2000
		}
		binary.BigEndian.PutUint16(frag[6:8], f)
		setIPv4Checksum(frag[:ihl])
		emit(frag)
	}
	return true
}
