package main

import (
	"encoding/binary"
	"log"
	"net/netip"
	"time"

	"obsidian/obsidian"
)

// Clients choose their own tunnel address, and they do not choose well: the iOS and Android
// apps hardcode 10.8.0.2, the desktop derives one from a hash. Old apps stay in the field, so
// the server cannot ask them to change. Instead every session gets a server-side address and
// its packets are translated on the way through, the client never sees it. A client whose
// address is still free keeps it and its packets are not touched at all.

// serverTunAddr6 is the server side of the in-tunnel IPv6 prefix.
const serverTunAddr6 = "fd00:8::1/64"

// addrReservation is how long a closed session's address stays with its device. Server NAT
// keeps its connections open across a reconnect only if the source address stays the same.
const addrReservation = 2 * time.Minute

// addrBinding maps the address a client uses to the one the server knows it by.
type addrBinding struct {
	client, virtual netip.Addr
}

type reservedAddr struct {
	identity [obsidian.KeySize]byte
	until    time.Time
}

// configureAddressing sets the IPv4 address pool from the server's tun_address, such as
// 10.8.0.1/24. Call it before run and before sessions are registered.
func (r *tunRouter) configureAddressing(tunAddress string) {
	if p, err := netip.ParsePrefix(tunAddress); err == nil && p.Addr().Is4() {
		r.pool4 = p
	} else if tunAddress != "" {
		log.Printf("tun_address %q is not an IPv4 prefix, using %s for client addresses", tunAddress, r.pool4)
	}
}

// setIdentity records the authenticated key of the device behind this session. Call it before
// the session carries traffic.
func (s *routedSession) setIdentity(key [obsidian.KeySize]byte) {
	s.router.mu.Lock()
	s.identity = key
	s.hasIdentity = true
	s.router.mu.Unlock()
}

func (s *routedSession) binding(addr netip.Addr) *addrBinding {
	if addr.Is4() {
		return s.bind4.Load()
	}
	return s.bind6.Load()
}

func (s *routedSession) storeBinding(addr netip.Addr, b *addrBinding) {
	if addr.Is4() {
		s.bind4.Store(b)
	} else {
		s.bind6.Store(b)
	}
}

// bindAddress returns the binding for a source address seen from this client, or nil if the
// session is closed or the pool is exhausted.
func (s *routedSession) bindAddress(src netip.Addr) *addrBinding {
	r := s.router
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, active := r.sessions[s]; !active {
		return nil
	}
	cur := s.binding(src)
	if cur != nil {
		if cur.client == src {
			return cur
		}
		b := &addrBinding{client: src, virtual: cur.virtual}
		s.storeBinding(src, b)
		return b
	}

	virtual, ok := r.pickAddress(s, src)
	if !ok {
		return nil
	}
	if prev := r.byIP[virtual]; prev != nil && prev != s {
		// The same device reconnected. The old session's next packet gets an address of its own.
		prev.superseded = true
		prev.storeBinding(src, nil)
	}
	r.byIP[virtual] = s
	delete(r.reserved, virtual)
	b := &addrBinding{client: src, virtual: virtual}
	s.storeBinding(src, b)
	if virtual == src {
		log.Printf("session %s: client address %s", s.sid, src)
	} else {
		log.Printf("session %s: client address %s is %s on the server", s.sid, src, virtual)
	}
	return b
}

// pickAddress chooses a server-side address: the one this device already holds, then the one
// the client asked for, then the first free one. Must be called with r.mu held.
func (r *tunRouter) pickAddress(s *routedSession, src netip.Addr) (netip.Addr, bool) {
	now := time.Now()
	if s.hasIdentity && !s.superseded {
		for other := range r.sessions {
			if other == s || other.superseded || !other.hasIdentity || other.identity != s.identity {
				continue
			}
			if b := other.binding(src); b != nil && b.client == src {
				return b.virtual, true
			}
		}
		for addr, res := range r.reserved {
			if res.identity == s.identity && addr.Is4() == src.Is4() && now.Before(res.until) {
				return addr, true
			}
		}
	}

	pool := r.pool4
	if src.Is6() {
		pool = r.pool6
	}
	free := func(a netip.Addr, honorReservations bool) bool {
		if r.byIP[a] != nil {
			return false
		}
		if res, held := r.reserved[a]; honorReservations && held && now.Before(res.until) {
			return false
		}
		return true
	}
	if usablePoolAddr(pool, src) && free(src, true) {
		return src, true
	}
	// Reservations give way only when nothing else is left.
	for _, honor := range []bool{true, false} {
		for a := pool.Masked().Addr().Next(); a.IsValid() && pool.Contains(a); a = a.Next() {
			if usablePoolAddr(pool, a) && free(a, honor) {
				return a, true
			}
		}
	}
	return netip.Addr{}, false
}

// usablePoolAddr reports whether a can be handed to a client: inside the pool, not the server's
// own address and not the IPv4 broadcast address.
func usablePoolAddr(pool netip.Prefix, a netip.Addr) bool {
	if !pool.Contains(a) || a == pool.Addr() || a == pool.Masked().Addr() {
		return false
	}
	if a.Is4() && pool.Bits() < 31 {
		bytes := a.As4()
		v := binary.BigEndian.Uint32(bytes[:])
		if hostMask := uint32(1)<<(32-pool.Bits()) - 1; v&hostMask == hostMask {
			return false
		}
	}
	return true
}

// releaseAddresses frees the session's addresses, keeping them for its device for a while.
// Must be called with r.mu held.
func (s *routedSession) releaseAddresses() {
	r := s.router
	now := time.Now()
	for addr, res := range r.reserved {
		if !now.Before(res.until) {
			delete(r.reserved, addr)
		}
	}
	for _, b := range []*addrBinding{s.bind4.Load(), s.bind6.Load()} {
		if b == nil || r.byIP[b.virtual] != s {
			continue
		}
		delete(r.byIP, b.virtual)
		if s.hasIdentity {
			r.reserved[b.virtual] = reservedAddr{identity: s.identity, until: now.Add(addrReservation)}
		}
	}
}

// translateUplink puts the session's server-side address into a client packet. It returns false
// when the packet must be dropped because no address is available for it.
func (s *routedSession) translateUplink(pkt []byte) bool {
	src, _, ok := packetEndpoints(pkt)
	if !ok || !src.IsValid() || src.IsUnspecified() || src.IsMulticast() || src.IsLinkLocalUnicast() {
		// Nothing can answer such a source, so it must not claim an address. Windows sends from
		// 169.254.x.x before the tunnel address is set.
		return true
	}
	b := s.binding(src)
	if b == nil || b.client != src {
		if b = s.bindAddress(src); b == nil {
			if dropLog.Ready() {
				log.Printf("session %s: no free client address for %s, dropping packet", s.sid, src)
			}
			return false
		}
	}
	if b.virtual != b.client {
		rewriteClientAddr(pkt, true, b.client, b.virtual)
	}
	return true
}

// restoreDownlink puts the client's own address back into a packet going to it.
func (s *routedSession) restoreDownlink(pkt []byte) {
	_, dst, ok := packetEndpoints(pkt)
	if !ok {
		return
	}
	if b := s.binding(dst); b != nil && b.virtual == dst && b.client != dst {
		rewriteClientAddr(pkt, false, dst, b.client)
	}
}

// rewriteClientAddr changes the client's address in pkt from one value to another: the source
// on uplink, the destination on downlink. A quoted packet inside an ICMP error travelled the
// other way, so the opposite field is changed there.
func rewriteClientAddr(pkt []byte, uplink bool, from, to netip.Addr) {
	l4, proto, ok := setPacketAddr(pkt, uplink, to)
	if !ok {
		return
	}
	v6 := pkt[0]>>4 == 6
	if inner, isErr := icmpErrorQuote(pkt, v6, l4, proto); isErr {
		if len(inner) > 0 && inner[0]>>4 == pkt[0]>>4 && quotedAddrIs(inner, !uplink, from) {
			setPacketAddr(inner, !uplink, to)
			setICMPChecksum(pkt, v6, l4)
		}
	}
}

// setPacketAddr writes addr into the source or destination field and patches the checksums that
// cover it. It returns the L4 offset and protocol, ok is false if pkt is too short to hold the
// address. L4 data that is not there is skipped: fragments and truncated ICMP quotes are normal.
func setPacketAddr(pkt []byte, isSrc bool, addr netip.Addr) (l4 int, proto byte, ok bool) {
	var oldSum, newSum uint32
	switch {
	case len(pkt) >= 20 && pkt[0]>>4 == 4 && addr.Is4():
		off := 16
		if isSrc {
			off = 12
		}
		next := addr.As4()
		oldSum, newSum = onesSum(pkt[off:off+4]), onesSum(next[:])
		copy(pkt[off:off+4], next[:])
		adjustChecksum(pkt[10:12], oldSum, newSum)
		ihl := int(pkt[0]&0x0f) * 4
		proto = pkt[9]
		// Only the first fragment carries an L4 header.
		if ihl < 20 || binary.BigEndian.Uint16(pkt[6:8])&0x1fff != 0 {
			return 0, proto, true
		}
		l4 = ihl
	case len(pkt) >= 40 && pkt[0]>>4 == 6 && addr.Is6():
		off := 24
		if isSrc {
			off = 8
		}
		next := addr.As16()
		oldSum, newSum = onesSum(pkt[off:off+16]), onesSum(next[:])
		copy(pkt[off:off+16], next[:])
		l4, proto = locateIPv6Payload(pkt)
		if l4 == 0 {
			return 0, proto, true
		}
	default:
		return 0, 0, false
	}

	switch proto {
	case 6: // TCP
		if len(pkt) >= l4+18 {
			adjustChecksum(pkt[l4+16:l4+18], oldSum, newSum)
		}
	case 17: // UDP
		// Zero means "no checksum" on IPv4 and must stay zero; a computed zero is sent as 0xffff.
		if len(pkt) >= l4+8 && (pkt[l4+6] != 0 || pkt[l4+7] != 0) {
			adjustChecksum(pkt[l4+6:l4+8], oldSum, newSum)
			if pkt[l4+6] == 0 && pkt[l4+7] == 0 {
				pkt[l4+6], pkt[l4+7] = 0xff, 0xff
			}
		}
	case 58: // ICMPv6 has a pseudo-header, ICMPv4 does not
		if len(pkt) >= l4+4 {
			adjustChecksum(pkt[l4+2:l4+4], oldSum, newSum)
		}
	}
	return l4, proto, true
}

// adjustChecksum applies an address change to a checksum field, per RFC 1624:
// HC' = ~(~HC + ~m + m').
func adjustChecksum(field []byte, oldSum, newSum uint32) {
	hc := binary.BigEndian.Uint16(field)
	m, mNew := foldSum(oldSum), foldSum(newSum)
	binary.BigEndian.PutUint16(field, ^foldSum(uint32(^hc)+uint32(^m)+uint32(mNew)))
}

// locateIPv6Payload walks the IPv6 extension headers. It returns the L4 offset and protocol, or
// offset 0 for a non-first fragment or when the headers do not fit in the packet.
func locateIPv6Payload(pkt []byte) (int, byte) {
	off, next := 40, pkt[6]
	for {
		switch next {
		case 0, 43, 60: // hop-by-hop, routing, destination options
			if len(pkt) < off+2 {
				return 0, next
			}
			next, off = pkt[off], off+(int(pkt[off+1])+1)*8
		case 44: // fragment
			if len(pkt) < off+8 {
				return 0, next
			}
			if binary.BigEndian.Uint16(pkt[off+2:off+4])&0xfff8 != 0 {
				return 0, pkt[off]
			}
			next, off = pkt[off], off+8
		default:
			return off, next
		}
	}
}

// icmpErrorQuote returns the quoted packet of an ICMP error message.
func icmpErrorQuote(pkt []byte, v6 bool, l4 int, proto byte) ([]byte, bool) {
	if l4 == 0 || len(pkt) < l4+8 {
		return nil, false
	}
	t := pkt[l4]
	switch {
	case !v6 && proto == 1 && (t == 3 || t == 4 || t == 5 || t == 11 || t == 12):
	case v6 && proto == 58 && t >= 1 && t <= 4:
	default:
		return nil, false
	}
	return pkt[l4+8:], true
}

func quotedAddrIs(inner []byte, isSrc bool, addr netip.Addr) bool {
	src, dst, ok := packetEndpoints(inner)
	if !ok {
		return false
	}
	if isSrc {
		return src == addr
	}
	return dst == addr
}

// setICMPChecksum recomputes an ICMP checksum after the quoted packet changed.
func setICMPChecksum(pkt []byte, v6 bool, l4 int) {
	end := len(pkt)
	var pseudo uint32
	if v6 {
		end = min(end, 40+int(binary.BigEndian.Uint16(pkt[4:6])))
		pseudo = onesSum(pkt[8:40]) + 58 + uint32(end-l4)
	} else {
		end = min(end, int(binary.BigEndian.Uint16(pkt[2:4])))
	}
	if end < l4+4 {
		return
	}
	body := pkt[l4:end]
	body[2], body[3] = 0, 0
	binary.BigEndian.PutUint16(body[2:4], ^foldSum(pseudo+onesSum(body)))
}
