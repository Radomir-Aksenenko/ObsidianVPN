package main

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"testing"
	"time"
)

var (
	testRemote4 = netip.MustParseAddr("93.184.216.34")
	testRemote6 = netip.MustParseAddr("2001:db8::99")
	phoneIP4    = netip.MustParseAddr("10.8.0.2")
	phoneIP6    = netip.MustParseAddr("fd00:8::2")
)

func buildIPv4(proto byte, src, dst netip.Addr, l4 []byte) []byte {
	pkt := make([]byte, 20+len(l4))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = proto
	s, d := src.As4(), dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	copy(pkt[20:], l4)
	setIPv4Checksum(pkt[:20])
	finishL4Checksum(pkt)
	return pkt
}

func buildIPv6(proto byte, src, dst netip.Addr, l4 []byte) []byte {
	pkt := make([]byte, 40+len(l4))
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(l4)))
	pkt[6] = proto
	pkt[7] = 64
	s, d := src.As16(), dst.As16()
	copy(pkt[8:24], s[:])
	copy(pkt[24:40], d[:])
	copy(pkt[40:], l4)
	finishL4Checksum(pkt)
	return pkt
}

func l4Checksum(pkt []byte) (off int, sum uint16, proto byte) {
	var pseudo uint32
	var l4 []byte
	if pkt[0]>>4 == 4 {
		proto = pkt[9]
		l4 = pkt[20:]
		pseudo = onesSum(pkt[12:20])
	} else {
		proto = pkt[6]
		l4 = pkt[40:]
		pseudo = onesSum(pkt[8:40])
	}
	switch proto {
	case 6:
		off = 16
	case 17:
		off = 6
	case 1:
		off = 2
		pseudo = 0
	case 58:
		off = 2
	default:
		return -1, 0, proto
	}
	if proto != 1 {
		pseudo += uint32(proto) + uint32(len(l4))
	}
	return off, foldSum(pseudo + onesSum(l4)), proto
}

// finishL4Checksum fills in a correct L4 checksum for a freshly built test packet.
func finishL4Checksum(pkt []byte) {
	off, _, _ := l4Checksum(pkt)
	if off < 0 {
		return
	}
	l4 := pkt[20:]
	if pkt[0]>>4 == 6 {
		l4 = pkt[40:]
	}
	l4[off], l4[off+1] = 0, 0
	_, sum, _ := l4Checksum(pkt)
	binary.BigEndian.PutUint16(l4[off:], ^sum)
}

// assertChecksums recomputes every checksum from scratch, so that a wrong incremental update fails.
func assertChecksums(t *testing.T, pkt []byte) {
	t.Helper()
	if pkt[0]>>4 == 4 {
		if got := foldSum(onesSum(pkt[:20])); got != 0xffff {
			t.Fatalf("bad IPv4 header checksum: sum=%#x", got)
		}
	}
	if _, sum, proto := l4Checksum(pkt); sum != 0xffff {
		t.Fatalf("bad checksum for protocol %d: sum=%#x", proto, sum)
	}
}

func tcpSegment(payload string) []byte {
	seg := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(seg[0:2], 40000)
	binary.BigEndian.PutUint16(seg[2:4], 443)
	seg[12] = 5 << 4
	seg[13] = tcpPSH
	copy(seg[20:], payload)
	return seg
}

func udpDatagram(payload string) []byte {
	seg := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(seg[0:2], 40000)
	binary.BigEndian.PutUint16(seg[2:4], 53)
	binary.BigEndian.PutUint16(seg[4:6], uint16(len(seg)))
	copy(seg[8:], payload)
	return seg
}

type fakeTUN struct {
	mu      sync.Mutex
	written [][]byte
}

func (f *fakeTUN) Read([]byte) (int, error) { select {} }

func (f *fakeTUN) Write(p []byte) (int, error) {
	f.mu.Lock()
	f.written = append(f.written, append([]byte(nil), p...))
	f.mu.Unlock()
	return len(p), nil
}

func (f *fakeTUN) last(t *testing.T) []byte {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.written) == 0 {
		t.Fatal("nothing reached the server TUN")
	}
	return f.written[len(f.written)-1]
}

func newPhone(r *tunRouter, name string) *routedSession {
	return r.registerSession(name, func([]byte) error { return nil })
}

func phoneKey(b byte) [32]byte {
	var k [32]byte
	k[0] = b
	return k
}

func uplink(t *testing.T, s *routedSession, src netip.Addr) netip.Addr {
	t.Helper()
	pkt := buildIPv4(6, src, testRemote4, tcpSegment("hello"))
	if err := s.writeToTUN(pkt); err != nil {
		t.Fatal(err)
	}
	gotSrc, _, _ := packetEndpoints(s.router.tun.(*fakeTUN).last(t))
	return gotSrc
}

// Three phones report the same tunnel address (iOS and Android hardcode 10.8.0.2). Each must
// get its own server-side address and stay on it, otherwise downlink packets reach the wrong phone.
func TestPhonesWithSameAddressGetSeparateServerAddresses(t *testing.T) {
	tun := &fakeTUN{}
	r := newTunRouter(tun)
	seen := map[netip.Addr]*routedSession{}
	var phones []*routedSession
	for i := 0; i < 3; i++ {
		p := newPhone(r, "phone")
		defer p.Close()
		p.setIdentity(phoneKey(byte(i + 1)))
		phones = append(phones, p)
	}
	for round := 0; round < 3; round++ {
		for _, p := range phones {
			v := uplink(t, p, phoneIP4)
			if owner, dup := seen[v]; dup && owner != p {
				t.Fatalf("address %s is shared by two phones", v)
			}
			seen[v] = p
		}
	}
	if len(seen) != 3 {
		t.Fatalf("expected 3 server-side addresses, got %d", len(seen))
	}
	for v, p := range seen {
		pkt := buildIPv4(6, testRemote4, v, tcpSegment("reply"))
		if got := r.sessionForPacket(pkt); got != p {
			t.Fatalf("downlink for %s went to the wrong phone", v)
		}
		p.restoreDownlink(pkt)
		if _, dst, _ := packetEndpoints(pkt); dst != phoneIP4 {
			t.Fatalf("downlink destination = %s, want %s", dst, phoneIP4)
		}
		assertChecksums(t, pkt)
	}
}

// A single client must see no translation at all: that is the path everyone used before.
func TestFirstClientKeepsItsAddress(t *testing.T) {
	r := newTunRouter(&fakeTUN{})
	p := newPhone(r, "one")
	defer p.Close()
	if v := uplink(t, p, phoneIP4); v != phoneIP4 {
		t.Fatalf("single client was translated to %s", v)
	}
}

func TestTranslationKeepsChecksumsValid(t *testing.T) {
	cases := []struct {
		name string
		pkt  func(src netip.Addr) []byte
		src  netip.Addr
	}{
		{"ipv4 tcp", func(s netip.Addr) []byte { return buildIPv4(6, s, testRemote4, tcpSegment("odd")) }, phoneIP4},
		{"ipv4 udp", func(s netip.Addr) []byte { return buildIPv4(17, s, testRemote4, udpDatagram("data")) }, phoneIP4},
		{"ipv4 icmp", func(s netip.Addr) []byte { return buildIPv4(1, s, testRemote4, []byte{8, 0, 0, 0, 1, 2, 3, 4}) }, phoneIP4},
		{"ipv6 tcp", func(s netip.Addr) []byte { return buildIPv6(6, s, testRemote6, tcpSegment("odd")) }, phoneIP6},
		{"ipv6 udp", func(s netip.Addr) []byte { return buildIPv6(17, s, testRemote6, udpDatagram("data")) }, phoneIP6},
		{"ipv6 icmp", func(s netip.Addr) []byte { return buildIPv6(58, s, testRemote6, []byte{128, 0, 0, 0, 1, 2, 3, 4}) }, phoneIP6},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tun := &fakeTUN{}
			r := newTunRouter(tun)
			first, second := newPhone(r, "a"), newPhone(r, "b")
			defer first.Close()
			defer second.Close()
			_ = first.writeToTUN(tc.pkt(tc.src))
			if err := second.writeToTUN(tc.pkt(tc.src)); err != nil {
				t.Fatal(err)
			}
			out := tun.last(t)
			src, _, _ := packetEndpoints(out)
			if src == tc.src {
				t.Fatal("second client was not translated")
			}
			assertChecksums(t, out)

			// Swap the addresses to build the reply, then restore it the way the router does.
			reply := append([]byte(nil), out...)
			swapAddresses(reply)
			finishL4Checksum(reply)
			if reply[0]>>4 == 4 {
				setIPv4Checksum(reply[:20])
			}
			second.restoreDownlink(reply)
			if _, dst, _ := packetEndpoints(reply); dst != tc.src {
				t.Fatalf("reply destination = %s, want %s", dst, tc.src)
			}
			assertChecksums(t, reply)
		})
	}
}

func swapAddresses(pkt []byte) {
	off, n := 12, 4
	if pkt[0]>>4 == 6 {
		off, n = 8, 16
	}
	for i := 0; i < n; i++ {
		pkt[off+i], pkt[off+n+i] = pkt[off+n+i], pkt[off+i]
	}
}

// An ICMP error quotes the packet the client sent. The client only matches it to a connection
// (and adjusts its path MTU) if the quoted source is its own address.
func TestICMPErrorQuoteIsRestored(t *testing.T) {
	tun := &fakeTUN{}
	r := newTunRouter(tun)
	first, second := newPhone(r, "a"), newPhone(r, "b")
	defer first.Close()
	defer second.Close()
	uplink(t, first, phoneIP4)
	virtual := uplink(t, second, phoneIP4)

	quoted := buildIPv4(6, virtual, testRemote4, tcpSegment(""))[:28]
	body := append([]byte{3, 4, 0, 0, 0, 0, 5, 0}, quoted...)
	pkt := buildIPv4(1, testRemote4, virtual, body)
	second.restoreDownlink(pkt)

	if _, dst, _ := packetEndpoints(pkt); dst != phoneIP4 {
		t.Fatalf("outer destination = %s", dst)
	}
	assertChecksums(t, pkt)
	inner := pkt[28:]
	if src, _, _ := packetEndpoints(inner); src != phoneIP4 {
		t.Fatalf("quoted source = %s, want %s", src, phoneIP4)
	}
	if got := foldSum(onesSum(inner[:20])); got != 0xffff {
		t.Fatalf("bad quoted IPv4 checksum: %#x", got)
	}
}

// A client cannot take traffic meant for another one by sending from its address.
func TestClientCannotStealAnotherAddress(t *testing.T) {
	r := newTunRouter(&fakeTUN{})
	victim, attacker := newPhone(r, "victim"), newPhone(r, "attacker")
	defer victim.Close()
	defer attacker.Close()
	victim.setIdentity(phoneKey(1))
	attacker.setIdentity(phoneKey(2))

	uplink(t, victim, phoneIP4)
	if v := uplink(t, attacker, phoneIP4); v == phoneIP4 {
		t.Fatal("attacker got the victim's address")
	}
	reply := buildIPv4(6, testRemote4, phoneIP4, tcpSegment("secret"))
	if r.sessionForPacket(reply) != victim {
		t.Fatal("reply no longer goes to the victim")
	}
	if v := uplink(t, victim, phoneIP4); v != phoneIP4 {
		t.Fatalf("victim moved to %s", v)
	}
}

// Wi-Fi to LTE: the same device reconnects while its old session is still alive. It must keep
// the address, otherwise server NAT sees a new source and every open connection dies.
func TestReconnectKeepsAddressWhileOldSessionAlive(t *testing.T) {
	r := newTunRouter(&fakeTUN{})
	first := newPhone(r, "other")
	defer first.Close()
	first.setIdentity(phoneKey(1))
	uplink(t, first, phoneIP4)

	old := newPhone(r, "old")
	defer old.Close()
	old.setIdentity(phoneKey(2))
	want := uplink(t, old, phoneIP4)

	fresh := newPhone(r, "new")
	defer fresh.Close()
	fresh.setIdentity(phoneKey(2))
	if got := uplink(t, fresh, phoneIP4); got != want {
		t.Fatalf("reconnected device moved from %s to %s", want, got)
	}
	reply := buildIPv4(6, testRemote4, want, tcpSegment("x"))
	if r.sessionForPacket(reply) != fresh {
		t.Fatal("downlink still goes to the dead session")
	}
	// A late packet from the old session must not take the address back.
	if got := uplink(t, old, phoneIP4); got == want {
		t.Fatal("old session took the address back")
	}
	if r.sessionForPacket(reply) != fresh {
		t.Fatal("downlink flipped back to the old session")
	}
}

func TestReconnectKeepsAddressAfterOldSessionClosed(t *testing.T) {
	r := newTunRouter(&fakeTUN{})
	first := newPhone(r, "other")
	defer first.Close()
	first.setIdentity(phoneKey(1))
	uplink(t, first, phoneIP4)

	old := newPhone(r, "old")
	old.setIdentity(phoneKey(2))
	want := uplink(t, old, phoneIP4)
	old.Close()

	// Another device connecting during the gap must not get the address.
	stranger := newPhone(r, "stranger")
	defer stranger.Close()
	stranger.setIdentity(phoneKey(3))
	if got := uplink(t, stranger, phoneIP4); got == want {
		t.Fatal("reserved address was handed to another device")
	}

	fresh := newPhone(r, "new")
	defer fresh.Close()
	fresh.setIdentity(phoneKey(2))
	if got := uplink(t, fresh, phoneIP4); got != want {
		t.Fatalf("reconnected device moved from %s to %s", want, got)
	}
}

func TestReservedAddressIsReusedAfterExpiry(t *testing.T) {
	r := newTunRouter(&fakeTUN{})
	old := newPhone(r, "old")
	old.setIdentity(phoneKey(1))
	uplink(t, old, phoneIP4)
	old.Close()

	r.mu.Lock()
	entry := r.reserved[phoneIP4]
	entry.until = time.Now().Add(-time.Second)
	r.reserved[phoneIP4] = entry
	r.mu.Unlock()

	next := newPhone(r, "next")
	defer next.Close()
	next.setIdentity(phoneKey(2))
	if got := uplink(t, next, phoneIP4); got != phoneIP4 {
		t.Fatalf("expired reservation still blocks the address: got %s", got)
	}
}

func TestPoolExhaustionDropsInsteadOfSharing(t *testing.T) {
	tun := &fakeTUN{}
	r := newTunRouter(tun)
	r.configureAddressing("10.9.0.1/30") // one usable client address
	a, b := newPhone(r, "a"), newPhone(r, "b")
	defer a.Close()
	defer b.Close()
	if v := uplink(t, a, phoneIP4); v != netip.MustParseAddr("10.9.0.2") {
		t.Fatalf("client outside the pool got %s", v)
	}
	before := len(tun.written)
	if err := b.writeToTUN(buildIPv4(6, phoneIP4, testRemote4, tcpSegment("x"))); err != nil {
		t.Fatal(err)
	}
	if len(tun.written) != before {
		t.Fatal("packet without an address reached the TUN")
	}
}

func TestLinkLocalSourceIsNotBound(t *testing.T) {
	tun := &fakeTUN{}
	r := newTunRouter(tun)
	p := newPhone(r, "win")
	defer p.Close()
	ll := netip.MustParseAddr("169.254.10.10")
	if v := uplink(t, p, ll); v != ll {
		t.Fatalf("link-local source rewritten to %s", v)
	}
	if v := uplink(t, p, phoneIP4); v != phoneIP4 {
		t.Fatalf("real source got %s", v)
	}
}

func TestCloseReleasesAddresses(t *testing.T) {
	r := newTunRouter(&fakeTUN{})
	p := newPhone(r, "anon") // no identity, so nothing is reserved
	uplink(t, p, phoneIP4)
	p.Close()
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.byIP) != 0 || len(r.reserved) != 0 {
		t.Fatalf("leftovers: byIP=%d reserved=%d", len(r.byIP), len(r.reserved))
	}
}

func TestConcurrentClientsKeepTheirOwnTraffic(t *testing.T) {
	r := newTunRouter(&fakeTUN{})
	const n = 8
	var wg sync.WaitGroup
	addrs := make([]netip.Addr, n)
	for i := 0; i < n; i++ {
		s := newPhone(r, "c")
		defer s.Close()
		s.setIdentity(phoneKey(byte(i + 1)))
		wg.Add(1)
		go func(i int, s *routedSession) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				pkt := buildIPv4(17, phoneIP4, testRemote4, udpDatagram("data"))
				if err := s.writeToTUN(pkt); err != nil {
					t.Error(err)
					return
				}
				src, _, _ := packetEndpoints(pkt)
				if j > 0 && src != addrs[i] {
					t.Errorf("client %d moved from %s to %s", i, addrs[i], src)
					return
				}
				addrs[i] = src
				reply := buildIPv4(17, testRemote4, src, udpDatagram("data"))
				s.restoreDownlink(reply)
				_, dst, _ := packetEndpoints(reply)
				if dst != phoneIP4 {
					t.Errorf("reply destination = %s", dst)
					return
				}
			}
		}(i, s)
	}
	wg.Wait()
	seen := map[netip.Addr]bool{}
	for _, a := range addrs {
		if seen[a] {
			t.Fatalf("address %s is shared", a)
		}
		seen[a] = true
	}
}

func BenchmarkUplinkFirstClient(b *testing.B) {
	r := newTunRouter(&fakeTUN{})
	p := newPhone(r, "p")
	defer p.Close()
	pkt := buildIPv4(6, phoneIP4, testRemote4, tcpSegment("payload"))
	b.ReportAllocs()
	for b.Loop() {
		p.translateUplink(pkt)
	}
}

func BenchmarkTranslatedRoundTrip(b *testing.B) {
	r := newTunRouter(&fakeTUN{})
	first, p := newPhone(r, "a"), newPhone(r, "b")
	defer first.Close()
	defer p.Close()
	first.translateUplink(buildIPv4(6, phoneIP4, testRemote4, tcpSegment("x")))
	pkt := make([]byte, 1280)
	copy(pkt, buildIPv4(6, phoneIP4, testRemote4, make([]byte, 1260)))
	b.SetBytes(1280)
	b.ReportAllocs()
	p.translateUplink(pkt)
	v, _, _ := packetEndpoints(pkt)
	swapAddresses(pkt)
	for b.Loop() {
		p.restoreDownlink(pkt)
		swapAddresses(pkt)
		p.translateUplink(pkt)
		swapAddresses(pkt)
	}
	_ = v
}

// Two devices can share one key. The second takes the address once, as a reconnecting device
// would, and after that their packets alternate without either address moving again.
func TestLiveSessionsWithSameKeySettleOnSeparateAddresses(t *testing.T) {
	r := newTunRouter(&fakeTUN{})
	a := newPhone(r, "a")
	defer a.Close()
	b := newPhone(r, "b")
	defer b.Close()
	a.setIdentity(phoneKey(1))
	b.setIdentity(phoneKey(1))

	uplink(t, a, phoneIP4)
	addrB := uplink(t, b, phoneIP4)
	addrA := uplink(t, a, phoneIP4)
	if addrA == addrB {
		t.Fatalf("both sessions share %s", addrA)
	}
	for i := 0; i < 6; i++ {
		if got := uplink(t, a, phoneIP4); got != addrA {
			t.Fatalf("first session moved from %s to %s", addrA, got)
		}
		if got := uplink(t, b, phoneIP4); got != addrB {
			t.Fatalf("second session moved from %s to %s", addrB, got)
		}
	}
	if r.sessionForPacket(buildIPv4(6, testRemote4, addrA, tcpSegment("x"))) != a {
		t.Fatal("downlink for the first session went elsewhere")
	}
	if r.sessionForPacket(buildIPv4(6, testRemote4, addrB, tcpSegment("x"))) != b {
		t.Fatal("downlink for the second session went elsewhere")
	}
}
