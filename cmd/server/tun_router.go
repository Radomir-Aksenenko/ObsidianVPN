package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// routedSessionQueueSize bounds downlink packets queued per client. It only has to absorb
// bursts (many parallel flows, e.g. Telegram media) and bound memory; latency is bounded
// by routedMaxSojourn below. The previous 8192 entries (~10 MB) let a slow client build
// seconds of queueing delay before any loss, which inflated inner TCP/QUIC RTTs.
const routedSessionQueueSize = 1024

// routedMaxSojourn is the longest a downlink packet may wait in the per-session queue.
// Older packets are dropped at dequeue time (CoDel-style): a standing queue is shed
// quickly and the inner flows get a loss signal instead of seconds of bufferbloat.
const routedMaxSojourn = 100 * time.Millisecond

// routedPrioQueueSize bounds latency-sensitive packets queued per client (see isLatencySensitive).
// When it is full such packets fall back to the bulk queue instead of being dropped.
const routedPrioQueueSize = 256

// routedPrioBurst is how many latency-sensitive packets may go out in a row before a waiting
// bulk packet gets a turn. Without it, a constant game or voice stream would starve bulk.
const routedPrioBurst = 64

type routedPacket struct {
	buf []byte
	at  time.Time
}

var routedPacketPool = sync.Pool{
	New: func() any {
		return make([]byte, 2048)
	},
}

type tunRouter struct {
	tun io.ReadWriter

	mu       sync.RWMutex
	sessions map[*routedSession]struct{}
	byIP     map[netip.Addr]*routedSession

	writeMu sync.Mutex

	// tunnelMTU is the packet size that fits the encrypted transport.
	tunnelMTU int
	// normalizeMSS enables MSS rewriting and downlink splitting (see mss.go).
	normalizeMSS bool
}

type routedSession struct {
	router *tunRouter
	sid    string
	send   func([]byte) error

	// mtu is the largest downlink packet this client accepts.
	mtu  atomic.Int32
	ips  map[netip.Addr]struct{}
	out  chan routedPacket
	prio chan routedPacket
	// prioRun counts latency-sensitive sends since the last bulk send. writeLoop only.
	prioRun int
	done    chan struct{}
	once    sync.Once
}

func newTunRouter(tun io.ReadWriter) *tunRouter {
	return &tunRouter{
		tun:          tun,
		sessions:     make(map[*routedSession]struct{}),
		byIP:         make(map[netip.Addr]*routedSession),
		tunnelMTU:    maxTunnelMTU,
		normalizeMSS: true,
	}
}

// configureMSS sets the transport MTU and the MSS normalization mode. Call it before run
// and before sessions are registered.
func (r *tunRouter) configureMSS(tunnelMTU int, normalize bool) {
	r.tunnelMTU = tunnelMTU
	r.normalizeMSS = normalize
}

func (r *tunRouter) run() {
	buf := make([]byte, 65535)
	for {
		n, err := r.tun.Read(buf)
		if err != nil {
			log.Printf("TUN router read error: %v", err)
			return
		}
		packet := buf[:n]
		sess := r.sessionForPacket(packet)
		if sess == nil {
			continue
		}
		if r.normalizeMSS {
			limit := int(sess.mtu.Load())
			clampDownlinkSYN(packet, limit)
			if n > limit {
				sendOversized(sess, packet, limit)
				continue
			}
		}

		copyPacket := getRoutedPacket(n)
		copy(copyPacket, packet)
		if !sess.enqueue(copyPacket) {
			if dropLog.Ready() {
				log.Printf("session %s: outbound queue full, dropping packet len=%d", sess.sid, len(copyPacket))
			}
			putRoutedPacket(copyPacket)
		}
	}
}

// sendOversized queues a downlink packet larger than limit as several packets that fit it.
func sendOversized(sess *routedSession, packet []byte, limit int) {
	emit := func(p []byte) {
		cp := getRoutedPacket(len(p))
		copy(cp, p)
		if !sess.enqueue(cp) {
			if dropLog.Ready() {
				log.Printf("session %s: outbound queue full, dropping packet len=%d", sess.sid, len(cp))
			}
			putRoutedPacket(cp)
		}
	}
	if splitTCP(packet, limit, emit) || fragmentIPv4(packet, limit, emit) {
		return
	}
	if dropLog.Ready() {
		log.Printf("session %s: dropping oversized packet limit=%d: %s", sess.sid, limit, packetSummary(packet))
	}
}

func getRoutedPacket(size int) []byte {
	if size <= 2048 {
		b := routedPacketPool.Get().([]byte)
		return b[:size]
	}
	return make([]byte, size)
}

func putRoutedPacket(packet []byte) {
	if cap(packet) == 2048 {
		routedPacketPool.Put(packet[:2048])
	}
}

func (r *tunRouter) registerSession(sid string, send func([]byte) error) *routedSession {
	s := &routedSession{
		router: r,
		sid:    sid,
		send:   send,
		ips:    make(map[netip.Addr]struct{}),
		out:    make(chan routedPacket, routedSessionQueueSize),
		prio:   make(chan routedPacket, routedPrioQueueSize),
		done:   make(chan struct{}),
	}
	s.mtu.Store(int32(r.tunnelMTU))
	r.mu.Lock()
	r.sessions[s] = struct{}{}
	r.mu.Unlock()
	go s.writeLoop()
	return s
}

func (r *tunRouter) writePacket(packet []byte) error {
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	_, err := r.tun.Write(packet)
	return err
}

func (r *tunRouter) sessionForPacket(packet []byte) *routedSession {
	_, dst, ok := packetEndpoints(packet)
	if !ok {
		return r.singleSession()
	}

	r.mu.RLock()
	sess := r.byIP[dst]
	r.mu.RUnlock()
	if sess != nil {
		return sess
	}

	return r.singleSession()
}

func (r *tunRouter) singleSession() *routedSession {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.sessions) != 1 {
		return nil
	}
	for sess := range r.sessions {
		return sess
	}
	return nil
}

func (s *routedSession) learnFromClientPacket(packet []byte) {
	src, _, ok := packetEndpoints(packet)
	if !ok || !src.IsValid() || src.IsUnspecified() || src.IsMulticast() {
		return
	}

	s.router.mu.Lock()
	defer s.router.mu.Unlock()

	if _, active := s.router.sessions[s]; !active {
		return
	}

	if _, exists := s.ips[src]; exists {
		return
	}

	if prev := s.router.byIP[src]; prev != nil && prev != s {
		delete(prev.ips, src)
	}
	s.ips[src] = struct{}{}
	s.router.byIP[src] = s

	log.Printf("session %s: learned client IP %s", s.sid, src)
}

func (s *routedSession) writeToTUN(packet []byte) error {
	s.learnFromClientPacket(packet)
	if s.router.normalizeMSS {
		if clientMTU := normalizeUplinkSYN(packet); clientMTU > 0 {
			s.mtu.Store(int32(min(max(clientMTU, minClientMTU), s.router.tunnelMTU)))
		}
	}
	return s.router.writePacket(packet)
}

func (s *routedSession) Write(packet []byte) (int, error) {
	if err := s.writeToTUN(packet); err != nil {
		return 0, err
	}
	return len(packet), nil
}

// isLatencySensitive reports whether pkt is interactive traffic that should not queue behind
// bulk downlink data: ICMP, small UDP (game and voice frames) and TCP segments without payload
// (ACK, SYN, FIN, RST). Only fixed header fields are read; malformed packets report false.
func isLatencySensitive(pkt []byte) bool {
	var proto byte
	var ipHdr, ipLen int
	switch {
	case len(pkt) >= 20 && pkt[0]>>4 == 4:
		ipHdr = int(pkt[0]&0x0f) * 4
		ipLen = int(binary.BigEndian.Uint16(pkt[2:4]))
		proto = pkt[9]
	case len(pkt) >= 40 && pkt[0]>>4 == 6:
		ipHdr = 40
		ipLen = ipHdr + int(binary.BigEndian.Uint16(pkt[4:6]))
		proto = pkt[6]
	default:
		return false
	}
	if ipHdr < 20 || ipLen < ipHdr || ipLen > len(pkt) {
		return false
	}
	switch proto {
	case 1, 58: // ICMP, ICMPv6
		return true
	case 17: // UDP
		return len(pkt) <= 600
	case 6: // TCP
		l4 := pkt[ipHdr:ipLen]
		if len(l4) < 20 {
			return false
		}
		tcpHdr := int(l4[12]>>4) * 4
		if tcpHdr < 20 || tcpHdr > len(l4) {
			return false
		}
		payload := len(l4) - tcpHdr
		return payload == 0
	}
	return false
}

func (s *routedSession) enqueue(packet []byte) bool {
	p := routedPacket{buf: packet, at: time.Now()}
	if isLatencySensitive(packet) {
		select {
		case s.prio <- p:
			return true
		default:
			// Lane full: use the bulk queue rather than dropping the packet.
		}
	}
	select {
	case s.out <- p:
		return true
	case <-s.done:
		return false
	default:
		return false
	}
}

func (s *routedSession) writeLoop() {
	var batch [32]routedPacket
	for {
		// Bulk turn: after routedPrioBurst latency-sensitive sends in a row, a waiting bulk
		// packet goes out even if more of them are queued.
		if s.prioRun >= routedPrioBurst {
			select {
			case p := <-s.out:
				s.sendBulk(p, batch[:])
				continue
			default:
			}
		}
		select {
		case p := <-s.prio:
			s.prioRun++
			s.sendOne(p, time.Now())
		case p := <-s.out:
			s.sendBulk(p, batch[:])
		case <-s.done:
			s.drain()
			return
		}
	}
}

// sendBulk sends first and the bulk packets already queued behind it (up to len(batch)).
// Waiting latency-sensitive packets go out before each one, so a full batch cannot hold them up.
func (s *routedSession) sendBulk(first routedPacket, batch []routedPacket) {
	batch[0] = first
	n := 1 + takeQueued(s.out, batch[1:])
	for i := 0; i < n; i++ {
		s.sendPrioWaiting()
		p := batch[i]
		batch[i] = routedPacket{}
		s.prioRun = 0
		s.sendOne(p, time.Now())
	}
}

// sendPrioWaiting sends the latency-sensitive packets already queued, stopping after
// routedPrioBurst in a row so that bulk is not starved.
func (s *routedSession) sendPrioWaiting() {
	for s.prioRun < routedPrioBurst {
		select {
		case p := <-s.prio:
			s.prioRun++
			s.sendOne(p, time.Now())
		default:
			return
		}
	}
}

// sendOne sends a queued packet unless it has gone stale, then returns its buffer to the pool.
func (s *routedSession) sendOne(p routedPacket, now time.Time) {
	if now.Sub(p.at) > routedMaxSojourn {
		if dropLog.Ready() {
			log.Printf("session %s: dropping stale downlink packet (queued %v)", s.sid, now.Sub(p.at).Round(time.Millisecond))
		}
		putRoutedPacket(p.buf)
		return
	}
	if err := s.send(p.buf); err != nil && dropLog.Ready() {
		log.Printf("session %s: send to client dropped packet len=%d: %v", s.sid, len(p.buf), err)
	}
	putRoutedPacket(p.buf)
}

// takeQueued moves up to len(dst) packets that are already waiting in q into dst.
func takeQueued(q chan routedPacket, dst []routedPacket) int {
	for n := range dst {
		select {
		case dst[n] = <-q:
		default:
			return n
		}
	}
	return len(dst)
}

func (s *routedSession) drain() {
	drainQueue(s.prio)
	drainQueue(s.out)
}

func drainQueue(q chan routedPacket) {
	for {
		select {
		case p := <-q:
			putRoutedPacket(p.buf)
		default:
			return
		}
	}
}

func (s *routedSession) Close() {
	s.once.Do(func() {
		close(s.done)

		s.router.mu.Lock()
		delete(s.router.sessions, s)
		for ip := range s.ips {
			if s.router.byIP[ip] == s {
				delete(s.router.byIP, ip)
			}
		}
		s.router.mu.Unlock()
	})
}

func packetSummary(packet []byte) string {
	if len(packet) == 0 {
		return "empty"
	}
	src, dst, ok := packetEndpoints(packet)
	if !ok {
		return fmt.Sprintf("unknown len=%d first=0x%02x", len(packet), packet[0])
	}
	version := packet[0] >> 4
	proto := "?"
	sport := 0
	dport := 0
	flags := ""
	if version == 4 && len(packet) >= 20 {
		ihl := int(packet[0]&0x0f) * 4
		if ihl >= 20 && len(packet) >= ihl {
			switch packet[9] {
			case 1:
				proto = "icmp"
			case 6:
				proto = "tcp"
				if len(packet) >= ihl+20 {
					sport = int(packet[ihl])<<8 | int(packet[ihl+1])
					dport = int(packet[ihl+2])<<8 | int(packet[ihl+3])
					flags = tcpFlags(packet[ihl+13])
				}
			case 17:
				proto = "udp"
				if len(packet) >= ihl+8 {
					sport = int(packet[ihl])<<8 | int(packet[ihl+1])
					dport = int(packet[ihl+2])<<8 | int(packet[ihl+3])
					if sport == 53 || dport == 53 {
						proto = "dns/udp"
					}
				}
			default:
				proto = fmt.Sprintf("ipproto/%d", packet[9])
			}
		}
	}
	if sport != 0 || dport != 0 {
		if flags != "" {
			return fmt.Sprintf("%s %s:%d -> %s:%d %s len=%d", proto, src, sport, dst, dport, flags, len(packet))
		}
		return fmt.Sprintf("%s %s:%d -> %s:%d len=%d", proto, src, sport, dst, dport, len(packet))
	}
	return fmt.Sprintf("%s %s -> %s len=%d", proto, src, dst, len(packet))
}

func tcpFlags(b byte) string {
	var parts []string
	if b&0x02 != 0 {
		parts = append(parts, "SYN")
	}
	if b&0x10 != 0 {
		parts = append(parts, "ACK")
	}
	if b&0x01 != 0 {
		parts = append(parts, "FIN")
	}
	if b&0x04 != 0 {
		parts = append(parts, "RST")
	}
	if b&0x08 != 0 {
		parts = append(parts, "PSH")
	}
	if len(parts) == 0 {
		return fmt.Sprintf("flags=0x%02x", b)
	}
	return strings.Join(parts, ",")
}

func packetEndpoints(packet []byte) (src, dst netip.Addr, ok bool) {
	if len(packet) == 0 {
		return netip.Addr{}, netip.Addr{}, false
	}

	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return netip.Addr{}, netip.Addr{}, false
		}
		src = netip.AddrFrom4([4]byte{packet[12], packet[13], packet[14], packet[15]})
		dst = netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]})
		return src, dst, true
	case 6:
		if len(packet) < 40 {
			return netip.Addr{}, netip.Addr{}, false
		}
		srcBytes := [16]byte{}
		dstBytes := [16]byte{}
		copy(srcBytes[:], packet[8:24])
		copy(dstBytes[:], packet[24:40])
		src = netip.AddrFrom16(srcBytes)
		dst = netip.AddrFrom16(dstBytes)
		return src, dst, true
	default:
		return netip.Addr{}, netip.Addr{}, false
	}
}
