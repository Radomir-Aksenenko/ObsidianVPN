package main

import (
	"fmt"
	"io"
	"log"
	"net/netip"
	"strings"
	"sync"
)

const routedSessionQueueSize = 8192

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
}

type routedSession struct {
	router *tunRouter
	sid    string
	send   func([]byte) error

	ips  map[netip.Addr]struct{}
	out  chan []byte
	done chan struct{}
	once sync.Once
}

func newTunRouter(tun io.ReadWriter) *tunRouter {
	return &tunRouter{
		tun:      tun,
		sessions: make(map[*routedSession]struct{}),
		byIP:     make(map[netip.Addr]*routedSession),
	}
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

		copyPacket := getRoutedPacket(n)
		copy(copyPacket, packet)
		if !sess.enqueue(copyPacket) {
			log.Printf("session %s: outbound queue full, dropping packet len=%d", sess.sid, len(copyPacket))
			putRoutedPacket(copyPacket)
		}
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
		out:    make(chan []byte, routedSessionQueueSize),
		done:   make(chan struct{}),
	}
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
	return s.router.writePacket(packet)
}

func (s *routedSession) Write(packet []byte) (int, error) {
	if err := s.writeToTUN(packet); err != nil {
		return 0, err
	}
	return len(packet), nil
}

func (s *routedSession) enqueue(packet []byte) bool {
	select {
	case s.out <- packet:
		return true
	case <-s.done:
		return false
	default:
		return false
	}
}

func (s *routedSession) writeLoop() {
	var batch [32][]byte
	for {
		select {
		case packet := <-s.out:
			batch[0] = packet
			n := 1
			for n < len(batch) {
				select {
				case p := <-s.out:
					batch[n] = p
					n++
				default:
					goto sendBatch
				}
			}
		sendBatch:
			for i := 0; i < n; i++ {
				p := batch[i]
				batch[i] = nil
				if err := s.send(p); err != nil {
					putRoutedPacket(p)
					log.Printf("session %s: send to client dropped packet len=%d: %v", s.sid, len(p), err)
					continue
				}
				putRoutedPacket(p)
			}
		case <-s.done:
			s.drain()
			return
		}
	}
}

func (s *routedSession) drain() {
	for {
		select {
		case packet := <-s.out:
			putRoutedPacket(packet)
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
