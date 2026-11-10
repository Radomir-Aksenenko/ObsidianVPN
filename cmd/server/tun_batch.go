package main

import (
	"errors"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"obsidian/obsidian"
)

// Batched TUN I/O. On Linux the server TUN is opened with IFF_VNET_HDR offloads when the kernel
// allows it (tun_offload_linux.go): one read then returns a GSO super-packet already split into
// up to 64 KiB worth of segments, and one write can carry several TCP segments of a flow merged
// by GRO. Per-packet read and write system calls were the largest CPU cost of the server.

// tunBatchReader is a TUN device that can return several packets per read.
type tunBatchReader interface {
	BatchSize() int
	ReadBatch(bufs [][]byte, sizes []int) (int, error)
}

// tunBatchWriter is a TUN device that writes several packets in one call. Each buffer holds its
// packet from tunWriteHeadroom on; the headroom and the spare capacity let the device prepend its
// virtio header and merge segments of one flow in place.
type tunBatchWriter interface {
	WriteBatch(bufs [][]byte) (int, error)
}

const (
	tunWriteHeadroom = 16
	// tunWriteBufCap bounds how many segments GRO can merge into one write (about 11 at 1420).
	tunWriteBufCap = tunWriteHeadroom + 16<<10
	// tunWriteBatch is the most packets a relay goroutine hands to the TUN at once.
	tunWriteBatch = 32
)

var tunWriteBufPool = sync.Pool{New: func() any {
	b := make([]byte, tunWriteBufCap)
	return &b
}}

func getTunWriteBuf() *[]byte {
	bp := tunWriteBufPool.Get().(*[]byte)
	*bp = (*bp)[:cap(*bp)]
	return bp
}

func putTunWriteBuf(bp *[]byte) { tunWriteBufPool.Put(bp) }

// tunBatchSink is a relay destination that accepts batches laid out for tunBatchWriter.
type tunBatchSink interface {
	WriteBatch(bufs [][]byte) error
}

// tunnelToTUNBatch relays client packets from a TCP tunnel to the TUN. It blocks for the first
// packet, then takes whatever else is already queued, up to tunWriteBatch, and writes them in one
// call. No timer: a lone packet goes out as soon as it arrives.
func tunnelToTUNBatch(tunnel *obsidian.Tunnel, sink tunBatchSink, sid string, lastRecv *atomic.Int64) {
	held := make([]*[]byte, 0, tunWriteBatch)
	bufs := make([][]byte, 0, tunWriteBatch)
	defer func() {
		for _, bp := range held {
			putTunWriteBuf(bp)
		}
	}()
	for {
		bp := getTunWriteBuf()
		n, err := tunnel.RecvDataInto(nil, (*bp)[tunWriteHeadroom:])
		if err != nil {
			putTunWriteBuf(bp)
			log.Printf("session %s: tunnel recv error: %v", sid, err)
			return
		}
		if lastRecv != nil {
			lastRecv.Store(time.Now().UnixNano())
		}
		held, bufs = keepClientPacket(held, bufs, bp, n, sid)
		for len(held) < tunWriteBatch {
			bp = getTunWriteBuf()
			n, ok, err := tunnel.TryRecvDataInto((*bp)[tunWriteHeadroom:])
			if err != nil || !ok {
				putTunWriteBuf(bp)
				break
			}
			held, bufs = keepClientPacket(held, bufs, bp, n, sid)
		}
		flushClientBatch(sink, bufs, sid)
		for i, bp := range held {
			putTunWriteBuf(bp)
			held[i], bufs[i] = nil, nil
		}
		held, bufs = held[:0], bufs[:0]
	}
}

// udpClientToTUNBatch relays client packets from a UDP session; RecvBatch already returns the
// packets that arrived together.
func udpClientToTUNBatch(sess *obsidian.UDPSession, sink tunBatchSink, sid string, lastRecv *atomic.Int64) {
	batch := make([]obsidian.UDPPacket, tunWriteBatch)
	held := make([]*[]byte, 0, tunWriteBatch)
	bufs := make([][]byte, 0, tunWriteBatch)
	for {
		n, err := sess.RecvBatch(batch)
		if err != nil {
			log.Printf("session %s: udp recv done: %v", sid, err)
			return
		}
		if lastRecv != nil {
			lastRecv.Store(time.Now().UnixNano())
		}
		for i := 0; i < n; i++ {
			data := batch[i].Payload
			batch[i] = obsidian.UDPPacket{}
			if len(data) > 0 && len(data) <= tunWriteBufCap-tunWriteHeadroom {
				bp := getTunWriteBuf()
				copy((*bp)[tunWriteHeadroom:], data)
				held, bufs = keepClientPacket(held, bufs, bp, len(data), sid)
			}
			obsidian.PutPacket(data)
		}
		flushClientBatch(sink, bufs, sid)
		for i, bp := range held {
			putTunWriteBuf(bp)
			held[i], bufs[i] = nil, nil
		}
		held, bufs = held[:0], bufs[:0]
	}
}

// keepClientPacket adds the packet in bp to the batch unless it must not be forwarded.
func keepClientPacket(held []*[]byte, bufs [][]byte, bp *[]byte, n int, sid string) ([]*[]byte, [][]byte) {
	data := (*bp)[tunWriteHeadroom : tunWriteHeadroom+n]
	if n == 0 || shouldDropClientPacket(data) {
		if n > 0 && dropLog.Ready() {
			log.Printf("session %s: dropping non-forwardable client packet: %s", sid, packetSummary(data))
		}
		putTunWriteBuf(bp)
		return held, bufs
	}
	return append(held, bp), append(bufs, (*bp)[:tunWriteHeadroom+n])
}

func flushClientBatch(sink tunBatchSink, bufs [][]byte, sid string) {
	if len(bufs) == 0 {
		return
	}
	if err := sink.WriteBatch(bufs); err != nil && dropLog.Ready() {
		log.Printf("session %s: tun write dropped packets: %v", sid, err)
	}
}

// WriteBatch writes client packets laid out for tunBatchWriter (packet at tunWriteHeadroom).
func (s *routedSession) WriteBatch(bufs [][]byte) error {
	kept := bufs[:0]
	for _, b := range bufs {
		packet := b[tunWriteHeadroom:]
		if !s.translateUplink(packet) {
			continue
		}
		if s.router.normalizeMSS {
			if clientMTU := normalizeUplinkSYN(packet); clientMTU > 0 {
				s.learnClientMTU(clientMTU)
			}
		}
		kept = append(kept, b)
	}
	return s.router.writeBatch(kept)
}

// writeBatch hands packets to the TUN in one call when it supports batches.
func (r *tunRouter) writeBatch(bufs [][]byte) error {
	if len(bufs) == 0 {
		return nil
	}
	if bw, ok := r.tun.(tunBatchWriter); ok {
		r.writeMu.Lock()
		defer r.writeMu.Unlock()
		_, err := bw.WriteBatch(bufs)
		return err
	}
	var errs error
	for _, b := range bufs {
		if err := r.writePacket(b[tunWriteHeadroom:]); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	return errs
}

// WriteBatch is clientSink's batch path: IPv6 packets get the rate-limited reject, the rest go on.
func (c *clientSink) WriteBatch(bufs [][]byte) error {
	kept := bufs[:0]
	for _, b := range bufs {
		p := b[tunWriteHeadroom:]
		if p[0]>>4 == 6 {
			c.Write(p)
			continue
		}
		kept = append(kept, b)
	}
	return c.route.WriteBatch(kept)
}
