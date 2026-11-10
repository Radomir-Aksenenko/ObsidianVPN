package obsidian

import "encoding/binary"

// ACK thinning. During a download every inner TCP ACK the client stack emits (during an upload,
// every ACK the server side receives from the internet) becomes its own
// encrypted frame: hundreds of small uplink records per downloaded megabyte, a pattern a plain
// HTTPS download does not have, and frames that cost CPU and bytes. When several ACKs of one
// connection wait in the same uplink batch, only the newest carries information the sender still
// needs: ACKs are cumulative and the newest has the latest window.
//
// ThinACKs drops a pure ACK only when a later pure ACK of the same connection in the same batch
// acknowledges strictly more. It never drops duplicate ACKs (equal ack numbers signal loss to the
// sender), ACKs with SACK or any option other than NOP/timestamps, segments with payload, or
// anything with SYN, FIN, RST, URG, ECE or CWR. Nothing waits for a batch to fill: thinning only
// sees packets that were already queued.

type ackFlow struct {
	n   int
	key [36]byte // src addr, dst addr, src port, dst port
}

// PureACK reports whether pkt is a TCP segment that only acknowledges, and returns its flow and
// acknowledgment number.
func PureACK(pkt []byte) (ackFlow, uint32, bool) {
	var f ackFlow
	var l4 []byte
	switch {
	case len(pkt) >= 20 && pkt[0]>>4 == 4:
		ihl := int(pkt[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(pkt[2:4]))
		if pkt[9] != 6 || ihl < 20 || total < ihl || total > len(pkt) {
			return f, 0, false
		}
		if binary.BigEndian.Uint16(pkt[6:8])&0x3fff != 0 { // MF or fragment offset
			return f, 0, false
		}
		f.n = copy(f.key[:], pkt[12:20])
		l4 = pkt[ihl:total]
	case len(pkt) >= 40 && pkt[0]>>4 == 6:
		payload := int(binary.BigEndian.Uint16(pkt[4:6]))
		if pkt[6] != 6 || 40+payload > len(pkt) { // extension headers are left alone
			return f, 0, false
		}
		f.n = copy(f.key[:], pkt[8:40])
		l4 = pkt[40 : 40+payload]
	default:
		return f, 0, false
	}
	if len(l4) < 20 {
		return f, 0, false
	}
	hdr := int(l4[12]>>4) * 4
	if hdr < 20 || hdr != len(l4) || l4[13] != 0x10 { // no payload, ACK only
		return f, 0, false
	}
	for opts := l4[20:hdr]; len(opts) > 0; {
		switch opts[0] {
		case 0: // end of options
			opts = nil
		case 1: // NOP
			opts = opts[1:]
		case 8: // timestamps
			if len(opts) < 10 || opts[1] != 10 {
				return f, 0, false
			}
			opts = opts[10:]
		default: // SACK and anything else
			return f, 0, false
		}
	}
	f.n += copy(f.key[f.n:], l4[0:4])
	return f, binary.BigEndian.Uint32(l4[8:12]), true
}

// ackThinMax bounds the batch ThinACKs looks at; longer batches are left as they are.
const ackThinMax = 64

// ackAfter reports whether a is a later acknowledgment number than b (RFC 1982 serial order).
func ackAfter(a, b uint32) bool { return int32(a-b) > 0 }

// ThinACKs removes superseded pure ACKs from pkts in place, keeping the order of the rest, and
// returns the shortened slice.
func ThinACKs(pkts [][]byte) [][]byte {
	if len(pkts) < 2 || len(pkts) > ackThinMax {
		return pkts
	}
	// Newest ack number seen later in the batch, per flow. Batches hold at most
	// ackThinMax packets, so a linear scan of a stack array beats a map.
	type seen struct {
		flow ackFlow
		ack  uint32
	}
	var buf [ackThinMax]seen
	newest := buf[:0]
	drop := 0
	for i := len(pkts) - 1; i >= 0; i-- {
		flow, ack, ok := PureACK(pkts[i])
		if !ok {
			continue
		}
		j := 0
		for j < len(newest) && newest[j].flow != flow {
			j++
		}
		switch {
		case j == len(newest):
			newest = append(newest, seen{flow, ack})
		case ackAfter(newest[j].ack, ack):
			pkts[i] = nil
			drop++
		case ackAfter(ack, newest[j].ack):
			newest[j].ack = ack
		}
	}
	if drop == 0 {
		return pkts
	}
	out := pkts[:0]
	for _, p := range pkts {
		if p != nil {
			out = append(out, p)
		}
	}
	clear(pkts[len(out):])
	return out
}

// ACKHoldBytes is how much data the pure ACKs of one held run may acknowledge before the run is
// sent. A time-only hold caps the inner TCP rate at about the acknowledged data per hold: at a
// low RTT, or when the receiver acknowledges GRO-merged segments, few ACKs arrive and each one
// waited the whole hold. Bounding the run by bytes keeps the ACK clock fine enough for any rate
// while slow flows still fold their ACKs over the time limit.
const ACKHoldBytes = 32 << 10

// ackProgressFlows is how many connections ACKProgress follows; a run spanning more is sent.
const ackProgressFlows = 8

// ACKProgress follows how far the pure ACKs of a held run have moved, per connection.
type ACKProgress struct {
	flows [ackProgressFlows]struct {
		flow  ackFlow
		first uint32
	}
	n int
}

// Reset starts a new run.
func (p *ACKProgress) Reset() { p.n = 0 }

// Add records pkt, which must be a pure ACK, and reports whether the run should be sent now:
// one connection is acknowledged by ACKHoldBytes or more since the run began, or the run spans
// more connections than are followed.
func (p *ACKProgress) Add(pkt []byte) bool {
	flow, ack, ok := PureACK(pkt)
	if !ok {
		return true
	}
	for i := 0; i < p.n; i++ {
		if p.flows[i].flow == flow {
			return ackAfter(ack, p.flows[i].first) && ack-p.flows[i].first >= ACKHoldBytes
		}
	}
	if p.n == len(p.flows) {
		return true
	}
	p.flows[p.n].flow, p.flows[p.n].first = flow, ack
	p.n++
	return false
}
