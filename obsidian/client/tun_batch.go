package client

import (
	"io"
	"sync"
	"time"

	"obsidian/obsidian"
)

// Uplink batching. The server already writes downlink bursts with Tunnel.SendDataBatch; the
// client used to frame, seal and write every TUN packet on its own, one TLS record and one write
// syscall per packet, ACKs included. A reader goroutine now queues packets and the sender takes
// whatever is already waiting. There is no timer: a lone packet leaves at once, so latency does not
// grow, and a burst costs one write. The bytes on the wire are the same frames concatenated.
const (
	UplinkBatchPackets = 32
	uplinkBatchBytes   = 60 * 1024
	uplinkQueueLen     = 64
	tunPacketBufSize   = 2048
)

// TunBatchReader queues TUN packets for batched uplink sends.
type TunBatchReader struct {
	pkts chan *[]byte
	errc chan error
	done chan struct{}
	once sync.Once
	pool sync.Pool

	ackHold time.Duration // see ACKHold
	timer   *time.Timer
}

// ACKHold is how long an uplink batch made only of pure TCP ACKs may wait for more packets
// before it is sent. During a download the inner TCP stack acknowledges every second segment,
// and each ACK used to leave as its own encrypted record: about a hundred small client records
// per downloaded megabyte, where a browser downloading over HTTPS sends almost none. Holding
// ACK-only batches briefly lets obsidian.ThinACKs fold them into one ACK per connection. A packet with
// data, SYN, FIN or RST ends the wait at once, so requests, handshakes and interactive traffic
// are not delayed; only acknowledgements are, by at most ACKHold. Zero disables the hold.
var ACKHold = 4 * time.Millisecond

// NewTunBatchReader reads tun in its own goroutine until Close is called or Read fails. Like the
// loop it replaces, a goroutine blocked in Read returns only with the next packet, which it drops
// once the reader is closed with Close.
func NewTunBatchReader(tun io.Reader) *TunBatchReader {
	r := &TunBatchReader{
		pkts:    make(chan *[]byte, uplinkQueueLen),
		errc:    make(chan error, 1),
		done:    make(chan struct{}),
		ackHold: ACKHold,
	}
	r.pool.New = func() any {
		b := make([]byte, tunPacketBufSize)
		return &b
	}
	go r.loop(tun)
	return r
}

func (r *TunBatchReader) loop(tun io.Reader) {
	for {
		bp := r.pool.Get().(*[]byte)
		b := (*bp)[:cap(*bp)]
		n, err := tun.Read(b)
		if err != nil {
			r.pool.Put(bp)
			select {
			case r.errc <- err:
			case <-r.done:
			}
			return
		}
		*bp = b[:n]
		select {
		case r.pkts <- bp:
		case <-r.done:
			r.pool.Put(bp)
			return
		}
	}
}

func (r *TunBatchReader) Close() { r.once.Do(func() { close(r.done) }) }

// NextBatch waits for one packet, then adds the packets already queued, up to the batch limits.
// It returns nil, nil when stop is closed.
func (r *TunBatchReader) NextBatch(dst []*[]byte, stop <-chan struct{}) ([]*[]byte, error) {
	dst = dst[:0]
	select {
	case bp := <-r.pkts:
		dst = append(dst, bp)
	case err := <-r.errc:
		return nil, err
	case <-stop:
		return nil, nil
	}
	size := len(*dst[0])
	for len(dst) < UplinkBatchPackets && size < uplinkBatchBytes {
		select {
		case bp := <-r.pkts:
			dst = append(dst, bp)
			size += len(*bp)
			continue
		default:
		}
		break
	}
	if r.ackHold <= 0 || len(dst) >= UplinkBatchPackets || !allPureACKs(dst) {
		return dst, nil
	}
	// Only acknowledgements so far: wait briefly for more, and stop as soon as anything else
	// arrives.
	if r.timer == nil {
		r.timer = time.NewTimer(r.ackHold)
	} else {
		r.timer.Reset(r.ackHold)
	}
	defer r.timer.Stop()
	for len(dst) < UplinkBatchPackets && size < uplinkBatchBytes {
		select {
		case bp := <-r.pkts:
			dst = append(dst, bp)
			size += len(*bp)
			if _, _, ok := obsidian.PureACK(*bp); !ok {
				return dst, nil
			}
		case <-r.timer.C:
			return dst, nil
		case <-stop:
			return dst, nil
		}
	}
	return dst, nil
}

func allPureACKs(batch []*[]byte) bool {
	for _, bp := range batch {
		if _, _, ok := obsidian.PureACK(*bp); !ok {
			return false
		}
	}
	return true
}

// Release returns the batch buffers; the packets must no longer be referenced.
func (r *TunBatchReader) Release(batch []*[]byte) {
	for i, bp := range batch {
		r.pool.Put(bp)
		batch[i] = nil
	}
}
