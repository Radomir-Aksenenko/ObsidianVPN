package tun

import (
	"context"
	"io"
	"sync"
)

// PacketDevice allows reading and writing raw IP packets in-memory.
// Useful for iOS NetworkExtension packetFlow.readPackets / packetFlow.writePackets,
// unit testing, and custom memory packet pipes.
type PacketDevice struct {
	inQueue  chan []byte
	outQueue chan []byte
	name     string
	mtu      int
	closed   chan struct{}
	once     sync.Once
}

// NewPacketDevice creates a new in-memory packet device.
func NewPacketDevice(name string, mtu int, queueSize int) *PacketDevice {
	if queueSize <= 0 {
		queueSize = 2048
	}
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	if name == "" {
		name = "packet-tun"
	}
	return &PacketDevice{
		inQueue:  make(chan []byte, queueSize),
		outQueue: make(chan []byte, queueSize),
		name:     name,
		mtu:      mtu,
		closed:   make(chan struct{}),
	}
}

var inPacketPool = sync.Pool{
	New: func() any {
		b := make([]byte, 2048)
		return &b
	},
}

func (p *PacketDevice) Read(b []byte) (int, error) {
	select {
	case <-p.closed:
		return 0, io.EOF
	case pkt, ok := <-p.inQueue:
		if !ok {
			return 0, io.EOF
		}
		n := copy(b, pkt)
		if cap(pkt) == 2048 {
			inPacketPool.Put(&pkt)
		}
		return n, nil
	}
}

func (p *PacketDevice) Write(b []byte) (int, error) {
	select {
	case <-p.closed:
		return 0, io.ErrClosedPipe
	default:
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	select {
	case <-p.closed:
		return 0, io.ErrClosedPipe
	case p.outQueue <- cp:
		return len(b), nil
	default:
		// Queue full: drop packet rather than blocking network pipeline
		return len(b), nil
	}
}

func (p *PacketDevice) Close() error {
	p.once.Do(func() {
		close(p.closed)
	})
	return nil
}

func (p *PacketDevice) Name() string {
	return p.name
}

func (p *PacketDevice) MTU() int {
	return p.mtu
}

// InjectPacket feeds an incoming packet from the host OS (e.g. iOS packetFlow) into the tunnel.
func (p *PacketDevice) InjectPacket(pkt []byte) error {
	select {
	case <-p.closed:
		return io.ErrClosedPipe
	default:
	}

	pBuf := inPacketPool.Get().(*[]byte)
	if cap(*pBuf) < len(pkt) {
		*pBuf = make([]byte, len(pkt))
	}
	*pBuf = (*pBuf)[:len(pkt)]
	copy(*pBuf, pkt)

	select {
	case <-p.closed:
		if cap(*pBuf) == 2048 {
			inPacketPool.Put(pBuf)
		}
		return io.ErrClosedPipe
	case p.inQueue <- *pBuf:
		return nil
	default:
		// Queue full: drop packet rather than stalling host network stack
		if cap(*pBuf) == 2048 {
			inPacketPool.Put(pBuf)
		}
		return nil
	}
}

// ReceivePacket retrieves a packet from the tunnel to be delivered to the host OS.
func (p *PacketDevice) ReceivePacket(ctx context.Context) ([]byte, error) {
	select {
	case <-p.closed:
		return nil, io.EOF
	case <-ctx.Done():
		return nil, ctx.Err()
	case pkt, ok := <-p.outQueue:
		if !ok {
			return nil, io.EOF
		}
		return pkt, nil
	}
}

// TryReceivePacket non-blockingly retrieves the next packet if available.
func (p *PacketDevice) TryReceivePacket() ([]byte, error) {
	select {
	case <-p.closed:
		return nil, io.EOF
	case pkt, ok := <-p.outQueue:
		if !ok {
			return nil, io.EOF
		}
		return pkt, nil
	default:
		return nil, nil
	}
}
