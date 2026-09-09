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

func (p *PacketDevice) Read(b []byte) (int, error) {
	select {
	case <-p.closed:
		return 0, io.EOF
	case pkt, ok := <-p.inQueue:
		if !ok {
			return 0, io.EOF
		}
		n := copy(b, pkt)
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
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	select {
	case <-p.closed:
		return io.ErrClosedPipe
	case p.inQueue <- cp:
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
