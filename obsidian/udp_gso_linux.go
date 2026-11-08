//go:build linux

package obsidian

import (
	"encoding/binary"
	"errors"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

var (
	// gsoOff is set once the kernel or the NIC turned a UDP_SEGMENT send down; every later
	// batch then goes out one datagram at a time.
	gsoOff       atomic.Bool
	gsoProbeOnce sync.Once
)

// gsoAvailable reports whether batched sends may use UDP_SEGMENT. Kernels before 4.18 do not
// know the option and would ignore the control message, sending the whole batch as one huge
// datagram, so support is probed with getsockopt first (the same check quic-go uses).
func gsoAvailable(conn *net.UDPConn) bool {
	gsoProbeOnce.Do(func() {
		ok := false
		if rc, err := conn.SyscallConn(); err == nil {
			_ = rc.Control(func(fd uintptr) {
				_, err := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT)
				ok = err == nil
			})
		}
		if !ok {
			gsoOff.Store(true)
		}
	})
	return !gsoOff.Load()
}

// gsoWriteMsg is the UDP_SEGMENT send, a variable so tests can make it fail.
var gsoWriteMsg = func(conn *net.UDPConn, b, oob []byte, addr *net.UDPAddr) error {
	_, _, err := conn.WriteMsgUDP(b, oob, addr)
	return err
}

// writeSegments sends b, a run of segSize-byte datagrams (the last may be shorter), with a single
// UDP_SEGMENT sendmsg. When the kernel or NIC rejects that (no checksum offload gives EIO, a
// segment above the path MTU gives EINVAL), GSO is switched off for good and the same bytes go
// out one datagram at a time. They are already sealed, so nothing is encrypted twice.
func writeSegments(conn *net.UDPConn, b []byte, segSize int, addr *net.UDPAddr) error {
	if len(b) <= segSize || gsoOff.Load() {
		return writeEach(conn, b, segSize, addr)
	}
	// Backed by uint64s so the header cast is aligned; 24 bytes is CmsgSpace(2) on 64-bit,
	// checked in init.
	var words [3]uint64
	oob := unsafe.Slice((*byte)(unsafe.Pointer(&words[0])), len(words)*8)
	h := (*unix.Cmsghdr)(unsafe.Pointer(&words[0]))
	h.Level = unix.IPPROTO_UDP
	h.Type = unix.UDP_SEGMENT
	h.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(oob[unix.CmsgLen(0):], uint16(segSize))
	err := gsoWriteMsg(conn, b, oob[:unix.CmsgSpace(2)], addr)
	if err == nil {
		return nil
	}
	if !gsoRejected(err) {
		return err
	}
	if gsoOff.CompareAndSwap(false, true) {
		log.Printf("udp: GSO turned off, sending datagrams one by one: %v", err)
	}
	return writeEach(conn, b, segSize, addr)
}

func gsoRejected(err error) bool {
	return errors.Is(err, unix.EIO) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EMSGSIZE) ||
		errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOPROTOOPT)
}

func init() {
	if unix.CmsgSpace(2) > 24 {
		panic("udp gso: control buffer too small")
	}
}
