//go:build linux

package obsidian

import (
	"net"

	"golang.org/x/sys/unix"
)

// tuneTCPSocket caps the unsent part of the kernel send queue. The window still grows on its
// own (sent but unacknowledged bytes are not limited), but a bulk sender cannot pile seconds of
// data in front of a game or DNS packet written right after it.
func tuneTCPSocket(tc *net.TCPConn) {
	rc, err := tc.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, tcpNotSentLowat)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, int(tcpUserTimeout.Milliseconds()))
	})
}

// setTCPCongestion switches one socket to the named congestion control and returns the one the
// socket ends up with. It needs the module to be available; with CAP_NET_ADMIN the kernel loads
// it on demand. Failure leaves the system default.
func setTCPCongestion(tc *net.TCPConn, name string) string {
	rc, err := tc.SyscallConn()
	if err != nil {
		return ""
	}
	var got string
	_ = rc.Control(func(fd uintptr) {
		_ = unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, name)
		got, _ = unix.GetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION)
	})
	return got
}

// SetUDPSocketBuffers sets both socket buffers to size bytes. Plain SO_RCVBUF is silently
// clamped to net.core.rmem_max (often 208 KiB), so the forced variant is tried first: it needs
// CAP_NET_ADMIN, which the server container has. It returns the sizes the kernel reports back,
// which on Linux are twice the usable payload size.
func SetUDPSocketBuffers(conn *net.UDPConn, size int) (rcv, snd int, err error) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	ctrlErr := rc.Control(func(fd uintptr) {
		s := int(fd)
		if unix.SetsockoptInt(s, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, size) != nil {
			_ = unix.SetsockoptInt(s, unix.SOL_SOCKET, unix.SO_RCVBUF, size)
		}
		if unix.SetsockoptInt(s, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, size) != nil {
			_ = unix.SetsockoptInt(s, unix.SOL_SOCKET, unix.SO_SNDBUF, size)
		}
		rcv, _ = unix.GetsockoptInt(s, unix.SOL_SOCKET, unix.SO_RCVBUF)
		snd, _ = unix.GetsockoptInt(s, unix.SOL_SOCKET, unix.SO_SNDBUF)
	})
	return rcv, snd, ctrlErr
}
