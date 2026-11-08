//go:build darwin

package obsidian

import (
	"net"

	"golang.org/x/sys/unix"
)

// tuneTCPSocket caps the unsent part of the send queue, as on Linux.
func tuneTCPSocket(tc *net.TCPConn) {
	rc, err := tc.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, tcpNotSentLowat)
	})
}
