//go:build windows

package obsidian

import (
	"net"
	"syscall"
)

// tcpMaxRT is TCP_MAXRT: the seconds Windows keeps retransmitting before it drops the connection.
const tcpMaxRT = 5

// tuneTCPSocket bounds how long a dead path keeps the tunnel open (see tcpUserTimeout).
// Windows has no TCP_NOTSENT_LOWAT.
func tuneTCPSocket(tc *net.TCPConn) {
	rc, err := tc.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_TCP, tcpMaxRT, int(tcpUserTimeout.Seconds()))
	})
}
