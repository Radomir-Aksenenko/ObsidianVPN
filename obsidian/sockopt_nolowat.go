//go:build !linux && !darwin

package obsidian

import "net"

func tuneTCPSocket(*net.TCPConn) {}
