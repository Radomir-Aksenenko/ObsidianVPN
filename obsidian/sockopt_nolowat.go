//go:build !linux && !darwin && !windows

package obsidian

import "net"

func tuneTCPSocket(*net.TCPConn) {}
