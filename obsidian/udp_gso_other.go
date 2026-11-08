//go:build !linux

package obsidian

import "net"

func gsoAvailable(*net.UDPConn) bool { return false }

func writeSegments(conn *net.UDPConn, b []byte, segSize int, addr *net.UDPAddr) error {
	return writeEach(conn, b, segSize, addr)
}
