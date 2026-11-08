//go:build !linux

package obsidian

import "net"

func setTCPCongestion(*net.TCPConn, string) string { return "" }

// SetUDPSocketBuffers requests size bytes for both socket buffers. There is no forced variant
// outside Linux; the returned sizes are the requested ones, not what the kernel granted.
func SetUDPSocketBuffers(conn *net.UDPConn, size int) (rcv, snd int, err error) {
	if err := conn.SetReadBuffer(size); err != nil {
		return 0, 0, err
	}
	if err := conn.SetWriteBuffer(size); err != nil {
		return size, 0, err
	}
	return size, size, nil
}
