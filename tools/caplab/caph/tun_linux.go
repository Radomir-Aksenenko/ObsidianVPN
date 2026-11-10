//go:build linux

package main

import (
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// openTUN opens (creating if needed) a Linux TUN device without packet information headers.
func openTUN(name string) (*os.File, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var req [unix.IFNAMSIZ + 64]byte
	copy(req[:unix.IFNAMSIZ-1], name)
	*(*uint16)(unsafe.Pointer(&req[unix.IFNAMSIZ])) = unix.IFF_TUN | unix.IFF_NO_PI
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req[0]))); errno != 0 {
		unix.Close(fd)
		return nil, errno
	}
	return os.NewFile(uintptr(fd), "/dev/net/tun"), nil
}
