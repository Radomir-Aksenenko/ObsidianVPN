package tun

import (
	"errors"
	"fmt"
	"os"
)

type fdDevice struct {
	file *os.File
	name string
	mtu  int
}

func (d *fdDevice) Read(b []byte) (int, error) {
	return d.file.Read(b)
}

func (d *fdDevice) Write(b []byte) (int, error) {
	return d.file.Write(b)
}

func (d *fdDevice) Close() error {
	return d.file.Close()
}

func (d *fdDevice) Name() string {
	return d.name
}

func (d *fdDevice) MTU() int {
	if d.mtu <= 0 {
		return DefaultMTU
	}
	return d.mtu
}

// OpenFD wraps an existing operating system file descriptor into a TUN Device.
// This is the primary integration mechanism on Android (VpnService ParcelFileDescriptor.getFd()),
// iOS NetworkExtension tunnel fd, and containerized Linux environments.
func OpenFD(fd int, name string, mtu int) (Device, error) {
	if fd < 0 {
		return nil, errors.New("invalid file descriptor")
	}
	if name == "" {
		name = fmt.Sprintf("tun-fd-%d", fd)
	}
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	file := os.NewFile(uintptr(fd), name)
	return &fdDevice{
		file: file,
		name: name,
		mtu:  mtu,
	}, nil
}
