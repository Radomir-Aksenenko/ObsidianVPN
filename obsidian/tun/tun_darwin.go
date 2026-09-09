//go:build darwin

package tun

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	utunControlName = "com.apple.net.utun_control"
	sysprotoControl = 2
	afSysControl    = 2
	ctliocginfo     = 0xc0644e03 // CTLIOCGINFO
)

type ctlInfo struct {
	ctlID   uint32
	ctlName [96]byte
}

type sockaddrCtl struct {
	scLen      uint8
	scFamily   uint8
	ssSysaddr  uint16
	scID       uint32
	scUnit     uint32
	scReserved [5]uint32
}

type darwinDevice struct {
	file       *os.File
	name       string
	mtu        int
	serverHost string
	origGW     string
	routesSet  bool
}

// On Darwin, reading from utun returns a 4-byte header specifying the protocol family (e.g. AF_INET or AF_INET6)
// followed by the IP packet.
func (d *darwinDevice) Read(b []byte) (int, error) {
	var buf [4 + 2048]byte
	n, err := d.file.Read(buf[:])
	if err != nil {
		return 0, err
	}
	if n <= 4 {
		return 0, nil
	}
	// Strip 4-byte protocol header
	copied := copy(b, buf[4:n])
	return copied, nil
}

// Writing to utun requires prepending 4 bytes with the protocol family:
// IPv4 (AF_INET = 2) or IPv6 (AF_INET6 = 30).
func (d *darwinDevice) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	var family uint32 = unix.AF_INET
	if b[0]>>4 == 6 {
		family = unix.AF_INET6
	}

	var buf [4 + 2048]byte
	binary.BigEndian.PutUint32(buf[:4], family)
	copy(buf[4:], b)

	n, err := d.file.Write(buf[:4+len(b)])
	if err != nil {
		return 0, err
	}
	if n <= 4 {
		return 0, io.ErrShortWrite
	}
	return n - 4, nil
}

func (d *darwinDevice) Close() error {
	if d.routesSet {
		_ = exec.Command("route", "delete", "-net", "0.0.0.0/1", "-interface", d.name).Run()
		_ = exec.Command("route", "delete", "-net", "128.0.0.0/1", "-interface", d.name).Run()
		if d.serverHost != "" && d.origGW != "" {
			_ = exec.Command("route", "delete", "-host", d.serverHost, d.origGW).Run()
		}
	}
	return d.file.Close()
}

func (d *darwinDevice) Name() string {
	return d.name
}

func (d *darwinDevice) MTU() int {
	return d.mtu
}

// Open creates and configures a native macOS utun interface.
func Open(cfg Config) (Device, error) {
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return nil, fmt.Errorf("socket(AF_SYSTEM): %w", err)
	}

	var info ctlInfo
	copy(info.ctlName[:], utunControlName)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(ctliocginfo), uintptr(unsafe.Pointer(&info)))
	if errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("ioctl CTLIOCGINFO: %w", errno)
	}

	var sa sockaddrCtl
	sa.scLen = uint8(unsafe.Sizeof(sa))
	sa.scFamily = unix.AF_SYSTEM
	sa.ssSysaddr = afSysControl
	sa.scID = info.ctlID
	sa.scUnit = 0 // allocate next available utun interface

	_, _, errno = syscall.Syscall(syscall.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&sa)), uintptr(sa.scLen))
	if errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("connect utun: %w", errno)
	}

	// Retrieve allocated interface name
	var ifNameBuf [64]byte
	ifNameLen := uint32(len(ifNameBuf))
	_, _, errno = syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		sysprotoControl,
		2, // UTUN_OPT_IFNAME
		uintptr(unsafe.Pointer(&ifNameBuf[0])),
		uintptr(unsafe.Pointer(&ifNameLen)),
		0,
	)
	var ifName string
	if errno == 0 {
		ifName = unix.ByteSliceToString(ifNameBuf[:])
	} else {
		ifName = "utun"
	}

	file := os.NewFile(uintptr(fd), ifName)

	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = DefaultMTU
	}

	addr := cfg.Address
	if addr == "" {
		addr = "10.8.0.2/24"
	}
	prefix, err := netip.ParsePrefix(addr)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("invalid tun address %q: %w", addr, err)
	}
	ip := prefix.Addr().String()

	destIP := "10.8.0.1"
	_ = exec.Command("ifconfig", ifName, ip, destIP, "mtu", strconv.Itoa(mtu), "up").Run()

	dev := &darwinDevice{
		file:       file,
		name:       ifName,
		mtu:        mtu,
		serverHost: cfg.ServerHost,
	}

	if cfg.ServerHost != "" {
		if gw, err := findDefaultGatewayDarwin(); err == nil && gw != "" {
			dev.origGW = gw
			_ = exec.Command("route", "add", "-host", cfg.ServerHost, gw).Run()
			_ = exec.Command("route", "add", "-net", "0.0.0.0/1", "-interface", ifName).Run()
			_ = exec.Command("route", "add", "-net", "128.0.0.0/1", "-interface", ifName).Run()
			dev.routesSet = true
		}
	}

	return dev, nil
}

func findDefaultGatewayDarwin() (string, error) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return "", err
	}
	lines := splitLines(string(out))
	for _, l := range lines {
		fields := splitFields(l)
		for i, f := range fields {
			if f == "gateway:" && i+1 < len(fields) {
				return fields[i+1], nil
			}
		}
	}
	return "", fmt.Errorf("gateway not found")
}

