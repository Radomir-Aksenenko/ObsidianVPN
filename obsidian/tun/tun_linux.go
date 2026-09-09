//go:build linux

package tun

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type ifreq struct {
	Name  [unix.IFNAMSIZ]byte
	Flags uint16
	_pad  [22]byte
}

type linuxDevice struct {
	file       *os.File
	name       string
	mtu        int
	serverHost string
	origGW     string
	routesSet  bool
}

func (d *linuxDevice) Read(b []byte) (int, error) {
	return d.file.Read(b)
}

func (d *linuxDevice) Write(b []byte) (int, error) {
	return d.file.Write(b)
}

func (d *linuxDevice) Close() error {
	if d.routesSet {
		// Clean up routes
		_ = exec.Command("ip", "route", "del", "0.0.0.0/1", "dev", d.name).Run()
		_ = exec.Command("ip", "route", "del", "128.0.0.0/1", "dev", d.name).Run()
		if d.serverHost != "" && d.origGW != "" {
			_ = exec.Command("ip", "route", "del", d.serverHost, "via", d.origGW).Run()
		}
	}
	_ = exec.Command("ip", "link", "set", "dev", d.name, "down").Run()
	return d.file.Close()
}

func (d *linuxDevice) Name() string {
	return d.name
}

func (d *linuxDevice) MTU() int {
	return d.mtu
}

// Open creates and configures a native Linux TUN device via /dev/net/tun.
func Open(cfg Config) (Device, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w (ensure CAP_NET_ADMIN or root)", err)
	}

	var req ifreq
	req.Flags = unix.IFF_TUN | unix.IFF_NO_PI
	if cfg.Name != "" {
		copy(req.Name[:], cfg.Name)
	}

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("ioctl TUNSETIFF: %w", errno)
	}

	actualName := unix.ByteSliceToString(req.Name[:])
	file := os.NewFile(uintptr(fd), actualName)

	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = DefaultMTU
	}

	// Configure MTU
	if err := exec.Command("ip", "link", "set", "dev", actualName, "mtu", strconv.Itoa(mtu)).Run(); err != nil {
		file.Close()
		return nil, fmt.Errorf("set mtu %d on %s: %w", mtu, actualName, err)
	}

	// Configure IP address
	addr := cfg.Address
	if addr == "" {
		addr = "10.8.0.2/24"
	}
	if _, err := netip.ParsePrefix(addr); err != nil {
		file.Close()
		return nil, fmt.Errorf("invalid tun address %q: %w", addr, err)
	}

	if err := exec.Command("ip", "addr", "add", addr, "dev", actualName).Run(); err != nil {
		file.Close()
		return nil, fmt.Errorf("set ip address %s on %s: %w", addr, actualName, err)
	}

	// Bring interface up
	if err := exec.Command("ip", "link", "set", "dev", actualName, "up").Run(); err != nil {
		file.Close()
		return nil, fmt.Errorf("bring up %s: %w", actualName, err)
	}

	dev := &linuxDevice{
		file:       file,
		name:       actualName,
		mtu:        mtu,
		serverHost: cfg.ServerHost,
	}

	// Configure split default routing if serverHost is known
	if cfg.ServerHost != "" {
		if gw, err := findDefaultGatewayLinux(); err == nil && gw != "" {
			dev.origGW = gw
			_ = exec.Command("ip", "route", "add", cfg.ServerHost, "via", gw).Run()
			_ = exec.Command("ip", "route", "add", "0.0.0.0/1", "dev", actualName).Run()
			_ = exec.Command("ip", "route", "add", "128.0.0.0/1", "dev", actualName).Run()
			dev.routesSet = true
		}
	}

	return dev, nil
}

func findDefaultGatewayLinux() (string, error) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "", err
	}
	// Output format: "default via 192.168.1.1 dev eth0 ..."
	fields := splitFields(string(out))
	for i, f := range fields {
		if f == "via" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}
	return "", fmt.Errorf("default gateway not found")
}

